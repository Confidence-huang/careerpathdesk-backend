/*
生产 MFA 状态机测试：只使用随机 synthetic PostgreSQL schema，验证密码通过后仍不能绕过第二因素。
测试通过公开命令触发行为；数据库计数只用于证明安全副作用没有提前发生，不读取任何秘密正文。
*/
package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- 生产密码验证只签发五分钟 MFA challenge，不提前创建正常会话 ---
func TestLoginRequiresMFAWithoutIssuingSession(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 13, 0, 0, 0, time.UTC)
	sessions, sessionError := NewSessionCommands(connection, func() time.Time { return fixedNow })
	if sessionError != nil {
		t.Fatalf("session commands failed to initialize: %v", sessionError)
	}
	mfa, mfaError := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, true, make([]byte, 32))
	if mfaError != nil {
		t.Fatalf("MFA commands failed to initialize: %v", mfaError)
	}

	challenge, beginError := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if beginError != nil {
		t.Fatalf("password-authenticated MFA login failed to begin: %v", beginError)
	}
	if challenge.Purpose != MFAEnrollmentPurpose || challenge.Secret == "" {
		t.Fatalf("expected enrollment challenge, got purpose %q", challenge.Purpose)
	}
	if !challenge.ExpiresAt.Equal(fixedNow.Add(MFAChallengeLifetime)) {
		t.Fatalf("expected exact five-minute challenge lifetime, got %v", challenge.ExpiresAt.Sub(fixedNow))
	}

	var sessionCount int
	if countError := connection.QueryRow(context.Background(), "SELECT count(*) FROM account_sessions").Scan(&sessionCount); countError != nil {
		t.Fatal("normal session count was unavailable")
	}
	if sessionCount != 0 {
		t.Fatalf("password-only login created %d normal sessions", sessionCount)
	}
}

// --- MFA AES key 只从 0600 文件读取严格 Base64 编码的 32 字节材料 ---
func TestLoadMFAEncryptionKeyRequiresProtectedBase64File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mfa-encryption-key")
	rawKey := bytes.Repeat([]byte{0xa5}, 32)
	if writeError := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(rawKey)+"\n"), 0o600); writeError != nil {
		t.Fatal("synthetic MFA key fixture failed")
	}
	loaded, loadError := LoadMFAEncryptionKey(path)
	if loadError != nil || !bytes.Equal(loaded, rawKey) {
		t.Fatalf("protected 32-byte MFA key failed to load: %v", loadError)
	}
	if writeError := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(rawKey[:31])), 0o600); writeError != nil {
		t.Fatal("invalid MFA key fixture failed")
	}
	if _, invalidError := LoadMFAEncryptionKey(path); !errors.Is(invalidError, ErrMFAEncryptionKeyUnavailable) {
		t.Fatalf("expected invalid key length rejection, got %v", invalidError)
	}
}

// --- 一个有效 TOTP 原子确认注册、生成恢复码并创建第一条正常会话 ---
func TestMFAConfirmEnrollmentIssuesSessionAndOneTimeRecoveryCodes(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 13, 30, 0, 0, time.UTC)
	sessions, _ := NewSessionCommands(connection, func() time.Time { return fixedNow })
	mfa, _ := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, true, bytes.Repeat([]byte{0x3c}, 32))
	challenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	enrollment, enrollmentError := mfa.BeginEnrollment(context.Background(), challenge.Secret)
	if enrollmentError != nil {
		t.Fatalf("MFA enrollment failed to begin: %v", enrollmentError)
	}

	code := testTOTPCode(t, enrollment.ManualKey, fixedNow.Unix()/30)
	accountSession, recoveryCodes, confirmError := mfa.ConfirmEnrollment(context.Background(), challenge.Secret, code, "Synthetic Browser")
	if confirmError != nil {
		t.Fatalf("valid TOTP failed to confirm enrollment: %v", confirmError)
	}
	if accountSession.Account.ID != "A-syntheticowner01" || accountSession.Credential.SessionID == "" {
		t.Fatal("confirmed enrollment did not issue the expected account session")
	}
	if len(recoveryCodes) != MFARecoveryCodeCount {
		t.Fatalf("expected %d one-time recovery codes, got %d", MFARecoveryCodeCount, len(recoveryCodes))
	}
	seen := map[string]bool{}
	for _, recoveryCode := range recoveryCodes {
		if recoveryCode == "" || seen[recoveryCode] {
			t.Fatal("recovery codes were empty or repeated")
		}
		seen[recoveryCode] = true
	}
	if _, currentError := sessions.Current(context.Background(), accountSession.Account.ID, accountSession.Credential.SessionID, accountSession.Credential.CredentialVersion); currentError != nil {
		t.Fatalf("confirmed MFA session was not active: %v", currentError)
	}
}

// --- 已注册账号的 TOTP 只能在一个时间步成功一次 ---
func TestMFALoginRejectsReplayedTOTPStep(t *testing.T) {
	connection := openSessionTestDatabase(t)
	currentNow := time.Date(2026, time.August, 8, 14, 0, 0, 0, time.UTC)
	now := func() time.Time { return currentNow }
	sessions, _ := NewSessionCommands(connection, now)
	mfa, _ := NewMFACommands(connection, sessions, now, true, bytes.Repeat([]byte{0x7d}, 32))
	enrollChallenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	enrollment, _ := mfa.BeginEnrollment(context.Background(), enrollChallenge.Secret)
	_, _, confirmError := mfa.ConfirmEnrollment(context.Background(), enrollChallenge.Secret, testTOTPCode(t, enrollment.ManualKey, currentNow.Unix()/30), "Synthetic Browser")
	if confirmError != nil {
		t.Fatalf("MFA fixture enrollment failed: %v", confirmError)
	}

	currentNow = currentNow.Add(30 * time.Second)
	firstChallenge, firstBeginError := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if firstBeginError != nil || firstChallenge.Purpose != MFALoginPurpose {
		t.Fatalf("registered account did not receive login challenge: %v", firstBeginError)
	}
	code := testTOTPCode(t, enrollment.ManualKey, currentNow.Unix()/30)
	if _, verifyError := mfa.VerifyLogin(context.Background(), firstChallenge.Secret, code, "Synthetic Browser"); verifyError != nil {
		t.Fatalf("fresh TOTP failed: %v", verifyError)
	}

	replayChallenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if _, replayError := mfa.VerifyLogin(context.Background(), replayChallenge.Secret, code, "Synthetic Browser"); !errors.Is(replayError, ErrInvalidMFACode) {
		t.Fatalf("expected repeated TOTP step rejection, got %v", replayError)
	}
}

// --- 恢复码成功一次后从摘要集合移除，任何新 challenge 都不能重放 ---
func TestMFARecoveryCodeCanBeUsedOnlyOnce(t *testing.T) {
	connection := openSessionTestDatabase(t)
	currentNow := time.Date(2026, time.August, 8, 14, 30, 0, 0, time.UTC)
	now := func() time.Time { return currentNow }
	sessions, _ := NewSessionCommands(connection, now)
	mfa, _ := NewMFACommands(connection, sessions, now, true, bytes.Repeat([]byte{0x22}, 32))
	enrollChallenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	enrollment, _ := mfa.BeginEnrollment(context.Background(), enrollChallenge.Secret)
	_, recoveryCodes, _ := mfa.ConfirmEnrollment(context.Background(), enrollChallenge.Secret, testTOTPCode(t, enrollment.ManualKey, currentNow.Unix()/30), "Synthetic Browser")

	loginChallenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if _, verifyError := mfa.VerifyLogin(context.Background(), loginChallenge.Secret, recoveryCodes[0], "Synthetic Browser"); verifyError != nil {
		t.Fatalf("unused recovery code failed: %v", verifyError)
	}
	replayChallenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if _, replayError := mfa.VerifyLogin(context.Background(), replayChallenge.Secret, recoveryCodes[0], "Synthetic Browser"); !errors.Is(replayError, ErrInvalidMFACode) {
		t.Fatalf("expected consumed recovery code rejection, got %v", replayError)
	}
}

// --- 五次错误耗尽 challenge，之后即使正确验证码也不能恢复该挑战 ---
func TestMFALoginChallengeExpiresAfterFiveInvalidCodes(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 15, 0, 0, 0, time.UTC)
	sessions, _ := NewSessionCommands(connection, func() time.Time { return fixedNow })
	mfa, _ := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, true, bytes.Repeat([]byte{0x44}, 32))
	enrollChallenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	enrollment, _ := mfa.BeginEnrollment(context.Background(), enrollChallenge.Secret)
	_, _, _ = mfa.ConfirmEnrollment(context.Background(), enrollChallenge.Secret, testTOTPCode(t, enrollment.ManualKey, fixedNow.Unix()/30), "Synthetic Browser")
	challenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	for attempt := 0; attempt < 5; attempt++ {
		if _, verifyError := mfa.VerifyLogin(context.Background(), challenge.Secret, "000000", "Synthetic Browser"); !errors.Is(verifyError, ErrInvalidMFACode) {
			t.Fatalf("attempt %d did not consume one failure budget: %v", attempt+1, verifyError)
		}
	}
	validCode := testTOTPCode(t, enrollment.ManualKey, fixedNow.Unix()/30+1) // 允许窗口内但与注册时间步不同。
	if _, exhaustedError := mfa.VerifyLogin(context.Background(), challenge.Secret, validCode, "Synthetic Browser"); !errors.Is(exhaustedError, ErrInvalidMFAChallenge) {
		t.Fatalf("expected exhausted challenge rejection, got %v", exhaustedError)
	}
}

// --- 新 challenge 立即终止同账号同用途旧 challenge，不能并行扩大五次预算 ---
func TestMFANewChallengeInvalidatesPreviousChallenge(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 15, 15, 0, 0, time.UTC)
	sessions, _ := NewSessionCommands(connection, func() time.Time { return fixedNow })
	mfa, _ := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, true, bytes.Repeat([]byte{0x65}, 32))
	first, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	second, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if _, oldChallengeError := mfa.BeginEnrollment(context.Background(), first.Secret); !errors.Is(oldChallengeError, ErrInvalidMFAChallenge) {
		t.Fatalf("expected replaced challenge rejection, got %v", oldChallengeError)
	}
	if _, currentChallengeError := mfa.BeginEnrollment(context.Background(), second.Secret); currentChallengeError != nil {
		t.Fatalf("newest challenge was not active: %v", currentChallengeError)
	}
}

// --- 第一因素改变时，之前凭旧密码取得的 challenge 立即失效 ---
func TestMFAChallengeIsInvalidatedByPasswordChange(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 15, 20, 0, 0, time.UTC)
	sessions, _ := NewSessionCommands(connection, func() time.Time { return fixedNow })
	mfa, _ := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, true, bytes.Repeat([]byte{0x71}, 32))
	challenge, _ := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if changeError := sessions.ChangePassword(context.Background(), "A-syntheticowner01", "CareerPathDesk-Test-Only!", "CareerPathDesk-Changed-Only-2026!"); changeError != nil {
		t.Fatalf("synthetic password change failed: %v", changeError)
	}
	if _, challengeError := mfa.BeginEnrollment(context.Background(), challenge.Secret); !errors.Is(challengeError, ErrInvalidMFAChallenge) {
		t.Fatalf("expected pre-password-change challenge rejection, got %v", challengeError)
	}
}

// --- UAT 显式关闭 MFA 时沿用现有一次登录即建会话行为 ---
func TestMFADisabledKeepsExistingUATLoginFlow(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 15, 30, 0, 0, time.UTC)
	sessions, _ := NewSessionCommands(connection, func() time.Time { return fixedNow })
	mfa, constructorError := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, false, nil)
	if constructorError != nil {
		t.Fatalf("MFA-disabled UAT commands failed to initialize: %v", constructorError)
	}
	result, loginError := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if loginError != nil || result.Session == nil || result.Session.Credential.SessionID == "" {
		t.Fatalf("existing UAT login flow changed: %v", loginError)
	}
}

func testTOTPCode(t *testing.T, manualKey string, step int64) string {
	t.Helper()
	secret, decodeError := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(manualKey))
	if decodeError != nil {
		t.Fatal("test enrollment key was invalid")
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(step))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}

// --- 注册材料只在有效 challenge 下返回，数据库只保存 AES-GCM 密文 ---
func TestMFAEnrollmentProtectsTOTPSecretAtRest(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 13, 15, 0, 0, time.UTC)
	sessions, _ := NewSessionCommands(connection, func() time.Time { return fixedNow })
	encryptionKey := bytes.Repeat([]byte{0x5a}, 32)
	mfa, _ := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, true, encryptionKey)

	challenge, beginError := mfa.BeginLogin(context.Background(), "synthetic-owner", "CareerPathDesk-Test-Only!", "Synthetic Browser")
	if beginError != nil {
		t.Fatalf("MFA login failed to begin: %v", beginError)
	}
	enrollment, enrollmentError := mfa.BeginEnrollment(context.Background(), challenge.Secret)
	if enrollmentError != nil {
		t.Fatalf("MFA enrollment failed to begin: %v", enrollmentError)
	}
	if enrollment.ManualKey == "" || enrollment.OTPAuthURI == "" || !bytes.Contains([]byte(enrollment.OTPAuthURI), []byte(enrollment.ManualKey)) {
		t.Fatal("enrollment did not expose one usable TOTP registration projection")
	}

	var encryptedSecret []byte
	var nonce []byte
	if queryError := connection.QueryRow(context.Background(), `
		SELECT encrypted_secret, secret_nonce FROM account_mfa WHERE account_id = 'A-syntheticowner01'`,
	).Scan(&encryptedSecret, &nonce); queryError != nil {
		t.Fatal("encrypted MFA factor was not persisted")
	}
	if bytes.Contains(encryptedSecret, []byte(enrollment.ManualKey)) || len(nonce) != 12 {
		t.Fatal("MFA factor was not protected as AES-GCM ciphertext")
	}
}
