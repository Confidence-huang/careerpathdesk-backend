/*
MFA 命令模块：密码验证、短期挑战、TOTP/恢复码与正常会话共享清晰的事务边界。
数据库只保存 challenge、恢复码摘要和 AES-256-GCM 密文；原始值只在一次命令反馈中存在。
*/
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/identity"
	platformsecret "github.com/confidence-huang/careerpathdesk-backend/internal/platform/secret"
)

const MFAChallengeLifetime = 5 * time.Minute // 密码通过后的第二因素窗口最多持续五分钟。
const MFAEnrollmentPurpose = "enroll"        // 未确认第二因素的账号只能进入注册流程。
const MFALoginPurpose = "login"              // 已确认第二因素的账号只能进入验证流程。
const mfaChallengeSecretBytes = 32           // 256 位原始 challenge 只进入受限 Cookie。
const totpSecretBytes = 20                   // RFC 6238 SHA-1 因素使用 160 位随机 secret。
const MFARecoveryCodeCount = 10              // 首次注册反馈固定数量的一次性离线恢复码。
const recoveryCodeBytes = 10                 // 每枚恢复码有 80 位随机空间并以无填充 Base32 展示。

var ErrInvalidMFADependencies = errors.New("MFA dependencies are invalid")
var ErrInvalidMFAChallenge = errors.New("MFA challenge is invalid")
var ErrInvalidMFACode = errors.New("MFA code is invalid")
var ErrMFAEncryptionKeyUnavailable = errors.New("MFA encryption key unavailable")

// Challenge 是密码验证后的短期下一步；Secret 只能由 HTTP 写入 HttpOnly Cookie。
type Challenge struct {
	Purpose   string
	Secret    string
	ExpiresAt time.Time
	Session   *AccountSession // RequireMFA=false 时承载原有 UAT 登录反馈，不用于生产挑战。
}

// Enrollment 只在短期注册 challenge 有效时反馈一次 TOTP 注册材料。
type Enrollment struct {
	OTPAuthURI string `json:"otpauth_uri"`
	ManualKey  string `json:"manual_key"`
}

// RecoveryCodes 只在首次确认注册成功时反馈，数据库仅保留其摘要。
type RecoveryCodes []string

// MFACommands 隐藏密码后置挑战、因素保护和正常会话签发的完整状态机。
type MFACommands struct {
	database      transactionSource
	sessions      *SessionCommands
	now           func() time.Time
	requireMFA    bool
	encryptionKey []byte
}

// LoadMFAEncryptionKey 从受保护普通文件严格解码一枚 32 字节 AES-256 key。
func LoadMFAEncryptionKey(path string) ([]byte, error) {
	encoded, readError := platformsecret.Read(path)
	if readError != nil || encoded == "" {
		return nil, ErrMFAEncryptionKeyUnavailable
	}
	key, decodeError := base64.StdEncoding.Strict().DecodeString(encoded)
	if decodeError != nil || len(key) != 32 {
		return nil, ErrMFAEncryptionKeyUnavailable
	}
	return append([]byte(nil), key...), nil
}

// NewMFACommands 关闭式装配生产 MFA；UAT 可显式关闭并保留原有登录行为。
func NewMFACommands(database transactionSource, sessions *SessionCommands, now func() time.Time, requireMFA bool, encryptionKey []byte) (*MFACommands, error) {
	if database == nil || sessions == nil || now == nil || (requireMFA && len(encryptionKey) != 32) {
		return nil, ErrInvalidMFADependencies
	}
	keyCopy := append([]byte(nil), encryptionKey...)
	return &MFACommands{database: database, sessions: sessions, now: now, requireMFA: requireMFA, encryptionKey: keyCopy}, nil
}

// BeginLogin 验证第一因素；生产只写短期 challenge，显式关闭 MFA 的 UAT 沿用正常会话流程。
func (commands *MFACommands) BeginLogin(ctx context.Context, username string, password string, userAgent string) (Challenge, error) {
	if !commands.requireMFA {
		accountSession, loginError := commands.sessions.Login(ctx, username, password, userAgent)
		if loginError != nil {
			return Challenge{}, loginError
		}
		return Challenge{Session: &accountSession}, nil
	}

	tx, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return Challenge{}, ErrSessionWriteFailed
	}
	defer func() { _ = tx.Rollback(ctx) }()

	account, passwordHash, accountError := readLoginAccount(ctx, tx, username)
	if errors.Is(accountError, pgx.ErrNoRows) {
		_ = VerifyPassword(unknownAccountPasswordHash, password)
		return Challenge{}, ErrInvalidCredentials
	}
	if accountError != nil {
		return Challenge{}, ErrSessionWriteFailed
	}
	if !VerifyPassword(passwordHash, password) {
		return Challenge{}, ErrInvalidCredentials
	}
	if account.State != "active" {
		return Challenge{}, ErrAccountDisabled
	}

	purpose := MFAEnrollmentPurpose
	var confirmed bool
	if factorError := tx.QueryRow(ctx, "SELECT confirmed_at IS NOT NULL FROM account_mfa WHERE account_id = $1", account.ID).Scan(&confirmed); factorError != nil && !errors.Is(factorError, pgx.ErrNoRows) {
		return Challenge{}, ErrSessionWriteFailed
	} else if factorError == nil && confirmed {
		purpose = MFALoginPurpose
	}

	challengeID, challengeSecret, materialError := newMFAChallengeMaterial()
	if materialError != nil {
		return Challenge{}, ErrSessionIdentityUnavailable
	}
	now := commands.now().UTC()
	expiresAt := now.Add(MFAChallengeLifetime)
	digest := sha256.Sum256([]byte(challengeSecret))
	if _, invalidateError := tx.Exec(ctx, `
		UPDATE mfa_challenges SET remaining_attempts = 0
		WHERE account_id = $1 AND purpose = $2 AND consumed_at IS NULL AND remaining_attempts > 0`,
		account.ID, purpose,
	); invalidateError != nil {
		return Challenge{}, ErrSessionWriteFailed
	}
	if _, insertError := tx.Exec(ctx, `
		INSERT INTO mfa_challenges (
			id, account_id, purpose, secret_digest, expires_at, remaining_attempts, created_at
		) VALUES ($1, $2, $3, $4, $5, 5, $6)`,
		challengeID, account.ID, purpose, digest[:], expiresAt, now,
	); insertError != nil {
		return Challenge{}, ErrSessionWriteFailed
	}
	if commitError := tx.Commit(ctx); commitError != nil {
		return Challenge{}, ErrSessionWriteFailed
	}
	return Challenge{Purpose: purpose, Secret: challengeSecret, ExpiresAt: expiresAt}, nil
}

// BeginEnrollment 在有效注册 challenge 下建立或恢复一组未确认因素，明文只反馈给本次调用。
func (commands *MFACommands) BeginEnrollment(ctx context.Context, challengeSecret string) (Enrollment, error) {
	if !commands.requireMFA || challengeSecret == "" {
		return Enrollment{}, ErrInvalidMFAChallenge
	}
	tx, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return Enrollment{}, ErrSessionWriteFailed
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := commands.now().UTC()
	digest := sha256.Sum256([]byte(challengeSecret))
	var accountID string
	var username string
	challengeError := tx.QueryRow(ctx, `
		SELECT c.account_id, a.username_display
		FROM mfa_challenges AS c
		JOIN accounts AS a ON a.id = c.account_id
		WHERE c.secret_digest = $1 AND c.purpose = 'enroll' AND c.consumed_at IS NULL
			AND c.remaining_attempts > 0 AND $2 < c.expires_at AND a.state = 'active'
		FOR UPDATE OF c, a`, digest[:], now,
	).Scan(&accountID, &username)
	if errors.Is(challengeError, pgx.ErrNoRows) {
		return Enrollment{}, ErrInvalidMFAChallenge
	}
	if challengeError != nil {
		return Enrollment{}, ErrSessionWriteFailed
	}

	var ciphertext []byte
	var nonce []byte
	var keyVersion int
	var confirmedAt *time.Time
	factorError := tx.QueryRow(ctx, `
		SELECT encrypted_secret, secret_nonce, key_version, confirmed_at
		FROM account_mfa WHERE account_id = $1 FOR UPDATE`, accountID,
	).Scan(&ciphertext, &nonce, &keyVersion, &confirmedAt)
	var rawSecret []byte
	if errors.Is(factorError, pgx.ErrNoRows) {
		rawSecret = make([]byte, totpSecretBytes)
		if _, randomError := rand.Read(rawSecret); randomError != nil {
			return Enrollment{}, ErrSessionIdentityUnavailable
		}
		var protectError error
		keyVersion = 1
		ciphertext, nonce, protectError = encryptMFASecret(commands.encryptionKey, accountID, keyVersion, rawSecret)
		if protectError != nil {
			return Enrollment{}, ErrSessionIdentityUnavailable
		}
		if _, insertError := tx.Exec(ctx, `
			INSERT INTO account_mfa (
				account_id, encrypted_secret, secret_nonce, key_version, created_at, updated_at
			) VALUES ($1, $2, $3, 1, $4, $4)`, accountID, ciphertext, nonce, now,
		); insertError != nil {
			return Enrollment{}, ErrSessionWriteFailed
		}
	} else if factorError != nil {
		return Enrollment{}, ErrSessionWriteFailed
	} else {
		if confirmedAt != nil {
			return Enrollment{}, ErrInvalidMFAChallenge
		}
		var decryptError error
		rawSecret, decryptError = decryptMFASecret(commands.encryptionKey, accountID, keyVersion, nonce, ciphertext)
		if decryptError != nil {
			return Enrollment{}, ErrSessionWriteFailed
		}
	}
	if commitError := tx.Commit(ctx); commitError != nil {
		return Enrollment{}, ErrSessionWriteFailed
	}

	manualKey := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecret)
	label := url.PathEscape("CareerPathDesk:" + username)
	query := url.Values{"issuer": {"CareerPathDesk"}, "secret": {manualKey}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return Enrollment{OTPAuthURI: "otpauth://totp/" + label + "?" + query.Encode(), ManualKey: manualKey}, nil
}

// ConfirmEnrollment 用一个有效 TOTP 原子确认因素、生成恢复码并建立正常会话。
func (commands *MFACommands) ConfirmEnrollment(ctx context.Context, challengeSecret string, code string, userAgent string) (AccountSession, RecoveryCodes, error) {
	if !commands.requireMFA || challengeSecret == "" {
		return AccountSession{}, nil, ErrInvalidMFAChallenge
	}
	tx, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return AccountSession{}, nil, ErrSessionWriteFailed
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := commands.now().UTC()
	challengeDigest := sha256.Sum256([]byte(challengeSecret))
	challengeID, account, challengeError := lockMFAChallenge(ctx, tx, challengeDigest[:], MFAEnrollmentPurpose, now)
	if challengeError != nil {
		return AccountSession{}, nil, challengeError
	}

	var ciphertext []byte
	var nonce []byte
	var keyVersion int
	var confirmedAt *time.Time
	var lastAcceptedStep *int64
	factorError := tx.QueryRow(ctx, `
		SELECT encrypted_secret, secret_nonce, key_version, confirmed_at, last_accepted_step
		FROM account_mfa WHERE account_id = $1 FOR UPDATE`, account.ID,
	).Scan(&ciphertext, &nonce, &keyVersion, &confirmedAt, &lastAcceptedStep)
	if factorError != nil || confirmedAt != nil {
		return AccountSession{}, nil, ErrInvalidMFAChallenge
	}
	secret, decryptError := decryptMFASecret(commands.encryptionKey, account.ID, keyVersion, nonce, ciphertext)
	if decryptError != nil {
		return AccountSession{}, nil, ErrSessionWriteFailed
	}
	acceptedStep, valid := validTOTPStep(secret, code, now)
	if !valid || (lastAcceptedStep != nil && acceptedStep <= *lastAcceptedStep) {
		return AccountSession{}, nil, commands.rejectMFACode(ctx, tx, challengeID)
	}

	recoveryCodes, recoveryDigests, recoveryError := newRecoveryCodes()
	if recoveryError != nil {
		return AccountSession{}, nil, ErrSessionIdentityUnavailable
	}
	if _, updateError := tx.Exec(ctx, `
		UPDATE account_mfa
		SET confirmed_at = $2, last_accepted_step = $3, recovery_code_digests = $4, updated_at = $2
		WHERE account_id = $1`, account.ID, now, acceptedStep, recoveryDigests,
	); updateError != nil {
		return AccountSession{}, nil, ErrSessionWriteFailed
	}
	if _, consumeError := tx.Exec(ctx, "UPDATE mfa_challenges SET consumed_at = $2 WHERE id = $1", challengeID, now); consumeError != nil {
		return AccountSession{}, nil, ErrSessionWriteFailed
	}
	credential, sessionError := insertSession(ctx, tx, now, account.ID, account.CredentialVersion, userAgent)
	if sessionError != nil {
		return AccountSession{}, nil, sessionError
	}
	if commitError := tx.Commit(ctx); commitError != nil {
		return AccountSession{}, nil, ErrSessionWriteFailed
	}
	return AccountSession{Account: account, Credential: credential}, recoveryCodes, nil
}

// VerifyLogin 消费一个有效 TOTP 或恢复码，并在同一事务中建立正常会话。
func (commands *MFACommands) VerifyLogin(ctx context.Context, challengeSecret string, code string, userAgent string) (AccountSession, error) {
	if !commands.requireMFA || challengeSecret == "" {
		return AccountSession{}, ErrInvalidMFAChallenge
	}
	tx, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := commands.now().UTC()
	challengeDigest := sha256.Sum256([]byte(challengeSecret))
	challengeID, account, challengeError := lockMFAChallenge(ctx, tx, challengeDigest[:], MFALoginPurpose, now)
	if challengeError != nil {
		return AccountSession{}, challengeError
	}

	var ciphertext []byte
	var nonce []byte
	var keyVersion int
	var confirmedAt *time.Time
	var lastAcceptedStep *int64
	var recoveryDigests [][]byte
	factorError := tx.QueryRow(ctx, `
		SELECT encrypted_secret, secret_nonce, key_version, confirmed_at, last_accepted_step, recovery_code_digests
		FROM account_mfa WHERE account_id = $1 FOR UPDATE`, account.ID,
	).Scan(&ciphertext, &nonce, &keyVersion, &confirmedAt, &lastAcceptedStep, &recoveryDigests)
	if factorError != nil || confirmedAt == nil {
		return AccountSession{}, ErrInvalidMFAChallenge
	}
	secret, decryptError := decryptMFASecret(commands.encryptionKey, account.ID, keyVersion, nonce, ciphertext)
	if decryptError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}

	acceptedStep, validTOTP := validTOTPStep(secret, code, now)
	if validTOTP && lastAcceptedStep != nil && acceptedStep <= *lastAcceptedStep {
		validTOTP = false // 同一或更旧的允许窗口时间步不能在新 challenge 中重放。
	}
	recoveryIndex := matchingRecoveryCode(recoveryDigests, code)
	if !validTOTP && recoveryIndex < 0 {
		return AccountSession{}, commands.rejectMFACode(ctx, tx, challengeID)
	}
	if validTOTP {
		if _, updateError := tx.Exec(ctx, `
			UPDATE account_mfa SET last_accepted_step = $2, updated_at = $3 WHERE account_id = $1`,
			account.ID, acceptedStep, now,
		); updateError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
	} else {
		recoveryDigests = append(recoveryDigests[:recoveryIndex], recoveryDigests[recoveryIndex+1:]...)
		if _, updateError := tx.Exec(ctx, `
			UPDATE account_mfa SET recovery_code_digests = $2, updated_at = $3 WHERE account_id = $1`,
			account.ID, recoveryDigests, now,
		); updateError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
	}
	if _, consumeError := tx.Exec(ctx, "UPDATE mfa_challenges SET consumed_at = $2 WHERE id = $1", challengeID, now); consumeError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	credential, sessionError := insertSession(ctx, tx, now, account.ID, account.CredentialVersion, userAgent)
	if sessionError != nil {
		return AccountSession{}, sessionError
	}
	if commitError := tx.Commit(ctx); commitError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	return AccountSession{Account: account, Credential: credential}, nil
}

func matchingRecoveryCode(digests [][]byte, code string) int {
	candidate := sha256.Sum256([]byte(code))
	match := -1
	for index, digest := range digests { // 不因前部命中而提前返回，所有已存摘要承担同样比较工作。
		if subtle.ConstantTimeCompare(digest, candidate[:]) == 1 {
			match = index
		}
	}
	return match
}

func lockMFAChallenge(ctx context.Context, tx pgx.Tx, digest []byte, purpose string, now time.Time) (string, Account, error) {
	account := Account{}
	var challengeID string
	queryError := tx.QueryRow(ctx, `
		SELECT c.id, a.id, a.username_display, a.display_name, a.role, a.state, a.staff_profile_id,
			a.credential_version, a.must_change_password
		FROM mfa_challenges AS c
		JOIN accounts AS a ON a.id = c.account_id
		WHERE c.secret_digest = $1 AND c.purpose = $2 AND c.consumed_at IS NULL
			AND c.remaining_attempts > 0 AND $3 < c.expires_at AND a.state = 'active'
		FOR UPDATE OF c, a`, digest, purpose, now,
	).Scan(
		&challengeID, &account.ID, &account.Username, &account.DisplayName, &account.Role, &account.State, &account.StaffProfileID,
		&account.CredentialVersion, &account.MustChangePassword,
	)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return "", Account{}, ErrInvalidMFAChallenge
	}
	if queryError != nil {
		return "", Account{}, ErrSessionWriteFailed
	}
	return challengeID, account, nil
}

func (commands *MFACommands) rejectMFACode(ctx context.Context, tx pgx.Tx, challengeID string) error {
	if _, updateError := tx.Exec(ctx, `
		UPDATE mfa_challenges SET remaining_attempts = remaining_attempts - 1 WHERE id = $1`, challengeID,
	); updateError != nil {
		return ErrSessionWriteFailed
	}
	if commitError := tx.Commit(ctx); commitError != nil {
		return ErrSessionWriteFailed
	}
	return ErrInvalidMFACode
}

func validTOTPStep(secret []byte, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	currentStep := now.Unix() / 30
	acceptedStep := int64(0)
	matched := 0
	for _, step := range []int64{currentStep - 1, currentStep, currentStep + 1} {
		expected := totpCode(secret, step)
		equal := subtle.ConstantTimeCompare([]byte(expected), []byte(code))
		acceptedStep = int64(subtle.ConstantTimeSelect(equal, int(step), int(acceptedStep)))
		matched |= equal // 三个允许窗口全部计算，不从命中位置泄露提前返回时序。
	}
	return acceptedStep, matched == 1
}

func totpCode(secret []byte, step int64) string {
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(step))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}

func newRecoveryCodes() (RecoveryCodes, [][]byte, error) {
	codes := make(RecoveryCodes, MFARecoveryCodeCount)
	digests := make([][]byte, MFARecoveryCodeCount)
	for index := range codes {
		randomBytes := make([]byte, recoveryCodeBytes)
		if _, randomError := rand.Read(randomBytes); randomError != nil {
			return nil, nil, randomError
		}
		codes[index] = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
		digest := sha256.Sum256([]byte(codes[index]))
		digests[index] = append([]byte(nil), digest[:]...)
	}
	return codes, digests, nil
}

func readLoginAccount(ctx context.Context, tx pgx.Tx, username string) (Account, string, error) {
	account := Account{}
	var passwordHash string
	normalized := cases.Fold().String(norm.NFKC.String(strings.TrimSpace(username)))
	queryError := tx.QueryRow(ctx, `
		SELECT id, username_display, display_name, role, state, staff_profile_id,
			credential_version, must_change_password, password_hash
		FROM accounts WHERE username_normalized = $1 FOR UPDATE`, normalized,
	).Scan(
		&account.ID, &account.Username, &account.DisplayName, &account.Role, &account.State, &account.StaffProfileID,
		&account.CredentialVersion, &account.MustChangePassword, &passwordHash,
	)
	return account, passwordHash, queryError
}

func newMFAChallengeMaterial() (string, string, error) {
	challengeID, identityError := identity.New("MC")
	if identityError != nil {
		return "", "", identityError
	}
	randomBytes := make([]byte, mfaChallengeSecretBytes)
	if _, randomError := rand.Read(randomBytes); randomError != nil {
		return "", "", randomError
	}
	return challengeID, base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func encryptMFASecret(key []byte, accountID string, keyVersion int, plaintext []byte) ([]byte, []byte, error) {
	block, blockError := aes.NewCipher(key)
	if blockError != nil {
		return nil, nil, blockError
	}
	gcm, gcmError := cipher.NewGCM(block)
	if gcmError != nil {
		return nil, nil, gcmError
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, randomError := rand.Read(nonce); randomError != nil {
		return nil, nil, randomError
	}
	return gcm.Seal(nil, nonce, plaintext, mfaAAD(accountID, keyVersion)), nonce, nil
}

func decryptMFASecret(key []byte, accountID string, keyVersion int, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, blockError := aes.NewCipher(key)
	if blockError != nil {
		return nil, blockError
	}
	gcm, gcmError := cipher.NewGCM(block)
	if gcmError != nil || len(nonce) != gcm.NonceSize() {
		return nil, ErrSessionWriteFailed
	}
	return gcm.Open(nil, nonce, ciphertext, mfaAAD(accountID, keyVersion))
}

func mfaAAD(accountID string, keyVersion int) []byte {
	return []byte(fmt.Sprintf("careerpathdesk:mfa:%s:key:%d", accountID, keyVersion)) // 密文不能在账号或密钥版本之间交换。
}
