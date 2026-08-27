/*
账号管理命令测试：通过真实 PostgreSQL schema 验证老板权限先行和原子账号生命周期。
每个测试只使用 Foundation 合成数据；不连接 v1、正式库或私有候选库。
*/
package accounts

import (
	"bytes"         // 比较持久化摘要与不安全的旧快速密码验证器。
	"context"       // 驱动公开账号命令和测试数据库清理。
	"crypto/rand"   // 为每个测试生成互不碰撞的 schema 身份。
	"crypto/sha256" // 重建旧请求摘要以证明它不再能快速验证密码猜测。
	"encoding/hex"  // 将随机 schema 身份编码为安全 SQL 标识。
	"encoding/json" // 按旧固定字段顺序形成回归对照输入。
	"errors"        // 断言稳定公开错误分类而不是底层数据库正文。
	"os"            // 读取显式合成数据库配置和正式 migration/seed 文件。
	"strings"       // 清理受保护密码文件中的结尾换行。
	"testing"       // 组织可独立运行的账号行为测试。
	"time"          // 注入固定 UTC 事实，使审计和撤销可重复。

	"github.com/jackc/pgx/v5" // 使用真实 PostgreSQL 连接和安全 schema 标识引用。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"             // 复用已验证的公开账号投影和密码能力。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"  // 使用二进制唯一支持的 schema 版本事实。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate" // 通过正式入口建立完整产品 schema。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/seed"    // 只装载固定合成身份。
)

const syntheticInitialPassword = "CareerPathDesk-Test-Only!" // 只对应本测试 seed，不对应任何已部署环境。

// --- 员工在任何账号输入处理前被拒绝 ---
func TestStaffCannotCreateAccountEvenWithInvalidInput(t *testing.T) {
	connection := openAccountsTestDatabase(t) // 每个测试拥有独立随机 schema。
	commands := newAccountsTestCommands(t, connection)
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active"} // 模拟已由认证模块验证的员工投影。

	_, createError := commands.Create(context.Background(), staff, "R-syntheticstaffdeny", "synthetic-key-staff-deny", CreateInput{})

	if !errors.Is(createError, ErrForbidden) { // 权限拒绝必须先于空用户名、密码和员工关联校验。
		t.Fatalf("staff account creation did not fail role-first: %v", createError)
	}
}

// --- 老板创建员工账号时由同一事务自动建立责任档案 ---
func TestCreateStaffWithoutProfileAtomicallyProvisionsActiveProfile(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	var profilesBefore int
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM staff_profiles`).Scan(&profilesBefore); queryError != nil {
		t.Fatal("synthetic staff profile baseline query failed")
	}

	input := CreateInput{
		Username: "synthetic-auto-profile", DisplayName: "  Ｓynthetic Auto Staff  ", Role: "staff",
		InitialPassword: syntheticInitialPassword,
	}
	created, createError := commands.Create(t.Context(), owner, "R-syntheticautoprofile01", "synthetic-key-auto-profile-01", input)
	if createError != nil {
		t.Fatalf("staff account did not provision its responsibility profile: %v", createError)
	}
	if created.StaffProfileID == nil || !validStaffProfileID(created.StaffProfileID) {
		t.Fatalf("staff account omitted a generated responsibility profile: %#v", created)
	}
	replayed, replayError := commands.Create(t.Context(), owner, "R-syntheticautoprofile02", "synthetic-key-auto-profile-01", input)
	if replayError != nil || replayed.ID != created.ID || replayed.StaffProfileID == nil || *replayed.StaffProfileID != *created.StaffProfileID {
		t.Fatalf("automatic staff profile was not idempotent: first=%#v replay=%#v error=%v", created, replayed, replayError)
	}

	var profileDisplayName string
	var profileState string
	var profileVersion int64
	if queryError := connection.QueryRow(t.Context(), `SELECT display_name, state, version FROM staff_profiles WHERE id = $1`, *created.StaffProfileID).Scan(&profileDisplayName, &profileState, &profileVersion); queryError != nil {
		t.Fatal("generated staff profile query failed")
	}
	var profilesAfter int
	var accountCount int
	var auditCount int
	var idempotencyCount int
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM staff_profiles`).Scan(&profilesAfter); queryError != nil {
		t.Fatal("generated staff profile count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE id = $1 AND staff_profile_id = $2`, created.ID, *created.StaffProfileID).Scan(&accountCount); queryError != nil {
		t.Fatal("generated staff account count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action = 'account.created' AND object_id = $1`, created.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("generated staff audit count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM idempotency_records WHERE actor_scope = $1 AND action = 'account.create' AND idempotency_key = 'synthetic-key-auto-profile-01'`, owner.ID).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("generated staff idempotency count failed")
	}
	if profileDisplayName != "Synthetic Auto Staff" || profileState != "active" || profileVersion != 1 || profilesAfter != profilesBefore+1 || accountCount != 1 || auditCount != 1 || idempotencyCount != 1 {
		t.Fatalf("generated profile/account transaction is incomplete: display=%q state=%s version=%d profiles=%d->%d accounts=%d audits=%d idempotency=%d", profileDisplayName, profileState, profileVersion, profilesBefore, profilesAfter, accountCount, auditCount, idempotencyCount)
	}
}

// --- 自动员工档案与账号在审计失败时共同回滚 ---
func TestCreateStaffProfileRollsBackWithAccountAuditFailure(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	var profilesBefore int
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM staff_profiles`).Scan(&profilesBefore); queryError != nil {
		t.Fatal("synthetic staff profile rollback baseline failed")
	}
	if _, triggerError := connection.Exec(t.Context(), `
		CREATE FUNCTION reject_synthetic_account_create_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'account.created' THEN
				RAISE EXCEPTION 'synthetic account audit rejection';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_synthetic_account_create_audit
		BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_synthetic_account_create_audit();
	`); triggerError != nil {
		t.Fatal("synthetic account audit rejection setup failed")
	}

	_, createError := commands.Create(t.Context(), owner, "R-syntheticautorollback01", "synthetic-key-auto-rollback-01", CreateInput{
		Username: "synthetic-auto-rollback", DisplayName: "Synthetic Auto Rollback", Role: "staff",
		InitialPassword: syntheticInitialPassword,
	})
	if !errors.Is(createError, ErrWriteFailed) {
		t.Fatalf("injected account audit failure was not safe: %v", createError)
	}

	var profilesAfter int
	var accountCount int
	var auditCount int
	var idempotencyCount int
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM staff_profiles`).Scan(&profilesAfter); queryError != nil {
		t.Fatal("rolled-back staff profile count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE username_normalized = 'synthetic-auto-rollback'`).Scan(&accountCount); queryError != nil {
		t.Fatal("rolled-back staff account count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action = 'account.created' AND request_id = 'R-syntheticautorollback01'`).Scan(&auditCount); queryError != nil {
		t.Fatal("rolled-back staff audit count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM idempotency_records WHERE actor_scope = $1 AND action = 'account.create' AND idempotency_key = 'synthetic-key-auto-rollback-01'`, owner.ID).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("rolled-back staff idempotency count failed")
	}
	if profilesAfter != profilesBefore || accountCount != 0 || auditCount != 0 || idempotencyCount != 0 {
		t.Fatalf("account audit failure left partial staff facts: profiles=%d->%d accounts=%d audits=%d idempotency=%d", profilesBefore, profilesAfter, accountCount, auditCount, idempotencyCount)
	}
}

// --- 持久化幂等摘要不得成为初始密码的快速离线验证器 ---
func TestCreateIdempotencyDigestDoesNotPersistFastPasswordVerifier(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	input := CreateInput{
		Username: "synthetic-safe-digest", DisplayName: "Synthetic Safe Digest", Role: "staff",
		InitialPassword: syntheticInitialPassword,
	}
	if _, createError := commands.Create(t.Context(), owner, "R-syntheticsafedigest01", "synthetic-key-safe-digest-01", input); createError != nil {
		t.Fatalf("synthetic safe-digest account creation failed: %v", createError)
	}
	var storedDigest []byte
	if queryError := connection.QueryRow(t.Context(), `SELECT request_digest FROM idempotency_records WHERE actor_scope = $1 AND action = 'account.create' AND idempotency_key = 'synthetic-key-safe-digest-01'`, owner.ID).Scan(&storedDigest); queryError != nil {
		t.Fatal("synthetic account request digest query failed")
	}
	oldDigestBody, marshalError := json.Marshal(struct {
		Username        string  `json:"username"`
		DisplayName     string  `json:"display_name"`
		Role            string  `json:"role"`
		StaffProfileID  *string `json:"staff_profile_id"`
		InitialPassword string  `json:"initial_password"`
	}{input.Username, input.DisplayName, input.Role, input.StaffProfileID, input.InitialPassword})
	if marshalError != nil {
		t.Fatal("synthetic legacy digest fixture failed")
	}
	oldFastDigest := sha256.Sum256(oldDigestBody)
	if bytes.Equal(storedDigest, oldFastDigest[:]) {
		t.Fatal("account idempotency digest remained a single-SHA-256 password verifier")
	}
}

// --- 用户名按 NFKC、外部空白和大小写形成唯一身份 ---
func TestCreateNormalizesUsernameAndRejectsEquivalentIdentity(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	staffProfileID := "T-syntheticcoach03"
	if _, insertError := connection.Exec(context.Background(), `INSERT INTO staff_profiles (id, display_name) VALUES ($1, 'Synthetic Coach Three')`, staffProfileID); insertError != nil { // 创建尚未绑定账号的合成责任档案。
		t.Fatal("synthetic staff profile creation failed")
	}

	created, createError := commands.Create(context.Background(), owner, "R-syntheticcreate01", "synthetic-key-create-01", CreateInput{
		Username: "  Ｓynthetic-New  ", DisplayName: "Synthetic Staff Three", Role: "staff",
		StaffProfileID: &staffProfileID, InitialPassword: syntheticInitialPassword,
	})
	if createError != nil {
		t.Fatalf("normalized account creation failed: %v", createError)
	}
	if created.Username != "Synthetic-New" || created.Role != "staff" || created.StaffProfileID == nil || *created.StaffProfileID != staffProfileID || !created.MustChangePassword || created.Version != 1 { // 返回值只含可管理投影和首次改密事实。
		t.Fatalf("unexpected created account projection: %#v", created)
	}

	_, duplicateError := commands.Create(context.Background(), owner, "R-syntheticcreate02", "synthetic-key-create-02", CreateInput{
		Username: "synthetic-new", DisplayName: "Duplicate Synthetic Staff", Role: "owner",
		InitialPassword: syntheticInitialPassword,
	})
	if !errors.Is(duplicateError, ErrConflict) { // 大小写和兼容字符差异不得创建第二个登录身份。
		t.Fatalf("equivalent username was not rejected: %v", duplicateError)
	}
}

// --- 一个员工责任档案只能绑定一个逐人账号 ---
func TestCreateRejectsSecondAccountForSameStaffProfile(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	staffProfileID := "T-syntheticcoach03"
	if _, insertError := connection.Exec(context.Background(), `INSERT INTO staff_profiles (id, display_name) VALUES ($1, 'Synthetic Coach Three')`, staffProfileID); insertError != nil {
		t.Fatal("synthetic staff profile creation failed")
	}

	_, firstError := commands.Create(context.Background(), owner, "R-syntheticprofile01", "synthetic-key-profile-01", CreateInput{
		Username: "synthetic-profile-one", DisplayName: "Synthetic Profile One", Role: "staff",
		StaffProfileID: &staffProfileID, InitialPassword: syntheticInitialPassword,
	})
	if firstError != nil {
		t.Fatalf("first staff association failed: %v", firstError)
	}
	_, secondError := commands.Create(context.Background(), owner, "R-syntheticprofile02", "synthetic-key-profile-02", CreateInput{
		Username: "synthetic-profile-two", DisplayName: "Synthetic Profile Two", Role: "staff",
		StaffProfileID: &staffProfileID, InitialPassword: syntheticInitialPassword,
	})
	if !errors.Is(secondError, ErrConflict) { // 唯一责任关联必须由数据库约束在同一事务内裁决。
		t.Fatalf("duplicate staff association was not rejected: %v", secondError)
	}
}

// --- 停用保留历史账号并立即撤销其全部活动会话 ---
func TestDisableRetainsAccountAndRevokesSessions(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	staffProfileID := "T-syntheticcoach03"
	if _, insertError := connection.Exec(context.Background(), `INSERT INTO staff_profiles (id, display_name) VALUES ($1, 'Synthetic Coach Three')`, staffProfileID); insertError != nil {
		t.Fatal("synthetic staff profile creation failed")
	}
	created, createError := commands.Create(context.Background(), owner, "R-syntheticdisable01", "synthetic-key-disable-01", CreateInput{
		Username: "synthetic-disable", DisplayName: "Synthetic Disabled Staff", Role: "staff",
		StaffProfileID: &staffProfileID, InitialPassword: syntheticInitialPassword,
	})
	if createError != nil {
		t.Fatalf("synthetic account creation failed: %v", createError)
	}
	sessions, sessionError := auth.NewSessionCommands(connection, func() time.Time { return time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC) })
	if sessionError != nil {
		t.Fatalf("synthetic session commands failed to initialize: %v", sessionError)
	}
	credential, startError := sessions.Start(context.Background(), created.ID, "Synthetic Browser")
	if startError != nil {
		t.Fatalf("synthetic session failed to start: %v", startError)
	}

	disabled, updateError := commands.Update(context.Background(), owner, "R-syntheticdisable02", created.ID, UpdateInput{
		State: "disabled", StaffProfileID: &staffProfileID, Version: created.Version,
	})
	if updateError != nil {
		t.Fatalf("account disable failed: %v", updateError)
	}
	if disabled.State != "disabled" || disabled.Version != created.Version+1 || disabled.CredentialVersion != created.CredentialVersion+1 {
		t.Fatalf("unexpected disabled account projection: %#v", disabled)
	}
	listed, listError := commands.List(context.Background(), owner)
	if listError != nil {
		t.Fatalf("account list failed: %v", listError)
	}
	if !containsAccount(listed, created.ID) { // 停用是终态标记，不允许物理删除历史身份。
		t.Fatal("disabled account disappeared from management list")
	}
	if _, currentError := sessions.Current(context.Background(), created.ID, credential.SessionID, credential.CredentialVersion); !errors.Is(currentError, auth.ErrAuthenticationRequired) {
		t.Fatalf("disabled account session remained usable: %v", currentError)
	}
}

// --- 老板重置密码后旧凭据和旧会话同时失效 ---
func TestResetPasswordReplacesCredentialAndRevokesSessions(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	created, createError := commands.Create(context.Background(), owner, "R-syntheticreset01", "synthetic-key-reset-01", CreateInput{
		Username: "synthetic-reset", DisplayName: "Synthetic Reset Owner", Role: "owner", InitialPassword: syntheticInitialPassword,
	})
	if createError != nil {
		t.Fatalf("synthetic account creation failed: %v", createError)
	}
	sessions, sessionError := auth.NewSessionCommands(connection, func() time.Time { return time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC) })
	if sessionError != nil {
		t.Fatalf("synthetic session commands failed to initialize: %v", sessionError)
	}
	login, loginError := sessions.Login(context.Background(), created.Username, syntheticInitialPassword, "Synthetic Browser")
	if loginError != nil {
		t.Fatalf("initial password login failed: %v", loginError)
	}
	mfa, mfaError := auth.NewMFACommands(connection, sessions, func() time.Time { return time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC) }, true, []byte("synthetic-mfa-key-32-bytes-only!"))
	if mfaError != nil {
		t.Fatalf("synthetic MFA commands failed to initialize: %v", mfaError)
	}
	challenge, challengeError := mfa.BeginLogin(context.Background(), created.Username, syntheticInitialPassword, "Synthetic Browser")
	if challengeError != nil {
		t.Fatalf("pre-reset MFA challenge failed: %v", challengeError)
	}
	newPassword := "CareerPathDesk-Synthetic-Reset-2026!"

	reset, resetError := commands.ResetPassword(context.Background(), owner, "R-syntheticreset02", created.ID, newPassword)
	if resetError != nil {
		t.Fatalf("password reset failed: %v", resetError)
	}
	if !reset.MustChangePassword || reset.Version != created.Version+1 || reset.CredentialVersion != created.CredentialVersion+1 {
		t.Fatalf("unexpected reset account projection: %#v", reset)
	}
	if _, oldLoginError := sessions.Login(context.Background(), created.Username, syntheticInitialPassword, "Synthetic Old Browser"); !errors.Is(oldLoginError, auth.ErrInvalidCredentials) {
		t.Fatalf("old password remained valid: %v", oldLoginError)
	}
	newLogin, newLoginError := sessions.Login(context.Background(), created.Username, newPassword, "Synthetic New Browser")
	if newLoginError != nil || !newLogin.Account.MustChangePassword {
		t.Fatalf("new temporary password did not require first change: %#v %v", newLogin.Account, newLoginError)
	}
	if _, currentError := sessions.Current(context.Background(), created.ID, login.Credential.SessionID, login.Credential.CredentialVersion); !errors.Is(currentError, auth.ErrAuthenticationRequired) {
		t.Fatalf("pre-reset session remained usable: %v", currentError)
	}
	if _, oldChallengeError := mfa.BeginEnrollment(context.Background(), challenge.Secret); !errors.Is(oldChallengeError, auth.ErrInvalidMFAChallenge) {
		t.Fatalf("pre-reset MFA challenge remained usable: %v", oldChallengeError)
	}
}

// --- 创建重试反馈首次结果，不重复账号或审计 ---
func TestCreateIdempotencyReplaysSameIntentAndRejectsDifferentIntent(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	input := CreateInput{
		Username: "synthetic-idempotent", DisplayName: "Synthetic Idempotent Owner", Role: "owner", InitialPassword: syntheticInitialPassword,
	}

	first, firstError := commands.Create(context.Background(), owner, "R-syntheticidem01", "synthetic-key-idempotent-01", input)
	if firstError != nil {
		t.Fatalf("first idempotent creation failed: %v", firstError)
	}
	replayed, replayError := commands.Create(context.Background(), owner, "R-syntheticidem02", "synthetic-key-idempotent-01", input)
	if replayError != nil || replayed.ID != first.ID {
		t.Fatalf("same intent did not replay first result: %#v %v", replayed, replayError)
	}
	different := input
	different.DisplayName = "Different Synthetic Intent"
	if _, conflictError := commands.Create(context.Background(), owner, "R-syntheticidem03", "synthetic-key-idempotent-01", different); !errors.Is(conflictError, ErrIdempotencyConflict) {
		t.Fatalf("different intent reused idempotency key: %v", conflictError)
	}
	var accountCount int
	var auditCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM accounts WHERE username_normalized = 'synthetic-idempotent'`).Scan(&accountCount); queryError != nil {
		t.Fatal("synthetic account count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'account.created' AND object_id = $1`, first.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic audit count failed")
	}
	if accountCount != 1 || auditCount != 1 {
		t.Fatalf("idempotent retry duplicated facts: accounts=%d audits=%d", accountCount, auditCount)
	}
}

// --- 老板可撤销目标账号会话而不改变其凭据版本 ---
func TestRevokeSessionsTerminatesDevicesWithoutChangingCredential(t *testing.T) {
	connection := openAccountsTestDatabase(t)
	commands := newAccountsTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	created, createError := commands.Create(context.Background(), owner, "R-syntheticrevoke01", "synthetic-key-revoke-01", CreateInput{
		Username: "synthetic-revoke", DisplayName: "Synthetic Revoke Owner", Role: "owner", InitialPassword: syntheticInitialPassword,
	})
	if createError != nil {
		t.Fatalf("synthetic account creation failed: %v", createError)
	}
	sessions, sessionError := auth.NewSessionCommands(connection, func() time.Time { return time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC) })
	if sessionError != nil {
		t.Fatalf("synthetic session commands failed to initialize: %v", sessionError)
	}
	credential, startError := sessions.Start(context.Background(), created.ID, "Synthetic Browser")
	if startError != nil {
		t.Fatalf("synthetic session failed to start: %v", startError)
	}

	if revokeError := commands.RevokeSessions(context.Background(), owner, "R-syntheticrevoke02", created.ID); revokeError != nil {
		t.Fatalf("owner session revoke failed: %v", revokeError)
	}
	if _, currentError := sessions.Current(context.Background(), created.ID, credential.SessionID, credential.CredentialVersion); !errors.Is(currentError, auth.ErrAuthenticationRequired) {
		t.Fatalf("revoked device remained usable: %v", currentError)
	}
	var credentialVersion int64
	if queryError := connection.QueryRow(context.Background(), `SELECT credential_version FROM accounts WHERE id = $1`, created.ID).Scan(&credentialVersion); queryError != nil {
		t.Fatal("synthetic credential version query failed")
	}
	if credentialVersion != created.CredentialVersion { // 显式设备撤销不使未创建的新会话凭据整体失效。
		t.Fatalf("session revoke unexpectedly changed credential version: got=%d want=%d", credentialVersion, created.CredentialVersion)
	}
}

// --- 判断管理列表是否仍包含指定历史身份 ---
func containsAccount(accounts []Account, accountID string) bool {
	for _, account := range accounts {
		if account.ID == accountID {
			return true
		}
	}
	return false
}

// --- 打开 Foundation 已迁移、已 seed 的随机账号测试 schema ---
func openAccountsTestDatabase(t *testing.T) *pgx.Conn {
	t.Helper()                                                                             // 装配错误应归因到调用行为测试。
	databaseURL := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL"))            // 地址必须显式指向专用合成测试库。
	passwordFile := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE")) // 密码只从忽略的 0600 文件读取。
	if databaseURL == "" || passwordFile == "" {
		t.Fatal("explicit synthetic test database URL and password file are required")
	}
	passwordBytes, readError := os.ReadFile(passwordFile)
	if readError != nil {
		t.Fatal("synthetic database password file unavailable")
	}
	connectionConfig, parseError := pgx.ParseConfig(databaseURL)
	if parseError != nil {
		t.Fatal("synthetic database URL is invalid")
	}
	connectionConfig.Password = strings.TrimSpace(string(passwordBytes))
	connection, connectError := pgx.ConnectConfig(context.Background(), connectionConfig)
	if connectError != nil {
		t.Fatal("synthetic database connection failed")
	}

	randomIdentity := make([]byte, 8) // 64 位随机后缀足以隔离本地并发测试。
	if _, randomError := rand.Read(randomIdentity); randomError != nil {
		t.Fatal("synthetic account schema identity unavailable")
	}
	schemaName := "accounts_" + hex.EncodeToString(randomIdentity)
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()
	if _, createError := connection.Exec(context.Background(), "CREATE SCHEMA "+quotedSchema); createError != nil {
		t.Fatal("synthetic account schema creation failed")
	}
	if _, selectError := connection.Exec(context.Background(), "SET search_path TO "+quotedSchema); selectError != nil {
		t.Fatal("synthetic account schema selection failed")
	}

	migrations, loadError := migrate.Load(os.DirFS("../../database/migrations"))
	if loadError != nil {
		t.Fatalf("foundation migrations failed to load: %v", loadError)
	}
	if applyError := migrate.Apply(context.Background(), connection, migrations); applyError != nil {
		t.Fatalf("foundation migration failed: %v", applyError)
	}
	seedBytes, seedReadError := os.ReadFile("../../database/seeds/synthetic.sql")
	if seedReadError != nil {
		t.Fatal("synthetic seed failed to load")
	}
	if _, seedError := seed.Apply(context.Background(), connection, string(seedBytes), config.SupportedSchemaVersion, "CareerPathDesk-Test-Only!"); seedError != nil { // 只用不对应部署环境的测试凭据建立账号夹具。
		t.Fatalf("synthetic seed failed: %v", seedError)
	}
	if _, updateError := connection.Exec(context.Background(), "UPDATE accounts SET must_change_password = false WHERE id = 'A-syntheticowner01'"); updateError != nil { // 合成老板先完成首次改密，才能进入账号管理切片。
		t.Fatal("synthetic owner activation failed")
	}

	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "SET search_path TO public")            // 先离开待删除 schema。
		_, _ = connection.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") // 只清理本测试创建的随机 schema。
		_ = connection.Close(context.Background())                                           // 最后释放连接。
	})
	return connection // 反馈只含合成 Foundation 数据的隔离连接。
}

// --- 装配固定时钟和可预测领域 ID 的账号命令 ---
func newAccountsTestCommands(t *testing.T, connection *pgx.Conn) *Commands {
	t.Helper() // 构造失败应指向调用测试。
	identityCount := 0
	commands, createError := NewCommands(
		connection,
		func() time.Time { return time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC) },
		func(prefix string) (string, error) {
			identityCount++
			return prefix + "-syntheticidentity" + string(rune('a'+identityCount)), nil // 前缀固定且正文不含业务信息。
		},
	)
	if createError != nil {
		t.Fatalf("account commands failed to initialize: %v", createError)
	}
	return commands
}
