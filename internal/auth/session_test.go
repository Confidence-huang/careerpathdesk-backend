/*
刷新会话行为测试：通过真实隔离 PostgreSQL 证明轮换只返回一次新秘密，旧秘密重放会撤销完整 family。
测试只使用 Foundation 固定合成账号和每次随机 schema；断言只观察公开命令反馈，不输出 hash、secret 或业务行。
*/
package auth

import (
	"context"      // 为 migration、seed 和会话命令提供同一可取消测试边界。
	"crypto/rand"  // 为每个测试生成不可碰撞的 PostgreSQL schema 身份。
	"encoding/hex" // 将随机 schema 身份转换为安全标识片段。
	"errors"       // 比较稳定认证错误，不依赖错误文字。
	"os"           // 读取显式合成数据库配置和受审查的 seed 文件。
	"strings"      // 去除密码文件末尾换行，不改变秘密正文。
	"testing"      // 运行 Go 标准真实数据库行为测试。
	"time"         // 固定命令时间，精确验证轮换而不依赖墙钟。

	"github.com/jackc/pgx/v5" // 建立本轮随机 schema 的 PostgreSQL 连接。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"  // 使用二进制唯一支持的 schema 版本事实。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate" // 通过正式入口创建完整产品 schema。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/seed"    // 通过正式入口写入固定合成账号。
)

// --- 旧刷新秘密重放后，同一 family 的新秘密也立即失效 ---
func TestRotateRefreshReplayRevokesTokenFamily(t *testing.T) {
	connection := openSessionTestDatabase(t) // 建立只属于本测试的真实 PostgreSQL schema。
	fixedNow := time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC)
	sessions, createError := NewSessionCommands(connection, func() time.Time { return fixedNow })
	if createError != nil {
		t.Fatalf("session commands failed to initialize: %v", createError)
	}

	first, startError := sessions.Start(context.Background(), "A-syntheticowner01", "synthetic-browser")
	if startError != nil {
		t.Fatalf("synthetic session failed to start: %v", startError)
	}
	second, rotateError := sessions.Rotate(context.Background(), first.SessionID, first.RefreshToken)
	if rotateError != nil {
		t.Fatalf("first refresh rotation failed: %v", rotateError)
	}
	if second.SessionID == first.SessionID || second.RefreshToken == first.RefreshToken { // 轮换必须同时更换公开会话和秘密。
		t.Fatal("refresh rotation reused session credentials")
	}

	_, replayError := sessions.Rotate(context.Background(), first.SessionID, first.RefreshToken)
	if !errors.Is(replayError, ErrRefreshReplay) { // 旧秘密第二次出现必须形成可审计的稳定安全分类。
		t.Fatalf("expected ErrRefreshReplay, got %v", replayError)
	}
	_, activeFamilyError := sessions.Rotate(context.Background(), second.SessionID, second.RefreshToken)
	if !errors.Is(activeFamilyError, ErrInvalidRefreshSession) { // 重放撤销必须已经提交，不能随错误响应回滚。
		t.Fatalf("expected revoked family to reject current secret, got %v", activeFamilyError)
	}
}

// --- 小工具模式保持登录三十天，不再设置十二小时闲置门槛 ---
func TestNewSessionRemainsValidForThirtyDaysWithoutIdleCutoff(t *testing.T) {
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 9, 9, 0, 0, 0, time.UTC)
	sessions, createError := NewSessionCommands(connection, func() time.Time { return fixedNow })
	if createError != nil {
		t.Fatalf("session commands failed to initialize: %v", createError)
	}

	started, startError := sessions.Start(context.Background(), "A-syntheticowner01", "synthetic-browser")
	if startError != nil {
		t.Fatalf("synthetic session failed to start: %v", startError)
	}
	wantExpiry := fixedNow.Add(30 * 24 * time.Hour)
	if !started.IdleExpiresAt.Equal(wantExpiry) || !started.AbsoluteExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expected one thirty-day session boundary, got idle=%s absolute=%s", started.IdleExpiresAt, started.AbsoluteExpiresAt)
	}
}

// --- 修改本人密码后，旧密码与全部既有设备同时失效 ---
func TestChangePasswordRevokesEveryAccountSession(t *testing.T) {
	connection := openSessionTestDatabase(t) // 使用本测试独享且仅含 synthetic 数据的真实 schema。
	fixedNow := time.Date(2026, time.August, 5, 13, 0, 0, 0, time.UTC)
	sessions, createError := NewSessionCommands(connection, func() time.Time { return fixedNow })
	if createError != nil {
		t.Fatalf("session commands failed to initialize: %v", createError)
	}

	firstDevice, firstStartError := sessions.Start(context.Background(), "A-syntheticowner01", "synthetic-browser-one")
	if firstStartError != nil {
		t.Fatalf("first synthetic device failed to start: %v", firstStartError)
	}
	secondDevice, secondStartError := sessions.Start(context.Background(), "A-syntheticowner01", "synthetic-browser-two")
	if secondStartError != nil {
		t.Fatalf("second synthetic device failed to start: %v", secondStartError)
	}

	changeError := sessions.ChangePassword(
		context.Background(), "A-syntheticowner01",
		"CareerPathDesk-Test-Only!", "CareerPathDesk-Synthetic-Changed-2026!", // 当前密码只对应本测试 seed。
	)
	if changeError != nil {
		t.Fatalf("synthetic password change failed: %v", changeError)
	}
	_, firstRefreshError := sessions.Rotate(context.Background(), firstDevice.SessionID, firstDevice.RefreshToken)
	if !errors.Is(firstRefreshError, ErrInvalidRefreshSession) { // 第一台设备必须在改密事务提交时撤销。
		t.Fatalf("expected first device revocation, got %v", firstRefreshError)
	}
	_, secondRefreshError := sessions.Rotate(context.Background(), secondDevice.SessionID, secondDevice.RefreshToken)
	if !errors.Is(secondRefreshError, ErrInvalidRefreshSession) { // 第二台独立 family 也必须同时撤销。
		t.Fatalf("expected second device revocation, got %v", secondRefreshError)
	}

	oldPasswordError := sessions.ChangePassword(
		context.Background(), "A-syntheticowner01",
		"CareerPathDesk-Test-Only!", "CareerPathDesk-Synthetic-Next-2026!", // 当前密码只对应本测试 seed。
	)
	if !errors.Is(oldPasswordError, ErrInvalidCredentials) { // 已替换的密码不能再次授权安全动作。
		t.Fatalf("expected old password rejection, got %v", oldPasswordError)
	}
	newPasswordError := sessions.ChangePassword(
		context.Background(), "A-syntheticowner01",
		"CareerPathDesk-Synthetic-Changed-2026!", "CareerPathDesk-Synthetic-Next-2026!",
	)
	if newPasswordError != nil { // 新密码必须成为后续认证的唯一有效凭据。
		t.Fatalf("changed synthetic password was not active: %v", newPasswordError)
	}
}

// --- 停用账号首次刷新时，全部既有设备一起撤销 ---
func TestDisabledAccountRefreshRevokesEveryAccountSession(t *testing.T) {
	connection := openSessionTestDatabase(t) // 使用独立 synthetic schema，停用动作不会影响其他测试。
	fixedNow := time.Date(2026, time.August, 5, 14, 0, 0, 0, time.UTC)
	sessions, createError := NewSessionCommands(connection, func() time.Time { return fixedNow })
	if createError != nil {
		t.Fatalf("session commands failed to initialize: %v", createError)
	}

	firstDevice, firstStartError := sessions.Start(context.Background(), "A-syntheticstaff01", "synthetic-browser-one")
	if firstStartError != nil {
		t.Fatalf("first synthetic device failed to start: %v", firstStartError)
	}
	secondDevice, secondStartError := sessions.Start(context.Background(), "A-syntheticstaff01", "synthetic-browser-two")
	if secondStartError != nil {
		t.Fatalf("second synthetic device failed to start: %v", secondStartError)
	}
	if _, disableError := connection.Exec(context.Background(), "UPDATE accounts SET state = 'disabled' WHERE id = $1", "A-syntheticstaff01"); disableError != nil { // 只建立未来账号管理命令会产生的停用前置事实。
		t.Fatal("synthetic account disable setup failed")
	}

	_, disabledRefreshError := sessions.Rotate(context.Background(), firstDevice.SessionID, firstDevice.RefreshToken)
	if !errors.Is(disabledRefreshError, ErrAccountDisabled) { // 首次持有正确秘密的设备收到明确停用反馈。
		t.Fatalf("expected ErrAccountDisabled, got %v", disabledRefreshError)
	}
	_, otherDeviceError := sessions.Rotate(context.Background(), secondDevice.SessionID, secondDevice.RefreshToken)
	if !errors.Is(otherDeviceError, ErrInvalidRefreshSession) { // 另一独立 family 已被前一次安全事务同步撤销。
		t.Fatalf("expected other disabled account device to be revoked, got %v", otherDeviceError)
	}
}

// --- 未知用户名与错误密码承担可比的验证工作 ---
func TestLoginUnknownUsernameDoesNotCreateAUserEnumerationTimingShortcut(t *testing.T) {
	connection := openSessionTestDatabase(t) // 使用同一隔离 schema 比较两个公开登录失败路径。
	sessions, sessionError := NewSessionCommands(connection, func() time.Time { return time.Date(2026, time.August, 5, 16, 30, 0, 0, time.UTC) })
	if sessionError != nil {
		t.Fatalf("session commands failed to initialize: %v", sessionError)
	}

	wrongPasswordStartedAt := time.Now() // 已知账号的错误密码必须执行一次受限 Argon2id 验证。
	_, wrongPasswordError := sessions.Login(context.Background(), "synthetic-owner", "Wrong-Synthetic-Password-2026!", "Synthetic Browser")
	wrongPasswordDuration := time.Since(wrongPasswordStartedAt)
	unknownUsernameStartedAt := time.Now() // 未知账号不得在数据库查询后立即返回。
	_, unknownUsernameError := sessions.Login(context.Background(), "unknown-synthetic-account", "Wrong-Synthetic-Password-2026!", "Synthetic Browser")
	unknownUsernameDuration := time.Since(unknownUsernameStartedAt)

	if !errors.Is(wrongPasswordError, ErrInvalidCredentials) || !errors.Is(unknownUsernameError, ErrInvalidCredentials) { // 两条路径共享同一公开失败分类。
		t.Fatal("login failures exposed whether the username exists")
	}
	if unknownUsernameDuration*4 < wrongPasswordDuration { // 允许宿主抖动，但拒绝跳过高成本验证的数量级捷径。
		t.Fatal("unknown username skipped comparable password verification work")
	}
}

// --- 打开 Foundation 已迁移、已 seed 的随机测试 schema ---
func openSessionTestDatabase(t *testing.T) *pgx.Conn {
	t.Helper()                                                                             // 让装配失败指向调用测试。
	databaseURL := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL"))            // 地址不含密码且只能指向专用测试库。
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

	randomIdentity := make([]byte, 8) // 每个测试获得独立 64 位随机 schema 名称。
	if _, randomError := rand.Read(randomIdentity); randomError != nil {
		t.Fatal("synthetic test schema identity unavailable")
	}
	schemaName := "auth_" + hex.EncodeToString(randomIdentity)
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()
	if _, createSchemaError := connection.Exec(context.Background(), "CREATE SCHEMA "+quotedSchema); createSchemaError != nil {
		t.Fatal("synthetic auth schema creation failed")
	}
	if _, selectSchemaError := connection.Exec(context.Background(), "SET search_path TO "+quotedSchema); selectSchemaError != nil {
		t.Fatal("synthetic auth schema selection failed")
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
		t.Fatal("synthetic seed file failed to load")
	}
	if _, seedError := seed.Apply(context.Background(), connection, string(seedBytes), config.SupportedSchemaVersion, "CareerPathDesk-Test-Only!"); seedError != nil { // 只用不对应部署环境的测试凭据建立认证夹具。
		t.Fatalf("synthetic seed failed: %v", seedError)
	}

	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "SET search_path TO public")            // 先离开目标 schema。
		_, _ = connection.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") // 只删除本测试随机 schema。
		_ = connection.Close(context.Background())                                           // 最后释放测试连接。
	})
	return connection // 反馈只包含 Foundation 合成数据的隔离连接。
}
