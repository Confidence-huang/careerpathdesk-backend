/*
PostgreSQL migration 行为测试：通过真实隔离数据库验证 schema 变更和版本账本一起提交。
测试只读取忽略目录中的合成数据库密码文件，失败信息绝不打印连接串或数据库行。
调用示例：CAREERPATH_TEST_DATABASE_URL=postgres://... CAREERPATH_TEST_DATABASE_PASSWORD_FILE=... go test ./internal/platform/migrate。
*/
package migrate

import (
	"context"      // 为真实 PostgreSQL 操作提供可取消边界。
	"crypto/rand"  // 为每个测试 schema 生成不可碰撞的本轮身份。
	"encoding/hex" // 把随机身份转换为安全 PostgreSQL 标识片段。
	"errors"       // 比较公开 migration 错误分类，不依赖错误文字。
	"os"           // 读取显式测试数据库地址和忽略的密码文件路径。
	"strings"      // 去除密码文件末尾换行，不改变密码内部字符。
	"testing"      // 运行 Go 标准数据库行为测试。

	"github.com/jackc/pgx/v5" // 通过 PostgreSQL 原生协议验证真实事务行为。
)

// --- 重复应用同一 migration 只产生一个事实 ---
func TestApplyCreatesSchemaAndRecordsVersionOnce(t *testing.T) {
	connection := openTestDatabase(t) // 连接本轮独立的合成 migration 数据库。
	migration := Migration{           // 定义一个足以观察 schema 与账本的最小变更。
		Version: 1,
		Name:    "create migration probe",
		SQL:     "CREATE TABLE migration_probe (id bigint PRIMARY KEY)",
	}

	if applyError := Apply(context.Background(), connection, []Migration{migration}); applyError != nil { // 首次应用应原子创建表和版本事实。
		t.Fatalf("first migration application failed: %v", applyError)
	}
	if applyError := Apply(context.Background(), connection, []Migration{migration}); applyError != nil { // 重跑必须安全跳过相同 checksum。
		t.Fatalf("second migration application failed: %v", applyError)
	}

	var relationName string // 读取 PostgreSQL 对公开 schema 的最终反馈。
	if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass('migration_probe')::text").Scan(&relationName); queryError != nil {
		t.Fatalf("migration probe lookup failed: %v", queryError)
	}
	if relationName != "migration_probe" { // 表缺失代表 SQL 与版本账本没有共同完成。
		t.Fatalf("expected migration_probe, got %q", relationName)
	}

	var appliedCount int // 核对同一版本没有因重试重复写入。
	if queryError := connection.QueryRow(context.Background(), "SELECT count(*) FROM schema_migrations WHERE version = 1").Scan(&appliedCount); queryError != nil {
		t.Fatalf("migration ledger lookup failed: %v", queryError)
	}
	if appliedCount != 1 { // 网络重试语义要求一个 migration 只有一个已提交事实。
		t.Fatalf("expected one applied migration, got %d", appliedCount)
	}
}

// --- 已应用版本内容改变时拒绝 schema 漂移 ---
func TestApplyRejectsChecksumMismatch(t *testing.T) {
	connection := openTestDatabase(t) // 连接本轮独立的合成 migration 数据库。
	original := Migration{Version: 1, Name: "stable", SQL: "CREATE TABLE stable_probe (id bigint PRIMARY KEY)"}
	changed := Migration{Version: 1, Name: "stable", SQL: "CREATE TABLE changed_probe (id bigint PRIMARY KEY)"}

	if applyError := Apply(context.Background(), connection, []Migration{original}); applyError != nil { // 先建立可信版本账本。
		t.Fatalf("original migration failed: %v", applyError)
	}
	applyError := Apply(context.Background(), connection, []Migration{changed}) // 用同版本不同内容模拟事后改写。
	if !errors.Is(applyError, ErrChecksumMismatch) {                            // 必须反馈稳定漂移分类。
		t.Fatalf("expected ErrChecksumMismatch, got %v", applyError)
	}

	var changedRelationIsMissing bool
	if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass('changed_probe') IS NULL").Scan(&changedRelationIsMissing); queryError != nil {
		t.Fatalf("changed relation lookup failed: %v", queryError)
	}
	if !changedRelationIsMissing { // 冲突内容不得在数据库留下关系。
		t.Fatal("checksum mismatch wrote changed schema")
	}
}

// --- 数据库出现 runner 未声明版本时失败关闭 ---
func TestApplyRejectsUnknownAppliedVersion(t *testing.T) {
	connection := openTestDatabase(t) // 连接本轮独立的合成 migration 数据库。
	applied := Migration{Version: 1, Name: "known", SQL: "CREATE TABLE known_probe (id bigint PRIMARY KEY)"}
	if applyError := Apply(context.Background(), connection, []Migration{applied}); applyError != nil { // 先写入数据库已知事实。
		t.Fatalf("known migration failed: %v", applyError)
	}

	declared := Migration{Version: 2, Name: "later", SQL: "CREATE TABLE later_probe (id bigint PRIMARY KEY)"}
	applyError := Apply(context.Background(), connection, []Migration{declared}) // 故意遗漏数据库已有的版本 1。
	if !errors.Is(applyError, ErrUnknownAppliedVersion) {                        // runner 不得猜测旧版本来源。
		t.Fatalf("expected ErrUnknownAppliedVersion, got %v", applyError)
	}

	var laterRelationIsMissing bool
	if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass('later_probe') IS NULL").Scan(&laterRelationIsMissing); queryError != nil {
		t.Fatalf("later relation lookup failed: %v", queryError)
	}
	if !laterRelationIsMissing { // 未知历史存在时不得继续执行未来 migration。
		t.Fatal("unknown applied version allowed a later schema write")
	}
}

// --- migration SQL 失败时 schema 与版本账本一起回滚 ---
func TestApplyRollsBackFailedMigration(t *testing.T) {
	connection := openTestDatabase(t) // 连接本轮独立的合成 migration 数据库。
	broken := Migration{
		Version: 1,
		Name:    "broken",
		SQL:     "CREATE TABLE rollback_probe (id bigint PRIMARY KEY); SELECT missing_migration_function()",
	}

	if applyError := Apply(context.Background(), connection, []Migration{broken}); applyError == nil { // 第二条 SQL 必须使完整 migration 失败。
		t.Fatal("expected broken migration to fail")
	}

	var relationIsMissing bool
	if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass('rollback_probe') IS NULL").Scan(&relationIsMissing); queryError != nil {
		t.Fatalf("rollback relation lookup failed: %v", queryError)
	}
	if !relationIsMissing { // 前一条 CREATE 也必须跟随事务回滚。
		t.Fatal("failed migration left a partial relation")
	}
}

// --- 乱序 migration 在写数据库前被拒绝 ---
func TestApplyRejectsOutOfOrderMigrationsBeforeWriting(t *testing.T) {
	connection := openTestDatabase(t) // 复用本轮明确隔离的 migration 测试数据库。
	migrations := []Migration{        // 故意把较大版本放在较小版本之前。
		{Version: 300, Name: "wrong first", SQL: "CREATE TABLE out_of_order_probe (id bigint PRIMARY KEY)"},
		{Version: 200, Name: "wrong second", SQL: "CREATE TABLE later_probe (id bigint PRIMARY KEY)"},
	}

	applyError := Apply(context.Background(), connection, migrations) // 从公开入口提交无效序列。
	if !errors.Is(applyError, ErrMigrationOrder) {                    // 乱序必须产生稳定失败分类。
		t.Fatalf("expected ErrMigrationOrder, got %v", applyError)
	}

	var ledgerIsMissing bool // 读取关系身份，证明验证发生在创建账本之前。
	if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass('schema_migrations') IS NULL").Scan(&ledgerIsMissing); queryError != nil {
		t.Fatalf("migration ledger identity lookup failed: %v", queryError)
	}
	if !ledgerIsMissing { // 乱序输入不得留下账本或部分 schema 事实。
		t.Fatal("expected no migration ledger for out-of-order input")
	}
}

// --- schema 7 的恢复码数组只接受 SHA-256 长度摘要 ---
func TestAccountMFAMigrationRejectsNonDigestRecoveryCodes(t *testing.T) {
	connection := openTestDatabase(t)
	migrations, loadError := Load(os.DirFS("../../../database/migrations"))
	if loadError != nil {
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if applyError := Apply(context.Background(), connection, migrations); applyError != nil {
		t.Fatalf("product migrations failed to apply: %v", applyError)
	}
	if _, fixtureError := connection.Exec(context.Background(), `
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, must_change_password
		) VALUES (
			'A-syntheticmfa0002', 'synthetic-mfa-owner-two', 'synthetic-mfa-owner-two', 'Synthetic MFA Owner Two',
			'$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQ$c3ludGhldGljLWhhc2g', 'owner', false
		)`); fixtureError != nil {
		t.Fatalf("MFA account fixture failed: %v", fixtureError)
	}

	expectConstraintRejection(t, connection, `
		INSERT INTO account_mfa (
			account_id, encrypted_secret, secret_nonce, key_version, recovery_code_digests
		) VALUES (
			'A-syntheticmfa0002', decode(repeat('08', 36), 'hex'), decode(repeat('09', 12), 'hex'), 1,
			ARRAY[decode(repeat('0a', 31), 'hex')]::bytea[]
		)
	`) // 少于 32 字节的正文不能伪装成恢复码 SHA-256 digest。
}

// --- schema 8 为学生建立可证明的处理依据、告知与 180 天保留边界 ---
func TestPrivacyRetentionMigration(t *testing.T) {
	connection := openTestDatabase(t)
	migrations, loadError := Load(os.DirFS("../../../database/migrations"))
	if loadError != nil {
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if len(migrations) != 9 {
		t.Fatalf("expected nine ordered product migrations, got %d", len(migrations))
	}
	privacyRetention := migrations[7]
	if privacyRetention.Version != 8 || privacyRetention.Name != "privacy_retention" {
		t.Fatalf("unexpected privacy-retention identity: version=%d name=%q", privacyRetention.Version, privacyRetention.Name)
	}

	if applyError := Apply(context.Background(), connection, migrations[:7]); applyError != nil {
		t.Fatalf("schema 7 predecessor migrations failed: %v", applyError)
	}
	if _, fixtureError := connection.Exec(context.Background(), `
		INSERT INTO staff_profiles (id, display_name)
		VALUES ('T-syntheticprivacy1', 'Synthetic Privacy Staff');
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, staff_profile_id, must_change_password
		) VALUES (
			'A-syntheticprivacy1', 'synthetic-privacy-staff', 'synthetic-privacy-staff',
			'Synthetic Privacy Staff',
			'$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQ$c3ludGhldGljLWhhc2g',
			'staff', 'T-syntheticprivacy1', false
		);
		INSERT INTO students (
			id, name, service_stage, job_search_stage, owner_staff_id, source_kind,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			'S-syntheticprivacy1', 'Synthetic Privacy Student', '服务中', '未开始',
			'T-syntheticprivacy1', 'staff', 'A-syntheticprivacy1', 'A-syntheticprivacy1',
			'2026-08-08T00:00:00Z', '2026-08-08T00:00:00Z'
		)`); fixtureError != nil {
		t.Fatalf("privacy predecessor fixture failed: %v", fixtureError)
	}
	if applyError := Apply(context.Background(), connection, migrations); applyError != nil {
		t.Fatalf("schema 7 to 8 migration failed: %v", applyError)
	}

	var processingBasis, noticeVersion string
	var deliveredAt string
	if queryError := connection.QueryRow(context.Background(), `
		SELECT processing_basis, privacy_notice_version,
		       to_char(privacy_notice_delivered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM students WHERE id = 'S-syntheticprivacy1'
	`).Scan(&processingBasis, &noticeVersion, &deliveredAt); queryError != nil {
		t.Fatalf("synthetic privacy backfill lookup failed: %v", queryError)
	}
	if processingBasis != "service_contract" || noticeVersion != "privacy-notice-v1" || deliveredAt != "2026-08-08T00:00:00Z" {
		t.Fatalf("synthetic privacy backfill diverged: basis=%q notice=%q delivered=%q", processingBasis, noticeVersion, deliveredAt)
	}

	if _, updateError := connection.Exec(context.Background(), `
		UPDATE students
		SET closed_at = '2026-08-08T00:00:00Z', retention_due_at = '2027-02-04T00:00:00Z'
		WHERE id = 'S-syntheticprivacy1'
	`); updateError != nil {
		t.Fatalf("exact 180-day retention boundary was rejected: %v", updateError)
	}
	expectConstraintRejection(t, connection, `
		UPDATE students
		SET closed_at = '2026-08-08T00:00:00Z', retention_due_at = NULL
		WHERE id = 'S-syntheticprivacy1'
	`)
	expectConstraintRejection(t, connection, `
		UPDATE students
		SET closed_at = '2026-08-08T00:00:00Z', retention_due_at = '2027-02-03T23:59:59Z'
		WHERE id = 'S-syntheticprivacy1'
	`)
	expectConstraintRejection(t, connection, `
		UPDATE students SET processing_basis = 'marketing_interest'
		WHERE id = 'S-syntheticprivacy1'
	`)

	if _, requestError := connection.Exec(context.Background(), `
		INSERT INTO privacy_requests (
			id, student_id, request_type, status, received_by_account_id
		) VALUES (
			'PR-syntheticprivacy1', 'S-syntheticprivacy1', 'access', 'received',
			'A-syntheticprivacy1'
		)
	`); requestError != nil {
		t.Fatalf("valid privacy request was rejected: %v", requestError)
	}
	for _, invalidRequest := range []string{
		`INSERT INTO privacy_requests (id, student_id, request_type, status, received_by_account_id)
		 VALUES ('PR-syntheticprivacy2', 'S-syntheticprivacy1', 'identity_image', 'received', 'A-syntheticprivacy1')`,
		`INSERT INTO privacy_requests (id, student_id, request_type, status, received_by_account_id)
		 VALUES ('PR-syntheticprivacy3', 'S-syntheticprivacy1', 'deletion', 'queued', 'A-syntheticprivacy1')`,
	} {
		expectConstraintRejection(t, connection, invalidRequest)
	}

	var forbiddenIdentityColumnCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'privacy_requests'
		  AND column_name IN ('identity_document', 'identity_image', 'id_card', 'id_card_image', 'document_image')
	`).Scan(&forbiddenIdentityColumnCount); queryError != nil || forbiddenIdentityColumnCount != 0 {
		t.Fatalf("privacy requests exposed %d identity-image columns", forbiddenIdentityColumnCount)
	}

	var versionEightCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM schema_migrations WHERE version = 8
	`).Scan(&versionEightCount); queryError != nil || versionEightCount != 1 {
		t.Fatalf("schema 8 ledger count diverged: %d", versionEightCount)
	}
}

// --- schema 8 不为来源未确认的既有学生伪造法律处理依据 ---
func TestPrivacyRetentionMigrationRejectsUnclassifiedLegacyStudents(t *testing.T) {
	connection := openTestDatabase(t)
	migrations, loadError := Load(os.DirFS("../../../database/migrations"))
	if loadError != nil || len(migrations) != 9 {
		t.Fatal("product migrations unavailable for privacy fail-closed test")
	}
	if applyError := Apply(context.Background(), connection, migrations[:7]); applyError != nil {
		t.Fatalf("schema 7 predecessor migrations failed: %v", applyError)
	}
	if _, fixtureError := connection.Exec(context.Background(), `
		INSERT INTO students (
			id, name, service_stage, job_search_stage, source_kind, created_by, updated_by
		) VALUES (
			'S-productionlegacy01', 'Unclassified Legacy Student', '待服务', '未开始',
			'migration', 'A-legacyoperator0001', 'A-legacyoperator0001'
		)`); fixtureError != nil {
		t.Fatalf("unclassified predecessor fixture failed: %v", fixtureError)
	}

	if applyError := Apply(context.Background(), connection, migrations); applyError == nil {
		t.Fatal("privacy migration invented a processing basis for an unclassified legacy student")
	}

	var privacyColumnCount, versionEightCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'students'
		  AND column_name = 'processing_basis'
	`).Scan(&privacyColumnCount); queryError != nil || privacyColumnCount != 0 {
		t.Fatal("failed privacy migration left a partial student schema")
	}
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM schema_migrations WHERE version = 8
	`).Scan(&versionEightCount); queryError != nil || versionEightCount != 0 {
		t.Fatal("failed privacy migration recorded schema version 8")
	}
}

// --- 打开显式合成测试数据库 ---
func openTestDatabase(t *testing.T) *pgx.Conn {
	t.Helper() // 让失败位置指向调用测试，而不是连接装配细节。

	databaseURL := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL"))            // 地址不含密码，可安全由命令显式传入。
	passwordFile := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE")) // 密码只通过忽略文件路径进入测试。
	if databaseURL == "" || passwordFile == "" {                                           // 未提供真实隔离数据库时拒绝伪造通过。
		t.Fatal("explicit synthetic test database URL and password file are required")
	}

	passwordBytes, readError := os.ReadFile(passwordFile) // 从本机 0600 文件读取合成密码，不写测试日志。
	if readError != nil {                                 // 无法证明密码来源时停止数据库测试。
		t.Fatalf("synthetic password file unavailable: %v", readError)
	}
	connectionConfig, parseError := pgx.ParseConfig(databaseURL) // 解析不含秘密的 PostgreSQL 地址。
	if parseError != nil {                                       // 无效地址不允许回退到宿主默认数据库。
		t.Fatalf("synthetic database URL is invalid")
	}
	connectionConfig.Password = strings.TrimSpace(string(passwordBytes)) // 只在内存中补入密码。

	connection, connectError := pgx.ConnectConfig(context.Background(), connectionConfig) // 打开本测试唯一数据库连接。
	if connectError != nil {                                                              // 连接失败只反馈分类，不复制含密码配置。
		t.Fatalf("synthetic database connection failed")
	}

	randomIdentity := make([]byte, 8)                                    // 为本测试预留 64 位随机 schema 身份。
	if _, randomError := rand.Read(randomIdentity); randomError != nil { // 无法证明唯一性时拒绝共享 schema。
		t.Fatal("synthetic test schema identity unavailable")
	}
	schemaName := "test_" + hex.EncodeToString(randomIdentity)                                                      // 只使用十六进制构成合法且可精确删除的标识。
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()                                                           // 由 pgx 安全引用标识，不拼接用户输入。
	if _, createError := connection.Exec(context.Background(), "CREATE SCHEMA "+quotedSchema); createError != nil { // 创建本测试唯一数据边界。
		t.Fatal("synthetic test schema creation failed")
	}
	if _, searchError := connection.Exec(context.Background(), "SET search_path TO "+quotedSchema); searchError != nil { // 后续 SQL 只能落入本轮 schema。
		t.Fatal("synthetic test schema selection failed")
	}

	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "SET search_path TO public")            // 先离开目标 schema，保证精确清理可执行。
		_, _ = connection.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") // 只删除本测试随机创建的 schema。
		_ = connection.Close(context.Background())                                           // 最后释放数据库连接。
	})

	return connection // 反馈已经证明身份、数据库和随机 schema 边界的连接。
}
