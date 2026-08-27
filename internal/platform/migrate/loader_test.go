/*
Migration 文件加载测试：验证仓库中编号 SQL 被转换为严格有序的公开 Migration。
测试只读取 database/migrations，不读取 v1 schema、正式库或本地秘密。
调用示例：go test ./internal/platform/migrate -count=1。
*/
package migrate

import (
	"context"       // 把产品 migration 应用到真实 PostgreSQL 测试 schema。
	"crypto/sha256" // 冻结数据库中 assessment-1 的公开十题内容身份。
	"encoding/hex"  // 将问卷摘要转换为可审查的固定十六进制文本。
	"encoding/json" // 规范化 PostgreSQL jsonb 后计算跨实现稳定摘要。
	"errors"        // 证明失败来自 PostgreSQL 完整性约束而不是语法或运行器错误。
	"os"            // 把已审查的 v2 migration 目录作为只读文件系统提供给加载入口。
	"strings"       // 核对 migration SQL 身份且证明公开问卷不含权重。
	"testing"       // 运行 Go 标准文件合同测试。

	"github.com/jackc/pgx/v5"        // 把约束断言限定到当前随机 PostgreSQL schema。
	"github.com/jackc/pgx/v5/pgconn" // 读取不含 SQL 正文的稳定完整性错误码。
)

// --- 加载严格有序的 Foundation、业务切片与团队计划 migration ---
func TestLoadReadsOrderedProductMigrations(t *testing.T) {
	migrationFiles := os.DirFS("../../../database/migrations") // 从包目录定位唯一产品 schema 来源。
	migrations, loadError := Load(migrationFiles)              // 通过公开加载入口解析全部编号 SQL。
	if loadError != nil {                                      // 文件名、版本或读取未知时失败关闭。
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if len(migrations) != 9 { // 学生协作迁移紧随隐私迁移，形成第九个已审查版本。
		t.Fatalf("expected nine ordered product migrations, got %d", len(migrations))
	}

	foundation := migrations[0]                                     // 读取调用方将交给 Apply 的公开 migration。
	if foundation.Version != 1 || foundation.Name != "foundation" { // 文件名必须稳定映射为版本和名称。
		t.Fatalf("unexpected foundation identity: version=%d name=%q", foundation.Version, foundation.Name)
	}
	if !strings.Contains(foundation.SQL, "CREATE TABLE accounts") { // 初始 schema 必须包含逐人账号核心表。
		t.Fatal("foundation migration does not define accounts")
	}
	followUpAttention := migrations[1] // 第二个版本集中承载 US4 的持久化不变量。
	if followUpAttention.Version != 2 || followUpAttention.Name != "followup_attention" {
		t.Fatalf("unexpected follow-up attention identity: version=%d name=%q", followUpAttention.Version, followUpAttention.Name)
	}
	for _, relationName := range []string{"follow_up_records", "student_status_history", "student_events", "student_attention_cases"} { // 四张关系必须来自同一个原子 migration。
		if !strings.Contains(followUpAttention.SQL, "CREATE TABLE "+relationName) {
			t.Fatalf("follow-up attention migration does not define %s", relationName)
		}
	}
	invitationAssessment := migrations[2] // 第三个版本集中承载受限能力、固定问卷和权威结果。
	if invitationAssessment.Version != 3 || invitationAssessment.Name != "invitation_assessment" {
		t.Fatalf("unexpected invitation assessment identity: version=%d name=%q", invitationAssessment.Version, invitationAssessment.Name)
	}
	for _, relationName := range []string{"assessment_questionnaires", "student_invitations", "assessments"} { // 三张关系必须由一个 migration 原子建立。
		if !strings.Contains(invitationAssessment.SQL, "CREATE TABLE "+relationName) {
			t.Fatalf("invitation assessment migration does not define %s", relationName)
		}
	}
	operations := migrations[3] // 第四个版本只建立导出确认事实和既有运营查询索引。
	if operations.Version != 4 || operations.Name != "operations" {
		t.Fatalf("unexpected operations identity: version=%d name=%q", operations.Version, operations.Name)
	}
	if !strings.Contains(operations.SQL, "CREATE TABLE export_confirmations") {
		t.Fatal("operations migration does not define export confirmations")
	}
	teamDocuments := migrations[4] // 第五个版本只建立团队文档层级和共享任务。
	if teamDocuments.Version != 5 || teamDocuments.Name != "team_documents" {
		t.Fatalf("unexpected team-document identity: version=%d name=%q", teamDocuments.Version, teamDocuments.Name)
	}
	for _, relationName := range []string{"team_documents", "team_tasks"} {
		if !strings.Contains(teamDocuments.SQL, "CREATE TABLE "+relationName) {
			t.Fatalf("team-document migration does not define %s", relationName)
		}
	}
	teamPlan := migrations[5] // 第六个版本把重复工作区收缩成工作台唯一计划。
	if teamPlan.Version != 6 || teamPlan.Name != "team_plan" {
		t.Fatalf("unexpected team-plan identity: version=%d name=%q", teamPlan.Version, teamPlan.Name)
	}
	if !strings.Contains(teamPlan.SQL, "CREATE TABLE team_plans") || !strings.Contains(teamPlan.SQL, "DROP TABLE team_tasks") || !strings.Contains(teamPlan.SQL, "DROP TABLE team_documents") {
		t.Fatal("team-plan migration does not replace the abandoned document and task relations")
	}
	accountMFA := migrations[6] // 第七个版本只保存加密因素、摘要挑战与防重放事实。
	if accountMFA.Version != 7 || accountMFA.Name != "account_mfa" {
		t.Fatalf("unexpected account-MFA identity: version=%d name=%q", accountMFA.Version, accountMFA.Name)
	}
	for _, relationName := range []string{"account_mfa", "mfa_challenges"} {
		if !strings.Contains(accountMFA.SQL, "CREATE TABLE "+relationName) {
			t.Fatalf("account-MFA migration does not define %s", relationName)
		}
	}
	privacyRetention := migrations[7] // 第八个版本只扩展隐私依据、保留时间和请求工作流。
	if privacyRetention.Version != 8 || privacyRetention.Name != "privacy_retention" {
		t.Fatalf("unexpected privacy-retention identity: version=%d name=%q", privacyRetention.Version, privacyRetention.Name)
	}
	if !strings.Contains(privacyRetention.SQL, "CREATE TABLE privacy_requests") {
		t.Fatal("privacy-retention migration does not define privacy requests")
	}
	studentCollaboration := migrations[8]
	if studentCollaboration.Version != 9 || studentCollaboration.Name != "student_collaboration" {
		t.Fatalf("unexpected student-collaboration identity: version=%d name=%q", studentCollaboration.Version, studentCollaboration.Name)
	}
	if !strings.Contains(studentCollaboration.SQL, "CREATE TABLE student_staff_assignments") || !strings.Contains(studentCollaboration.SQL, "ADD COLUMN content") {
		t.Fatal("student-collaboration migration does not define assignments and follow-up content")
	}
}

// --- schema 7 以前六版为前置，建立只保存密文或摘要的账号 MFA 事实 ---
func TestAccountMFAMigration(t *testing.T) {
	migrationFiles := os.DirFS("../../../database/migrations") // 从生产 runner 的唯一目录读取完整版本链。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil {
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if len(migrations) != 9 { // 完整产品链数量漂移时在连接数据库前失败。
		t.Fatalf("expected nine ordered product migrations, got %d", len(migrations))
	}
	accountMFA := migrations[6]
	if accountMFA.Version != 7 || accountMFA.Name != "account_mfa" {
		t.Fatalf("unexpected account MFA migration identity: version=%d name=%q", accountMFA.Version, accountMFA.Name)
	}

	connection := openTestDatabase(t) // 使用每个测试独立的 PostgreSQL schema 验证真实前滚和约束。
	if applyError := Apply(context.Background(), connection, migrations[:6]); applyError != nil {
		t.Fatalf("schema 6 predecessor migrations failed: %v", applyError)
	}
	if applyError := Apply(context.Background(), connection, migrations); applyError != nil {
		t.Fatalf("schema 6 to 7 migration failed: %v", applyError)
	}
	if replayError := Apply(context.Background(), connection, migrations); replayError != nil {
		t.Fatalf("schema 7 migration replay failed: %v", replayError)
	}

	for tableName, expectedColumns := range map[string][]string{
		"account_mfa": {
			"account_id", "encrypted_secret", "secret_nonce", "key_version", "confirmed_at",
			"last_accepted_step", "recovery_code_digests", "created_at", "updated_at",
		},
		"mfa_challenges": {
			"id", "account_id", "purpose", "secret_digest", "expires_at", "remaining_attempts",
			"consumed_at", "created_at",
		},
	} {
		rows, queryError := connection.Query(context.Background(), `
			SELECT column_name
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1
			ORDER BY ordinal_position`, tableName)
		if queryError != nil {
			t.Fatalf("%s column query failed", tableName)
		}
		var actualColumns []string
		for rows.Next() {
			var columnName string
			if scanError := rows.Scan(&columnName); scanError != nil {
				rows.Close()
				t.Fatalf("%s column scan failed", tableName)
			}
			actualColumns = append(actualColumns, columnName)
		}
		rows.Close()
		if strings.Join(actualColumns, ",") != strings.Join(expectedColumns, ",") {
			t.Fatalf("%s columns diverged: %v", tableName, actualColumns)
		}
	}
	for columnIdentity, expectedType := range map[string]string{
		"account_mfa.encrypted_secret":      "bytea",
		"account_mfa.secret_nonce":          "bytea",
		"account_mfa.recovery_code_digests": "_bytea",
		"mfa_challenges.secret_digest":      "bytea",
	} {
		identityParts := strings.SplitN(columnIdentity, ".", 2)
		var actualType string
		if queryError := connection.QueryRow(context.Background(), `
			SELECT udt_name
			FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
		`, identityParts[0], identityParts[1]).Scan(&actualType); queryError != nil || actualType != expectedType {
			t.Fatalf("%s type diverged: %q", columnIdentity, actualType)
		}
	}

	_, fixtureError := connection.Exec(context.Background(), `
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, must_change_password
		) VALUES (
			'A-syntheticmfa0001', 'synthetic-mfa-owner', 'synthetic-mfa-owner', 'Synthetic MFA Owner',
			'$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQ$c3ludGhldGljLWhhc2g', 'owner', false
		);
		INSERT INTO account_mfa (
			account_id, encrypted_secret, secret_nonce, key_version, confirmed_at,
			last_accepted_step, recovery_code_digests
		) VALUES (
			'A-syntheticmfa0001', decode(repeat('ab', 36), 'hex'), decode(repeat('cd', 12), 'hex'), 1,
			'2026-08-08T12:00:00Z', 59564160,
			ARRAY[decode(repeat('ef', 32), 'hex')]::bytea[]
		);
		INSERT INTO mfa_challenges (
			id, account_id, purpose, secret_digest, expires_at, created_at
		) VALUES (
			'MC-syntheticmfa0001', 'A-syntheticmfa0001', 'login', decode(repeat('01', 32), 'hex'),
			'2026-08-08T12:05:00Z', '2026-08-08T12:00:00Z'
		)`)
	if fixtureError != nil {
		t.Fatalf("valid account MFA facts were rejected: %v", fixtureError)
	}

	var remainingAttempts int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT remaining_attempts FROM mfa_challenges WHERE id = 'MC-syntheticmfa0001'
	`).Scan(&remainingAttempts); queryError != nil || remainingAttempts != 5 {
		t.Fatalf("challenge default attempts diverged: %d", remainingAttempts)
	}

	expectConstraintRejection(t, connection, `
		INSERT INTO account_mfa (account_id, encrypted_secret, secret_nonce, key_version)
		VALUES ('A-syntheticmfa0001', decode(repeat('02', 36), 'hex'), decode(repeat('03', 12), 'hex'), 1)
	`) // 一个账号只能拥有一组 MFA 因素。
	expectConstraintRejection(t, connection, `
		INSERT INTO account_mfa (account_id, encrypted_secret, secret_nonce, key_version)
		VALUES ('A-unknownmfa000001', decode(repeat('02', 36), 'hex'), decode(repeat('03', 12), 'hex'), 1)
	`) // 因素不能脱离账号存在。
	expectConstraintRejection(t, connection, `
		UPDATE account_mfa SET secret_nonce = decode(repeat('04', 11), 'hex')
		WHERE account_id = 'A-syntheticmfa0001'
	`) // AES-GCM nonce 必须固定为 12 字节。
	expectConstraintRejection(t, connection, `
		INSERT INTO mfa_challenges (
			id, account_id, purpose, secret_digest, expires_at, created_at
		) VALUES (
			'MC-syntheticmfa0002', 'A-syntheticmfa0001', 'password', decode(repeat('05', 32), 'hex'),
			'2026-08-08T12:04:00Z', '2026-08-08T12:00:00Z'
		)
	`) // challenge 目的不能扩大到登录、注册和恢复之外。
	expectConstraintRejection(t, connection, `
		INSERT INTO mfa_challenges (
			id, account_id, purpose, secret_digest, expires_at, created_at
		) VALUES (
			'MC-syntheticmfa0003', 'A-syntheticmfa0001', 'enroll', decode(repeat('06', 32), 'hex'),
			'2026-08-08T12:05:01Z', '2026-08-08T12:00:00Z'
		)
	`) // challenge 最长只能存活五分钟。
	expectConstraintRejection(t, connection, `
		INSERT INTO mfa_challenges (
			id, account_id, purpose, secret_digest, expires_at, remaining_attempts, created_at
		) VALUES (
			'MC-syntheticmfa0004', 'A-syntheticmfa0001', 'recovery', decode(repeat('07', 32), 'hex'),
			'2026-08-08T12:04:00Z', 6, '2026-08-08T12:00:00Z'
		)
	`) // 初始尝试预算不能超过五次。

	var plaintextColumnCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name IN ('account_mfa', 'mfa_challenges')
		  AND column_name IN ('totp_secret', 'secret', 'recovery_codes', 'challenge_secret')
	`).Scan(&plaintextColumnCount); queryError != nil || plaintextColumnCount != 0 {
		t.Fatalf("MFA schema exposed %d plaintext secret columns", plaintextColumnCount)
	}

	var indexExists bool
	if queryError := connection.QueryRow(context.Background(), `
		SELECT to_regclass('mfa_challenges_active_account_purpose_expiry_idx') IS NOT NULL
	`).Scan(&indexExists); queryError != nil || !indexExists {
		t.Fatal("active MFA challenge lookup index is missing")
	}
	var versionSevenCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM schema_migrations WHERE version = 7
	`).Scan(&versionSevenCount); queryError != nil || versionSevenCount != 1 {
		t.Fatalf("schema 7 ledger count diverged: %d", versionSevenCount)
	}
}

// --- 完整产品 migration 链建立全部当前核心关系 ---
func TestProductMigrationsCreateCoreRelations(t *testing.T) {
	connection := openTestDatabase(t)                          // 为当前版本链创建本测试唯一 PostgreSQL schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 读取仓库中唯一产品 schema 来源。
	migrations, loadError := Load(migrationFiles)              // 用正式加载入口解析文件身份和顺序。
	if loadError != nil {                                      // 文件缺失或命名未知时不运行部分 schema。
		t.Fatalf("foundation migrations failed to load: %v", loadError)
	}
	if applyError := Apply(context.Background(), connection, migrations); applyError != nil { // 用正式事务入口应用完整产品版本链。
		t.Fatalf("product migrations failed to apply: %v", applyError)
	}
	if replayError := Apply(context.Background(), connection, migrations); replayError != nil { // 同 checksum 重跑完整版本链必须安全跳过。
		t.Fatalf("product migration replay failed: %v", replayError)
	}

	relationNames := []string{ // 列出身份、学生工作与运行治理的最低核心关系。
		"staff_profiles", "accounts", "account_sessions", "students",
		"coaching_tasks", "audit_events", "idempotency_records", "follow_up_records",
		"student_status_history", "student_events", "student_attention_cases",
		"assessment_questionnaires", "student_invitations", "assessments", "export_confirmations",
		"team_plans", "account_mfa", "mfa_challenges",
	}
	for _, relationName := range relationNames { // 逐个观察 PostgreSQL 对公开 schema 的反馈。
		var exists bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NOT NULL", relationName).Scan(&exists); queryError != nil {
			t.Fatalf("core relation identity lookup failed: %v", queryError)
		}
		if !exists { // 缺少任何核心关系都代表三层骨架不完整。
			t.Fatalf("foundation relation %q is missing", relationName)
		}
	}
	for _, removedRelationName := range []string{"team_documents", "team_tasks"} { // 产品当前 schema 不再保留第二套文档树或团队任务。
		var removed bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NULL", removedRelationName).Scan(&removed); queryError != nil || !removed {
			t.Fatalf("abandoned relation %q still exists", removedRelationName)
		}
	}
}

// --- 运营 migration 只保存 digest，并拒绝矛盾账号、会话、类型和消费时间 ---
func TestOperationsMigrationEnforcesExportConfirmationFactsAndIndexes(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试使用独立随机 PostgreSQL schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 通过正式目录加载完整版本链。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil {
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if applyError := Apply(context.Background(), connection, migrations); applyError != nil {
		t.Fatalf("product migrations failed to apply: %v", applyError)
	}

	_, fixtureError := connection.Exec(context.Background(), `
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, must_change_password
		) VALUES
			('A-syntheticoperations01', 'synthetic-operations-one', 'synthetic-operations-one', 'Synthetic Operations Owner One',
			 '$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQ$c3ludGhldGljLWhhc2g', 'owner', false),
			('A-syntheticoperations02', 'synthetic-operations-two', 'synthetic-operations-two', 'Synthetic Operations Owner Two',
			 '$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQ$c3ludGhldGljLWhhc2g', 'owner', false);
		INSERT INTO account_sessions (
			id, account_id, token_family_id, refresh_digest, credential_version,
			idle_expires_at, absolute_expires_at
		) VALUES (
			'AS-syntheticoperations01', 'A-syntheticoperations01', 'RF-syntheticoperations01',
			decode(repeat('ab', 32), 'hex'), 1, '2026-08-07T00:00:00Z', '2026-08-08T00:00:00Z'
		);
		INSERT INTO export_confirmations (
			confirmation_digest, account_id, session_id, export_type, expires_at
		) VALUES (
			decode(repeat('cd', 32), 'hex'), 'A-syntheticoperations01',
			'AS-syntheticoperations01', 'students', '2026-08-06T06:00:00Z'
		);
		UPDATE export_confirmations SET used_at = '2026-08-06T05:59:59Z'
		WHERE confirmation_digest = decode(repeat('cd', 32), 'hex')`)
	if fixtureError != nil { // 合法老板会话绑定和边界前消费必须能被未来命令写入。
		t.Fatalf("valid operations schema facts were rejected: %v", fixtureError)
	}

	expectConstraintRejection(t, connection, `
		INSERT INTO export_confirmations (
			confirmation_digest, account_id, session_id, export_type, expires_at
		) VALUES (
			decode(repeat('de', 32), 'hex'), 'A-syntheticoperations02',
			'AS-syntheticoperations01', 'students', '2026-08-06T06:00:00Z'
		)`) // 一个账号不能误用另一个账号的会话创建确认。
	expectConstraintRejection(t, connection, `
		INSERT INTO export_confirmations (
			confirmation_digest, account_id, session_id, export_type, expires_at
		) VALUES (
			decode(repeat('ef', 32), 'hex'), 'A-syntheticoperations01',
			'AS-syntheticoperations01', 'all-data', '2026-08-06T06:00:00Z'
		)`) // 未注册导出类型不能扩大授权数据集合。
	expectConstraintRejection(t, connection, `
		INSERT INTO export_confirmations (
			confirmation_digest, account_id, session_id, export_type, expires_at
		) VALUES (
			decode(repeat('01', 31), 'hex'), 'A-syntheticoperations01',
			'AS-syntheticoperations01', 'students', '2026-08-06T06:00:00Z'
		)`) // 非 SHA-256 长度不能伪装成一次确认身份。
	expectConstraintRejection(t, connection, `
		UPDATE export_confirmations SET used_at = expires_at
		WHERE confirmation_digest = decode(repeat('cd', 32), 'hex')
	`) // 到达精确过期边界后不能记录一次成功消费。

	var columnCount, protectedColumnCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*), count(*) FILTER (
			WHERE column_name IN ('confirmation_digest', 'account_id', 'session_id', 'export_type', 'expires_at', 'used_at')
		)
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'export_confirmations'
	`).Scan(&columnCount, &protectedColumnCount); queryError != nil {
		t.Fatal("operations confirmation column query failed")
	}
	if columnCount != 6 || protectedColumnCount != 6 { // 原始确认或额外正文列不得进入持久化 schema。
		t.Fatalf("export confirmation column set is not digest-only: total=%d protected=%d", columnCount, protectedColumnCount)
	}

	indexNames := []string{ // 这些固定索引分别服务确认维护、活动会话核对和审计游标过滤。
		"export_confirmations_active_session_idx",
		"export_confirmations_expiry_idx",
		"export_confirmations_used_idx",
		"audit_events_action_object_cursor_idx",
		"audit_events_object_cursor_idx",
	}
	for _, indexName := range indexNames {
		var exists bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NOT NULL", indexName).Scan(&exists); queryError != nil {
			t.Fatal("operations index identity query failed")
		}
		if !exists {
			t.Fatalf("operations index %q is missing", indexName)
		}
	}
}

// --- US5 关系只接受固定问卷、完整能力生命周期和十题结果 ---
func TestInvitationAssessmentMigrationEnforcesFactCoherence(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试使用独立随机 PostgreSQL schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 通过正式目录加载完整版本链。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil {
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if applyError := Apply(context.Background(), connection, migrations); applyError != nil {
		t.Fatalf("product migrations failed to apply: %v", applyError)
	}

	var questionnaireCount int // migration 必须原子注册唯一活动的 assessment-1 十题定义。
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*)
		FROM assessment_questionnaires
		WHERE version = 'assessment-1'
		  AND is_active
		  AND jsonb_array_length(public_questions) = 10
		  AND scoring_definition ? 'option_weights'
		  AND scoring_definition ? 'result_material'
	`).Scan(&questionnaireCount); queryError != nil {
		t.Fatal("synthetic questionnaire registry query failed")
	}
	if questionnaireCount != 1 {
		t.Fatalf("assessment-1 registry count diverged: %d", questionnaireCount)
	}
	var publicQuestionsBody []byte // 只读取公开题目列，不查询私有评分定义正文。
	if queryError := connection.QueryRow(context.Background(), `
		SELECT public_questions FROM assessment_questionnaires WHERE version = 'assessment-1'
	`).Scan(&publicQuestionsBody); queryError != nil {
		t.Fatal("synthetic public questionnaire query failed")
	}
	if strings.Contains(string(publicQuestionsBody), `"weights"`) { // 公开列必须与私有权重形成数据库级清晰分离。
		t.Fatal("public questionnaire stored private scoring weights")
	}
	var publicQuestions any
	if decodeError := json.Unmarshal(publicQuestionsBody, &publicQuestions); decodeError != nil {
		t.Fatal("synthetic public questionnaire JSON was invalid")
	}
	canonicalQuestionnaire, encodeError := json.Marshal(map[string]any{
		"questionnaire_version": "assessment-1",  // 与表单公开合同使用同一个版本字段名。
		"questions":             publicQuestions, // PostgreSQL jsonb 解码后由 Go 固定键顺序。
	})
	if encodeError != nil {
		t.Fatal("synthetic public questionnaire could not be normalized")
	}
	questionnaireDigest := sha256.Sum256(canonicalQuestionnaire)
	if hex.EncodeToString(questionnaireDigest[:]) != "5aac5add9e8ec4b045b329a29e9779d9695e0f26d5824619538774b9203d83be" {
		t.Fatal("assessment-1 public registry digest diverged")
	}

	_, fixtureError := connection.Exec(context.Background(), `
		INSERT INTO staff_profiles (id, display_name) VALUES ('T-syntheticmigration02', 'Synthetic Invitation Staff');
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, staff_profile_id, must_change_password
		) VALUES (
			'A-syntheticmigration02', 'synthetic-invitation', 'synthetic-invitation', 'Synthetic Invitation Staff',
			'$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQ$c3ludGhldGljLWhhc2g',
			'staff', 'T-syntheticmigration02', false
		);
		INSERT INTO students (
			id, name, service_stage, job_search_stage, owner_staff_id, source_kind, created_by, updated_by,
			processing_basis, privacy_notice_version, privacy_notice_delivered_at
		) VALUES (
			'S-syntheticmigration02', 'Synthetic Invitation Student', '服务中', '简历准备',
			'T-syntheticmigration02', 'staff', 'A-syntheticmigration02', 'A-syntheticmigration02',
			'service_contract', 'privacy-notice-v1', '2026-08-06T00:00:00Z'
		);
		INSERT INTO student_invitations (
			id, student_id, issued_by_account_id, assessment_version, student_version, state,
			invite_digest, expires_at
		) VALUES (
			'IV-syntheticmigration01', 'S-syntheticmigration02', 'A-syntheticmigration02', 'assessment-1', 1, 'pending',
			decode(repeat('ab', 32), 'hex'), '2026-08-07T00:00:00Z'
		);
		UPDATE student_invitations
		SET state = 'exchanged', invite_digest = NULL, exchanged_at = '2026-08-06T01:00:00Z',
			restricted_session_id = 'IS-syntheticmigration01',
			restricted_session_digest = decode(repeat('cd', 32), 'hex'),
			restricted_session_expires_at = '2026-08-06T03:00:00Z', updated_at = '2026-08-06T01:00:00Z'
		WHERE id = 'IV-syntheticmigration01';
		INSERT INTO assessments (
			id, student_id, questionnaire_version, answers, server_score,
			internal_recommendation, source_invitation_id, submitted_at
		) VALUES (
			'AS-syntheticmigration01', 'S-syntheticmigration02', 'assessment-1',
			'{"p1":"p1-neutral-option-a","p2":"p2-neutral-option-a","p3":"p3-neutral-option-a","p4":"p4-neutral-option-a","p5":"p5-neutral-option-a","p6":"p6-neutral-option-a","p7":"p7-neutral-option-a","p8":"p8-neutral-option-a","p9":"p9-neutral-option-a","p10":"p10-neutral-option-a"}'::jsonb,
			'{"primary_type":"direct_goal","secondary_type":"evidence_planning"}'::jsonb,
			'{"report_status":"pending_human_confirmation"}'::jsonb,
			'IV-syntheticmigration01', '2026-08-06T02:00:00Z'
		)`)
	if fixtureError != nil { // 合法邀请、能力与十题结果必须能在未来命令事务中写入。
		t.Fatalf("valid US5 schema facts were rejected: %v", fixtureError)
	}

	expectConstraintRejection(t, connection, `
		UPDATE student_invitations
		SET state = 'pending', invite_digest = decode(repeat('ef', 32), 'hex')
		WHERE id = 'IV-syntheticmigration01'
	`) // pending 邀请不能保留已经兑换的会话与时间事实。
	expectConstraintRejection(t, connection, `
		UPDATE student_invitations
		SET assessment_version = 'assessment-2'
		WHERE id = 'IV-syntheticmigration01'
	`) // 既有能力也不能被改写为未注册问卷版本。
	expectConstraintRejection(t, connection, `
		UPDATE assessments
		SET answers = '{"p1":"p1-neutral-option-a"}'::jsonb
		WHERE id = 'AS-syntheticmigration01'
	`) // 既有测评也不能被改写为少于十题的答案对象。
}

// --- US4 关系拒绝矛盾回复、历史、事件和结论事实 ---
func TestFollowUpAttentionMigrationEnforcesFactCoherence(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试使用独立随机 PostgreSQL schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 通过正式目录加载完整版本链。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil {
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if applyError := Apply(context.Background(), connection, migrations); applyError != nil {
		t.Fatalf("product migrations failed to apply: %v", applyError)
	}

	_, fixtureError := connection.Exec(context.Background(), `
		INSERT INTO staff_profiles (id, display_name) VALUES ('T-syntheticmigration01', 'Synthetic Migration Staff');
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash,
			role, staff_profile_id, must_change_password
		) VALUES (
			'A-syntheticmigration01', 'synthetic-migration', 'synthetic-migration', 'Synthetic Migration Staff',
			'$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljLXNhbHQ$c3ludGhldGljLWhhc2g',
			'staff', 'T-syntheticmigration01', false
		);
		INSERT INTO students (
			id, name, service_stage, job_search_stage, owner_staff_id, source_kind, created_by, updated_by,
			processing_basis, privacy_notice_version, privacy_notice_delivered_at
		) VALUES (
			'S-syntheticmigration01', 'Synthetic Migration Student', '待服务', '未开始',
			'T-syntheticmigration01', 'staff', 'A-syntheticmigration01', 'A-syntheticmigration01',
			'service_contract', 'privacy-notice-v1', '2026-08-05T00:00:00Z'
		);
		INSERT INTO follow_up_records (
			id, student_id, contacted_at, channel, valid_contact, reply_required,
			reply_thread_id, overdue_occurrence, created_by, updated_by
		) VALUES (
			'FU-syntheticmigration01', 'S-syntheticmigration01', '2026-08-05T00:00:00Z', 'synthetic', true, true,
			'RT-syntheticmigration01', false, 'A-syntheticmigration01', 'A-syntheticmigration01'
		);
		INSERT INTO student_status_history (
			id, student_id, dimension, from_value, to_value, reason, base_student_version,
			student_version, changed_by_account_id
		) VALUES (
			'SH-syntheticmigration01', 'S-syntheticmigration01', 'service', '待服务', '服务中',
			'Synthetic migration status reason', 1, 2, 'A-syntheticmigration01'
		);
		INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload)
		VALUES (
			'EV-syntheticmigration01', 'S-syntheticmigration01', 'status.changed', 'account',
			'A-syntheticmigration01', '{"dimension":"service"}'::jsonb
		);
		INSERT INTO student_attention_cases (
			id, student_id, rule_code, trigger_codes, evidence, evidence_fingerprint,
			first_triggered_at, last_triggered_at
		) VALUES (
			'AC-syntheticmigration01', 'S-syntheticmigration01', 'complaint', ARRAY['complaint'],
			'[{"object_type":"student_event","object_id":"EV-syntheticmigration01"}]'::jsonb,
			decode(repeat('ab', 32), 'hex'), '2026-08-05T00:00:00Z', '2026-08-05T00:00:00Z'
		)`)
	if fixtureError != nil { // 合法事实链必须能被后续命令在一个事务中写入。
		t.Fatalf("valid US4 schema facts were rejected: %v", fixtureError)
	}

	expectConstraintRejection(t, connection, `
		INSERT INTO follow_up_records (
			id, student_id, contacted_at, channel, valid_contact, reply_required,
			overdue_occurrence, created_by, updated_by
		) VALUES (
			'FU-syntheticmigration02', 'S-syntheticmigration01', '2026-08-05T01:00:00Z', 'synthetic', false, true,
			false, 'A-syntheticmigration01', 'A-syntheticmigration01'
		)`) // 待回复事实必须指向一条明确线程。
	expectConstraintRejection(t, connection, `
		INSERT INTO student_status_history (
			id, student_id, dimension, from_value, to_value, reason, base_student_version,
			student_version, changed_by_account_id
		) VALUES (
			'SH-syntheticmigration02', 'S-syntheticmigration01', 'combined', '待服务', '服务中',
			'Synthetic invalid dimension', 1, 2, 'A-syntheticmigration01'
		)`) // 服务与求职维度不能被模糊合并。
	expectConstraintRejection(t, connection, `
		INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload)
		VALUES (
			'EV-syntheticmigration02', 'S-syntheticmigration01', 'status.changed', 'account',
			'A-syntheticmigration01', '"unsafe body"'::jsonb
		)`) // 事件 payload 只能是最小结构化对象。
	expectConstraintRejection(t, connection, `
		INSERT INTO student_attention_cases (
			id, student_id, rule_code, trigger_codes, evidence, evidence_fingerprint,
			first_triggered_at, last_triggered_at, status, conclusion_code, conclusion_reason
		) VALUES (
			'AC-syntheticmigration02', 'S-syntheticmigration01', 'complaint', ARRAY['complaint'],
			'[{"object_type":"student_event","object_id":"EV-syntheticmigration01"}]'::jsonb,
			decode(repeat('cd', 32), 'hex'), '2026-08-05T01:00:00Z', '2026-08-05T01:00:00Z',
			'open', 'dismiss', 'Synthetic contradictory conclusion'
		)`) // 开放事项不能伪装成已有人工结论。
	expectConstraintRejection(t, connection, `
		INSERT INTO student_attention_cases (
			id, student_id, rule_code, trigger_codes, evidence, evidence_fingerprint,
			first_triggered_at, last_triggered_at
		) VALUES (
			'AC-syntheticmigration03', 'S-syntheticmigration01', 'complaint', ARRAY['complaint'],
			'[{"object_type":"student_event","object_id":"EV-syntheticmigration01"}]'::jsonb,
			decode(repeat('ab', 32), 'hex'), '2026-08-05T02:00:00Z', '2026-08-05T02:00:00Z'
		)`) // 相同规则和证据指纹只能形成一个关注事项。
}

// --- 版本 2 任一语句失败时四张关系与账本共同回滚 ---
func TestFollowUpAttentionMigrationRollsBackAsOneVersion(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试拥有可精确清理的随机 schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 读取真实版本 2 SQL，而不是复制测试替身。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil || len(migrations) != 9 {
		t.Fatalf("product migrations unavailable for rollback test")
	}
	if applyError := Apply(context.Background(), connection, migrations[:1]); applyError != nil { // 先提交稳定 Foundation 版本。
		t.Fatalf("foundation migration failed before rollback test: %v", applyError)
	}
	brokenFollowUpAttention := migrations[1] // 保留真实版本、名称和全部结构，只在末尾注入一个确定失败点。
	brokenFollowUpAttention.SQL += "; SELECT missing_synthetic_followup_attention_function()"
	if applyError := Apply(context.Background(), connection, []Migration{migrations[0], brokenFollowUpAttention}); applyError == nil {
		t.Fatal("expected injected version 2 migration failure")
	}

	for _, relationName := range []string{"follow_up_records", "student_status_history", "student_events", "student_attention_cases"} { // 前面的 CREATE 也必须随末尾失败回滚。
		var relationIsMissing bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NULL", relationName).Scan(&relationIsMissing); queryError != nil {
			t.Fatal("rolled-back US4 relation identity query failed")
		}
		if !relationIsMissing {
			t.Fatalf("failed version 2 left relation %s", relationName)
		}
	}
	var versionTwoCount int // 账本不能宣称失败的 schema 已提交。
	if queryError := connection.QueryRow(context.Background(), "SELECT count(*) FROM schema_migrations WHERE version = 2").Scan(&versionTwoCount); queryError != nil {
		t.Fatal("rolled-back version 2 ledger query failed")
	}
	if versionTwoCount != 0 {
		t.Fatalf("failed version 2 left ledger count %d", versionTwoCount)
	}
}

// --- 版本 3 任一语句失败时邀请、问卷和测评关系整体回滚 ---
func TestInvitationAssessmentMigrationRollsBackAsOneVersion(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试拥有可精确清理的随机 schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 读取真实版本 3 SQL，而不是复制测试替身。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil || len(migrations) != 9 {
		t.Fatal("product migrations unavailable for US5 rollback test")
	}
	if applyError := Apply(context.Background(), connection, migrations[:2]); applyError != nil { // 先提交稳定的前两版。
		t.Fatalf("predecessor migrations failed before US5 rollback test: %v", applyError)
	}
	brokenInvitationAssessment := migrations[2] // 保留真实结构和静态问卷，只在末尾注入确定失败点。
	brokenInvitationAssessment.SQL += "; SELECT missing_synthetic_invitation_assessment_function()"
	if applyError := Apply(context.Background(), connection, []Migration{migrations[0], migrations[1], brokenInvitationAssessment}); applyError == nil {
		t.Fatal("expected injected version 3 migration failure")
	}

	for _, relationName := range []string{"assessment_questionnaires", "student_invitations", "assessments"} { // 前面的 ALTER/CREATE/INSERT 都必须随失败回滚。
		var relationIsMissing bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NULL", relationName).Scan(&relationIsMissing); queryError != nil {
			t.Fatal("rolled-back US5 relation identity query failed")
		}
		if !relationIsMissing {
			t.Fatalf("failed version 3 left relation %s", relationName)
		}
	}
	var profileColumnCount int // 版本 3 的学生白名单列也属于同一事务，不得部分保留。
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'students' AND column_name = 'wechat'
	`).Scan(&profileColumnCount); queryError != nil {
		t.Fatal("rolled-back US5 profile column query failed")
	}
	if profileColumnCount != 0 {
		t.Fatalf("failed version 3 left profile column count %d", profileColumnCount)
	}
	var versionThreeCount int // 账本不能宣称失败的 schema 已提交。
	if queryError := connection.QueryRow(context.Background(), "SELECT count(*) FROM schema_migrations WHERE version = 3").Scan(&versionThreeCount); queryError != nil {
		t.Fatal("rolled-back version 3 ledger query failed")
	}
	if versionThreeCount != 0 {
		t.Fatalf("failed version 3 left ledger count %d", versionThreeCount)
	}
}

// --- 版本 4 任一语句失败时确认表、运营索引和账本整体回滚 ---
func TestOperationsMigrationRollsBackAsOneVersion(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试拥有可精确清理的随机 schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 读取真实版本 4 SQL，不复制测试替身。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil || len(migrations) != 9 {
		t.Fatal("product migrations unavailable for operations rollback test")
	}
	if applyError := Apply(context.Background(), connection, migrations[:3]); applyError != nil { // 先提交稳定的前三版。
		t.Fatalf("predecessor migrations failed before operations rollback test: %v", applyError)
	}
	brokenOperations := migrations[3] // 保留真实表、约束和索引，只在末尾注入确定失败点。
	brokenOperations.SQL += "; SELECT missing_synthetic_operations_function()"
	if applyError := Apply(context.Background(), connection, []Migration{migrations[0], migrations[1], migrations[2], brokenOperations}); applyError == nil {
		t.Fatal("expected injected version 4 migration failure")
	}

	for _, relationName := range []string{"export_confirmations", "audit_events_action_object_cursor_idx", "audit_events_object_cursor_idx"} { // 表和对既有表创建的索引都必须回滚。
		var relationIsMissing bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NULL", relationName).Scan(&relationIsMissing); queryError != nil {
			t.Fatal("rolled-back operations relation identity query failed")
		}
		if !relationIsMissing {
			t.Fatalf("failed version 4 left relation %s", relationName)
		}
	}
	var accountSessionConstraintCount int // 对既有会话表增加的复合唯一约束也属于同一原子版本。
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM pg_constraint
		WHERE conrelid = 'account_sessions'::regclass AND conname = 'account_sessions_id_account_unique'
	`).Scan(&accountSessionConstraintCount); queryError != nil {
		t.Fatal("rolled-back operations constraint query failed")
	}
	if accountSessionConstraintCount != 0 {
		t.Fatalf("failed version 4 left account-session constraint count %d", accountSessionConstraintCount)
	}
	var versionFourCount int // 账本不能宣称失败的运营 schema 已提交。
	if queryError := connection.QueryRow(context.Background(), "SELECT count(*) FROM schema_migrations WHERE version = 4").Scan(&versionFourCount); queryError != nil {
		t.Fatal("rolled-back version 4 ledger query failed")
	}
	if versionFourCount != 0 {
		t.Fatalf("failed version 4 left ledger count %d", versionFourCount)
	}
}

// --- 版本 5 任一语句失败时团队文档、任务和账本整体回滚 ---
func TestTeamDocumentsMigrationRollsBackAsOneVersion(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试拥有可精确清理的随机 schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 读取真实版本 5 SQL，不复制测试替身。
	migrations, loadError := Load(migrationFiles)
	if loadError != nil || len(migrations) != 9 {
		t.Fatal("product migrations unavailable for team-document rollback test")
	}
	if applyError := Apply(context.Background(), connection, migrations[:4]); applyError != nil { // 先提交稳定的前四版。
		t.Fatalf("predecessor migrations failed before team-document rollback test: %v", applyError)
	}
	brokenTeamDocuments := migrations[4] // 保留真实表、约束和索引，只在末尾注入确定失败点。
	brokenTeamDocuments.SQL += "; SELECT missing_synthetic_team_documents_function()"
	if applyError := Apply(context.Background(), connection, append(migrations[:4], brokenTeamDocuments)); applyError == nil {
		t.Fatal("expected injected version 5 migration failure")
	}

	for _, relationName := range []string{"team_documents", "team_tasks", "team_documents_parent_order_idx", "team_tasks_document_status_due_idx"} {
		var relationIsMissing bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NULL", relationName).Scan(&relationIsMissing); queryError != nil {
			t.Fatal("rolled-back team-document relation identity query failed")
		}
		if !relationIsMissing {
			t.Fatalf("failed version 5 left relation %s", relationName)
		}
	}
	var versionFiveCount int
	if queryError := connection.QueryRow(context.Background(), "SELECT count(*) FROM schema_migrations WHERE version = 5").Scan(&versionFiveCount); queryError != nil {
		t.Fatal("rolled-back version 5 ledger query failed")
	}
	if versionFiveCount != 0 {
		t.Fatalf("failed version 5 left ledger count %d", versionFiveCount)
	}
}

// --- 版本 6 任一语句失败时收缩后的团队计划和账本整体回滚 ---
func TestTeamPlanMigrationRollsBackAsOneVersion(t *testing.T) {
	connection := openTestDatabase(t)                          // 当前测试拥有可精确清理的随机 schema。
	migrationFiles := os.DirFS("../../../database/migrations") // 读取真实版本 6 SQL，不复制测试替身。
	migrations, loadError := Load(migrationFiles)              // 版本数量异常时不能构造虚假的回滚证明。
	if loadError != nil || len(migrations) != 9 {
		t.Fatal("product migrations unavailable for team-plan rollback test")
	}
	if applyError := Apply(context.Background(), connection, migrations[:5]); applyError != nil { // 先提交包含旧工作区的前五版。
		t.Fatalf("predecessor migrations failed before team-plan rollback test: %v", applyError)
	}
	brokenTeamPlan := migrations[5] // 保留真实迁移，只在末尾注入确定失败点。
	brokenTeamPlan.SQL += "; SELECT missing_synthetic_team_plan_function()"
	if applyError := Apply(context.Background(), connection, append(migrations[:5], brokenTeamPlan)); applyError == nil {
		t.Fatal("expected injected version 6 migration failure")
	}

	for _, relationName := range []string{"team_documents", "team_tasks"} { // 事务回滚后旧关系必须仍完整存在。
		var relationExists bool
		if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass($1) IS NOT NULL", relationName).Scan(&relationExists); queryError != nil || !relationExists {
			t.Fatalf("failed version 6 did not restore relation %s", relationName)
		}
	}
	var teamPlanIsMissing bool // 新关系不能从失败事务中泄漏。
	if queryError := connection.QueryRow(context.Background(), "SELECT to_regclass('team_plans') IS NULL").Scan(&teamPlanIsMissing); queryError != nil || !teamPlanIsMissing {
		t.Fatal("failed version 6 left team_plans relation")
	}
	var versionSixCount int // 账本不能宣称失败的收缩已经提交。
	if queryError := connection.QueryRow(context.Background(), "SELECT count(*) FROM schema_migrations WHERE version = 6").Scan(&versionSixCount); queryError != nil || versionSixCount != 0 {
		t.Fatalf("failed version 6 left ledger count %d", versionSixCount)
	}
}

// --- 证明一条违反数据库不变量的 SQL 被明确拒绝 ---
func expectConstraintRejection(t *testing.T, connection *pgx.Conn, statement string) {
	t.Helper() // 失败位置指向提交矛盾事实的调用段。
	_, executeError := connection.Exec(context.Background(), statement)
	if executeError == nil {
		t.Fatal("expected PostgreSQL to reject contradictory schema facts")
	}
	var postgresError *pgconn.PgError
	if !errors.As(executeError, &postgresError) || !strings.HasPrefix(postgresError.Code, "23") { // 只接受约束类 SQLSTATE，语法或连接错误不能伪装成通过。
		t.Fatalf("expected PostgreSQL integrity rejection, got a different failure")
	}
}
