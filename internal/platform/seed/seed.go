/*
合成 Foundation 数据入口：先证明 SQL 具有唯一合成标记且不引用真实数据来源。
当前 Validate 只负责文件身份和来源边界；数据库事务会在后续行为测试中加入。
调用示例：validateError := seed.Validate(seedSQL)。
*/
package seed

import (
	"context"         // 把命令取消传给 schema 核对和 seed 事务。
	"encoding/base64" // 将合成 Argon2id salt/hash 编码为标准 PHC 字符串。
	"errors"          // 暴露不复制危险 seed 正文的固定失败分类。
	"fmt"             // 只拼装固定参数的合成 Argon2id 编码串。
	"strings"         // 规范化大小写后执行稳定来源标记检查。
	"unicode/utf8"    // 按用户可见字符核对合成初始密码长度。

	"github.com/jackc/pgx/v5"    // 使用真实 PostgreSQL 短事务写入固定合成数据。
	"golang.org/x/crypto/argon2" // 为公开合成密码生成仍符合认证格式的 Argon2id hash。
)

var ErrMissingMarker = errors.New("synthetic seed marker is required")                // 标识文件不是 CareerPathDesk 合成 seed。
var ErrForbiddenSource = errors.New("seed contains a forbidden data source")          // 标识 seed 可能引用真实、候选或外部数据。
var ErrSchemaUnavailable = errors.New("synthetic seed schema version is unavailable") // 标识目标 schema 不是本 seed 的已审查版本。
var ErrSeedWriteFailed = errors.New("synthetic seed write failed")                    // 标识事务没有完整写入固定数据包。
var ErrFixtureCountMismatch = errors.New("synthetic fixture count mismatch")          // 标识已写入身份集合与固定合同不一致。
var ErrAccountPasswordInvalid = errors.New("synthetic account password is invalid")   // 标识受保护文件中的账号密码不满足公开长度边界。

const requiredMarker = "-- CAREERPATHDESK_SYNTHETIC_SEED_V1"       // 唯一允许的 Foundation seed 文件头。
const passwordHashPlaceholder = "{{SYNTHETIC_PASSWORD_HASH}}" // SQL 中唯一允许被运行时替换的固定值。

var syntheticPasswordSalt = []byte("careerpathdesk-seed")                                                                                                                                // 固定公开 salt 让 seed 重跑产生完全相同的合成 hash。
var staffProfileIDs = []string{"T-syntheticcoach01", "T-syntheticcoach02"}                                                                                                               // 固定员工档案身份集合。
var accountIDs = []string{"A-syntheticowner01", "A-syntheticstaff01", "A-syntheticstaff02"}                                                                                              // 固定逐人账号身份集合。
var studentIDs = []string{"S-syntheticstudent01", "S-syntheticstudent02", "S-syntheticstudent03", "S-syntheticstudent04"}                                                                // 固定学生身份集合。
var assignmentIDs = []string{"SA-a89b8b2b82058e6f94c57d16f6dd28d9", "SA-974269f47b2a442e84e43297f4560b91", "SA-46148cd99a008b50a344b9110342303e", "SA-51d4c84edd4db15c7b754e5dc31709a5"} // 与迁移回填一致的固定主负责人关系集合。

var forbiddenSourceMarkers = []string{ // 这些标记代表 v1、影子库、外部导入或破坏性 SQL 边界。
	"crm.sqlite",
	"restored-candidate",
	"formal.sqlite",
	"production.env",
	"source_kind = 'migration'",
	"source_kind, 'migration'",
	"copy ",
	"dblink",
	"postgres_fdw",
	"file_fdw",
	"http://",
	"https://",
	"d:\\",
	"/home/",
	"delete from",
	"truncate ",
	"drop table",
	"alter table",
}

// --- 验证 seed 文件身份和数据来源 ---
func Validate(seedSQL string) error {
	normalizedSQL := strings.ToLower(strings.TrimSpace(seedSQL))            // 只用于静态边界判断，不改变将来执行的原 SQL。
	if !strings.HasPrefix(normalizedSQL, strings.ToLower(requiredMarker)) { // 未标记文件不能被推测为合成数据。
		return ErrMissingMarker
	}
	for _, forbiddenMarker := range forbiddenSourceMarkers { // 逐个拒绝真实路径、外部导入和破坏性动作。
		if strings.Contains(normalizedSQL, forbiddenMarker) { // 发现任一标记即停止，不反馈原始片段。
			return ErrForbiddenSource
		}
	}

	return nil // 文件只通过静态来源边界；数据库阶段仍需独立验证。
}

// Counts 是 seed 完成后对固定身份集合的最小反馈，不包含业务正文。
type Counts struct {
	StaffProfiles int // StaffProfiles 是固定员工档案数量。
	Accounts      int // Accounts 是固定逐人账号数量。
	Students      int // Students 是固定学生数量。
	Assignments   int // Assignments 是固定主负责人关系数量。
}

// --- 在一个事务内恢复固定 Foundation 合成数据 ---
func Apply(context context.Context, connection *pgx.Conn, seedSQL string, expectedSchemaVersion int64, accountPassword string) (Counts, error) {
	if validateError := Validate(seedSQL); validateError != nil { // 文件来源未知时不打开事务。
		return Counts{}, validateError
	}
	if !strings.Contains(seedSQL, passwordHashPlaceholder) { // 合成账号必须由固定 Argon2id hash 填充。
		return Counts{}, ErrSeedWriteFailed
	}
	passwordHash, passwordError := createSyntheticPasswordHash(accountPassword) // 只在 synthetic 门禁后的内存中派生账号 hash。
	if passwordError != nil {                                                   // 无效秘密不允许打开数据库事务。
		return Counts{}, passwordError
	}
	resolvedSQL := strings.ReplaceAll(seedSQL, passwordHashPlaceholder, passwordHash) // SQL 只接收不可逆 hash，不接收密码正文。

	transaction, beginError := connection.Begin(context) // schema 核对、四组写入和计数共享同一原子边界。
	if beginError != nil {
		return Counts{}, ErrSeedWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 任何提前返回都移除全部 seed 写入。

	var appliedSchemaVersion int64 // 只读取 migration 版本元数据，不读取业务行。
	versionError := transaction.QueryRow(context, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&appliedSchemaVersion)
	if versionError != nil || appliedSchemaVersion != expectedSchemaVersion { // 数据库与二进制声明不一致时禁止隐式修复。
		return Counts{}, ErrSchemaUnavailable
	}
	if _, executeError := transaction.Exec(context, resolvedSQL); executeError != nil { // 固定 SQL 任一语句失败时整体回滚。
		return Counts{}, ErrSeedWriteFailed
	}

	counts, countError := readFixtureCounts(context, transaction) // 只统计固定合成 ID 是否全部存在。
	if countError != nil {
		return Counts{}, ErrSeedWriteFailed
	}
	expectedCounts := Counts{StaffProfiles: len(staffProfileIDs), Accounts: len(accountIDs), Students: len(studentIDs), Assignments: len(assignmentIDs)}
	if counts != expectedCounts { // 缺少或重叠身份都代表 seed 没有形成完整确定性数据包。
		return Counts{}, ErrFixtureCountMismatch
	}
	if commitError := transaction.Commit(context); commitError != nil { // 只有计数合同成立后才提交。
		return Counts{}, ErrSeedWriteFailed
	}
	return counts, nil // 反馈固定计数，不反馈名称、密码 hash 或数据库行。
}

// --- 显式清空并恢复唯一 synthetic 业务基线 ---
func Reset(context context.Context, connection *pgx.Conn, seedSQL string, expectedSchemaVersion int64, accountPassword string) (Counts, error) {
	if validateError := Validate(seedSQL); validateError != nil {
		return Counts{}, validateError
	}
	if !strings.Contains(seedSQL, passwordHashPlaceholder) {
		return Counts{}, ErrSeedWriteFailed
	}
	passwordHash, passwordError := createSyntheticPasswordHash(accountPassword) // 与首次 seed 共享同一受保护密码输入。
	if passwordError != nil {
		return Counts{}, passwordError
	}
	resolvedSQL := strings.ReplaceAll(seedSQL, passwordHashPlaceholder, passwordHash)
	transaction, beginError := connection.Begin(context)
	if beginError != nil {
		return Counts{}, ErrSeedWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }()
	var appliedSchemaVersion int64
	if versionError := transaction.QueryRow(context, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&appliedSchemaVersion); versionError != nil || appliedSchemaVersion != expectedSchemaVersion {
		return Counts{}, ErrSchemaUnavailable
	}
	_, truncateError := transaction.Exec(context, `TRUNCATE TABLE
		team_plans, export_confirmations, assessments, student_invitations, student_attention_cases,
		student_events, student_status_history, follow_up_records, coaching_tasks, student_staff_assignments,
		idempotency_records, audit_events, account_sessions, students, accounts, staff_profiles
		RESTART IDENTITY CASCADE`)
	if truncateError != nil {
		return Counts{}, ErrSeedWriteFailed
	}
	if _, executeError := transaction.Exec(context, resolvedSQL); executeError != nil {
		return Counts{}, ErrSeedWriteFailed
	}
	counts, countError := readFixtureCounts(context, transaction)
	if countError != nil {
		return Counts{}, ErrSeedWriteFailed
	}
	expectedCounts := Counts{StaffProfiles: len(staffProfileIDs), Accounts: len(accountIDs), Students: len(studentIDs), Assignments: len(assignmentIDs)}
	if counts != expectedCounts {
		return Counts{}, ErrFixtureCountMismatch
	}
	if commitError := transaction.Commit(context); commitError != nil {
		return Counts{}, ErrSeedWriteFailed
	}
	return counts, nil
}

// --- 生成只用于合成账号的确定性 Argon2id hash ---
func createSyntheticPasswordHash(accountPassword string) (string, error) {
	passwordLength := utf8.RuneCountInString(accountPassword) // 与登录入口相同地按可见字符判断长度。
	if passwordLength < 6 || passwordLength > 128 {           // 空值、过短和过长秘密均拒绝生成可登录账号。
		return "", ErrAccountPasswordInvalid
	}
	passwordHash := argon2.IDKey([]byte(accountPassword), syntheticPasswordSalt, 3, 64*1024, 1, 32) // 使用正式候选参数和环境内秘密生成确定性 hash。
	saltText := base64.RawStdEncoding.EncodeToString(syntheticPasswordSalt)                         // PHC salt 不包含 padding。
	hashText := base64.RawStdEncoding.EncodeToString(passwordHash)                                  // PHC hash 不包含 padding。
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=1$%s$%s", saltText, hashText), nil             // 反馈后续认证可解析的标准编码串。
}

// --- 读取固定合成身份集合的最小计数 ---
func readFixtureCounts(context context.Context, transaction pgx.Tx) (Counts, error) {
	counts := Counts{} // 逐表填充固定身份计数，不读取任何正文列。
	queries := []struct {
		tableName  string   // tableName 只来自代码内固定白名单。
		identities []string // identities 是该表必须存在的合成 ID 集合。
		target     *int     // target 接收本表固定集合数量。
	}{
		{tableName: "staff_profiles", identities: staffProfileIDs, target: &counts.StaffProfiles},
		{tableName: "accounts", identities: accountIDs, target: &counts.Accounts},
		{tableName: "students", identities: studentIDs, target: &counts.Students},
		{tableName: "student_staff_assignments", identities: assignmentIDs, target: &counts.Assignments},
	}
	for _, fixtureQuery := range queries { // 四个固定表使用同一种参数化 ID 计数合同。
		query := "SELECT count(*) FROM " + pgx.Identifier{fixtureQuery.tableName}.Sanitize() + " WHERE id = ANY($1::text[])" // 表名来自白名单，ID 继续参数化。
		if queryError := transaction.QueryRow(context, query, fixtureQuery.identities).Scan(fixtureQuery.target); queryError != nil {
			return Counts{}, queryError
		}
	}
	return counts, nil // 反馈四个计数，调用方决定是否提交事务。
}
