/*
合成 Foundation seed 行为测试：验证真实数据来源标记在数据库连接前被拒绝。
测试只向公开 Validate 入口提交合成文本，不读取文件、秘密或数据库。
*/
package seed

import (
	"context"      // 为真实 PostgreSQL seed 事务提供可取消边界。
	"crypto/rand"  // 为每次测试 schema 生成不可碰撞身份。
	"encoding/hex" // 把随机字节转换为安全 PostgreSQL 标识片段。
	"errors"       // 比较公开失败分类，不依赖内部错误文字。
	"os"           // 读取显式测试数据库配置和仓库内合成 seed 文件。
	"reflect"      // 比较重复 seed 的公开计数反馈。
	"strings"      // 清理密码文件末尾换行，不改变密码正文。
	"testing"      // 运行 Go 标准行为测试。

	"github.com/jackc/pgx/v5" // 连接真实隔离 PostgreSQL 并创建本轮随机 schema。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"  // 使用二进制唯一支持的 schema 版本事实。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate" // 用正式 migration 入口建立完整产品 schema。
)

const syntheticTestPassword = "CareerPathDesk-Test-Only!" // 测试凭据不对应任何已部署环境或受保护访问文件。

// --- seed 文件引用 v1 正式数据库时立即拒绝 ---
func TestValidateRejectsFormalSQLiteReference(t *testing.T) {
	seedSQL := "-- CAREERPATHDESK_SYNTHETIC_SEED_V1\n-- import crm.sqlite\nINSERT INTO accounts(id) VALUES ('A-syntheticonly01');"

	validateError := Validate(seedSQL)                 // 从 seed 公开入口提交危险来源标记。
	if !errors.Is(validateError, ErrForbiddenSource) { // 拒绝必须发生在任何数据库副作用之前。
		t.Fatalf("expected ErrForbiddenSource, got %v", validateError)
	}
}

// --- seed 文件引用正式运行配置时立即拒绝 ---
func TestValidateRejectsProductionConfigurationReference(t *testing.T) {
	seedSQL := "-- CAREERPATHDESK_SYNTHETIC_SEED_V1\n-- load production.env\nINSERT INTO accounts(id) VALUES ('A-syntheticonly01');"

	validateError := Validate(seedSQL) // 提交另一个真实环境来源标记，防止门禁只认识 SQLite 文件名。
	if !errors.Is(validateError, ErrForbiddenSource) {
		t.Fatalf("expected ErrForbiddenSource, got %v", validateError)
	}
}

// --- Foundation seed 创建固定合成数据且重复执行保持相同反馈 ---
func TestApplyCreatesDeterministicFixturesAndCanRepeat(t *testing.T) {
	connection := openSeedTestDatabase(t)                                           // 连接专用测试库中的本轮随机 schema。
	migrations, loadError := migrate.Load(os.DirFS("../../../database/migrations")) // 读取正式 Foundation migration。
	if loadError != nil {                                                           // schema 来源未知时不允许测试伪造通过。
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if applyError := migrate.Apply(context.Background(), connection, migrations); applyError != nil { // 通过生产 migration 入口建立表。
		t.Fatalf("product migrations failed: %v", applyError)
	}
	seedBytes, readError := os.ReadFile("../../../database/seeds/synthetic.sql") // 读取唯一受审查的合成数据包。
	if readError != nil {                                                        // 缺失 seed 文件必须形成真实 RED，而不是跳过。
		t.Fatalf("synthetic seed file failed to load: %v", readError)
	}

	firstCounts, firstError := Apply(context.Background(), connection, string(seedBytes), config.SupportedSchemaVersion, syntheticTestPassword) // 首次写入当前 schema 的固定合成身份。
	if firstError != nil {
		t.Fatalf("first synthetic seed failed: %v", firstError)
	}
	secondCounts, secondError := Apply(context.Background(), connection, string(seedBytes), config.SupportedSchemaVersion, syntheticTestPassword) // 重跑必须只恢复同一数据包。
	if secondError != nil {
		t.Fatalf("second synthetic seed failed: %v", secondError)
	}
	expectedCounts := Counts{StaffProfiles: 2, Accounts: 3, Students: 4, Assignments: 4}
	if !reflect.DeepEqual(firstCounts, expectedCounts) || !reflect.DeepEqual(secondCounts, expectedCounts) { // 两次反馈必须完全相同。
		t.Fatalf("unexpected synthetic counts: first=%+v second=%+v", firstCounts, secondCounts)
	}
}

// --- 打开专用数据库中的本轮随机 schema ---
func openSeedTestDatabase(t *testing.T) *pgx.Conn {
	t.Helper()                                                                             // 让失败位置指向调用行为测试。
	databaseURL := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL"))            // 地址不含密码，由门禁命令明确传入。
	passwordFile := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE")) // 密码只从忽略的 0600 文件读取。
	if databaseURL == "" || passwordFile == "" {                                           // 缺少真实隔离目标时拒绝伪造通过。
		t.Fatal("explicit synthetic test database URL and password file are required")
	}
	passwordBytes, readError := os.ReadFile(passwordFile) // 读取合成数据库密码但不输出内容。
	if readError != nil {
		t.Fatal("synthetic database password file unavailable")
	}
	connectionConfig, parseError := pgx.ParseConfig(databaseURL) // 解析无密码 PostgreSQL URL。
	if parseError != nil {
		t.Fatal("synthetic database URL is invalid")
	}
	connectionConfig.Password = strings.TrimSpace(string(passwordBytes))                  // 密码只进入内存连接配置。
	connection, connectError := pgx.ConnectConfig(context.Background(), connectionConfig) // 建立本测试唯一连接。
	if connectError != nil {
		t.Fatal("synthetic database connection failed")
	}

	randomIdentity := make([]byte, 8)                                    // 为本轮 schema 预留 64 位随机身份。
	if _, randomError := rand.Read(randomIdentity); randomError != nil { // 随机源未知时不共享测试空间。
		t.Fatal("synthetic test schema identity unavailable")
	}
	schemaName := "seed_" + hex.EncodeToString(randomIdentity) // 只用十六进制构造安全标识。
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()      // 由 pgx 引用标识，禁止用户输入拼接。
	if _, createError := connection.Exec(context.Background(), "CREATE SCHEMA "+quotedSchema); createError != nil {
		t.Fatal("synthetic seed schema creation failed")
	}
	if _, selectError := connection.Exec(context.Background(), "SET search_path TO "+quotedSchema); selectError != nil {
		t.Fatal("synthetic seed schema selection failed")
	}

	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "SET search_path TO public")            // 先离开本轮 schema。
		_, _ = connection.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE") // 只删除本测试随机 schema。
		_ = connection.Close(context.Background())                                           // 最后释放本测试连接。
	})
	return connection // 反馈已隔离的真实 PostgreSQL 测试入口。
}
