/*
合成 PostgreSQL 测试入口：为业务包建立独立随机 schema、完整 migration 链和固定 Foundation seed。
该包只服务 Go 测试；它要求显式专用测试库与受保护密码文件，从不连接 v1 或正式候选库。
调用示例：connection := testsupport.OpenDatabase(t, "students")。
*/
package testsupport

import (
	"context"      // 驱动测试 schema 创建、迁移和精确清理。
	"crypto/rand"  // 为并行测试生成互不碰撞的 schema 后缀。
	"encoding/hex" // 将随机字节转换为安全 PostgreSQL 标识正文。
	"os"           // 读取显式测试配置和仓库内 migration/seed。
	"strings"      // 清理环境和密码文件的末尾换行。
	"testing"      // 把连接生命周期绑定到调用测试。

	"github.com/jackc/pgx/v5" // 使用真实 PostgreSQL 连接与安全标识引用。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"  // 使用二进制唯一支持的 schema 版本事实。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate" // 复用正式 migration 入口建立结构。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/seed"    // 复用只接受 synthetic 的 seed 入口。
)

const syntheticTestPassword = "CareerPathDesk-Test-Only!" // 测试固定凭据不对应任何已部署环境。

// --- 打开一个只含 Foundation 合成事实的随机 schema ---
func OpenDatabase(test *testing.T, prefix string) *pgx.Conn {
	test.Helper() // 装配失败归因到调用行为测试。
	databaseURL := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL"))
	passwordFile := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE"))
	if databaseURL == "" || passwordFile == "" || !validSchemaPrefix(prefix) { // 未明确测试边界时拒绝猜测默认数据库。
		test.Fatal("explicit synthetic test database configuration is required")
	}
	passwordBytes, readError := os.ReadFile(passwordFile)
	if readError != nil {
		test.Fatal("synthetic database password file unavailable")
	}
	connectionConfig, parseError := pgx.ParseConfig(databaseURL)
	if parseError != nil {
		test.Fatal("synthetic database URL is invalid")
	}
	connectionConfig.Password = strings.TrimSpace(string(passwordBytes)) // 密码只进入 pgx 配置，不进入日志或命令参数。
	connection, connectError := pgx.ConnectConfig(context.Background(), connectionConfig)
	if connectError != nil {
		test.Fatal("synthetic database connection failed")
	}

	randomIdentity := make([]byte, 8)
	if _, randomError := rand.Read(randomIdentity); randomError != nil {
		test.Fatal("synthetic schema identity unavailable")
	}
	schemaName := prefix + "_" + hex.EncodeToString(randomIdentity)
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()
	if _, createError := connection.Exec(context.Background(), "CREATE SCHEMA "+quotedSchema); createError != nil {
		test.Fatal("synthetic schema creation failed")
	}
	if _, selectError := connection.Exec(context.Background(), "SET search_path TO "+quotedSchema); selectError != nil {
		test.Fatal("synthetic schema selection failed")
	}

	migrations, loadError := migrate.Load(os.DirFS("../../database/migrations"))
	if loadError != nil {
		test.Fatalf("product migrations failed to load: %v", loadError)
	}
	if applyError := migrate.Apply(context.Background(), connection, migrations); applyError != nil {
		test.Fatalf("product migrations failed: %v", applyError)
	}
	seedBytes, seedReadError := os.ReadFile("../../database/seeds/synthetic.sql")
	if seedReadError != nil {
		test.Fatal("synthetic seed failed to load")
	}
	if _, seedError := seed.Apply(context.Background(), connection, string(seedBytes), config.SupportedSchemaVersion, syntheticTestPassword); seedError != nil {
		test.Fatalf("synthetic seed failed: %v", seedError)
	}
	if _, activateError := connection.Exec(context.Background(), `UPDATE accounts SET must_change_password = false`); activateError != nil {
		test.Fatal("synthetic account activation failed")
	}

	test.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "SET search_path TO public")
		_, _ = connection.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		_ = connection.Close(context.Background())
	})
	return connection
}

// --- 限定 schema 前缀为简单测试领域名 ---
func validSchemaPrefix(prefix string) bool {
	if len(prefix) < 2 || len(prefix) > 20 {
		return false
	}
	for _, character := range prefix {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return true
}
