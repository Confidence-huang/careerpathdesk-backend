/*
PostgreSQL 连接行为测试：验证无密码 URL 与 0600 密码文件能够建立真实合成连接。
测试只观察数据库身份，不查询或打印任何业务表、连接串或密码。
调用示例：CAREERPATH_TEST_DATABASE_URL=... CAREERPATH_TEST_DATABASE_PASSWORD_FILE=... go test ./internal/platform/postgres。
*/
package postgres

import (
	"context" // 为真实 PostgreSQL 连接和查询提供可取消边界。
	"errors"  // 用稳定合成错误触发事务回滚。
	"os"      // 读取显式合成测试地址与密码文件路径。
	"strings" // 去除测试命令输入的外部空白。
	"testing" // 运行 Go 标准数据库边界测试。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config" // 使用已经通过配置层定义的数据边界。
)

// --- 受保护密码文件建立合成数据库连接 ---
func TestConnectUsesProtectedPasswordFile(t *testing.T) {
	database := config.Database{ // 构造不含密码且明确指向 migration 测试库的连接事实。
		RuntimeMode:  "synthetic",
		URL:          strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL")),
		PasswordFile: strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE")),
	}
	if database.URL == "" || database.PasswordFile == "" { // 未提供真实隔离目标时拒绝伪造通过。
		t.Fatal("explicit synthetic test database URL and password file are required")
	}

	connection, connectError := Connect(context.Background(), database) // 通过公开入口完成秘密读取和 PostgreSQL 认证。
	if connectError != nil {                                            // 失败信息只记录公开分类。
		t.Fatalf("synthetic PostgreSQL connection failed: %v", connectError)
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) }) // 测试结束释放连接，不改变数据库内容。

	var databaseName string // 只读取非敏感数据库身份作为连接反馈。
	if queryError := connection.QueryRow(context.Background(), "SELECT current_database()").Scan(&databaseName); queryError != nil {
		t.Fatalf("synthetic PostgreSQL identity query failed: %v", queryError)
	}
	if databaseName != "careerpathdesk_synthetic" { // 公共仓库的本地测试统一连接 Docker Compose 创建的隔离合成库。
		t.Fatalf("unexpected synthetic database identity: %q", databaseName)
	}
}

// --- 连接池事务在命令失败时不保留部分 schema 写入 ---
func TestPoolWithinTransactionRollsBackCallbackFailure(t *testing.T) {
	database := syntheticTestDatabase(t) // 只连接专用 migration 测试库。
	pool, openError := OpenPool(context.Background(), database)
	if openError != nil {
		t.Fatalf("synthetic PostgreSQL pool failed: %v", openError)
	}
	t.Cleanup(pool.Close)

	const schemaName = "pool_transaction_probe" // 固定测试 schema 只保存结构且在测试末精确删除。
	if _, createError := pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE; CREATE SCHEMA "+schemaName); createError != nil {
		t.Fatal("transaction probe schema setup failed")
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schemaName+" CASCADE") })

	expectedError := errors.New("synthetic command failure")
	transactionError := pool.WithinTransaction(context.Background(), func(transaction Transaction) error {
		if _, executeError := transaction.Exec(context.Background(), "CREATE TABLE "+schemaName+".partial_write (id bigint PRIMARY KEY)"); executeError != nil {
			return executeError
		}
		return expectedError
	})
	if !errors.Is(transactionError, expectedError) {
		t.Fatalf("expected callback error, got %v", transactionError)
	}

	var relationIsMissing bool
	if queryError := pool.QueryRow(context.Background(), "SELECT to_regclass($1) IS NULL", schemaName+".partial_write").Scan(&relationIsMissing); queryError != nil {
		t.Fatal("transaction rollback lookup failed")
	}
	if !relationIsMissing {
		t.Fatal("failed callback left a partial database write")
	}
}

// --- 构造专用合成测试数据库配置 ---
func syntheticTestDatabase(t *testing.T) config.Database {
	t.Helper()
	database := config.Database{
		RuntimeMode:  "synthetic",
		URL:          strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL")),
		PasswordFile: strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE")),
	}
	if database.URL == "" || database.PasswordFile == "" {
		t.Fatal("explicit synthetic test database URL and password file are required")
	}
	return database
}
