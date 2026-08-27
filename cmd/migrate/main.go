/*
CareerPathDesk migration 入口：从显式合成配置加载编号 SQL 并原子应用到 PostgreSQL。
该命令不 seed、不启动 HTTP、不读取 v1；当前阶段拒绝 synthetic 之外的运行模式。
调用示例：go run ./cmd/migrate --migration-dir ../database/migrations。
*/
package main

import (
	"context" // 把终端取消传递到连接和 migration 事务。
	"errors"  // 定义不包含配置内容的运行模式拒绝分类。
	"flag"    // 接收人工明确的 migration 目录，而不是猜测仓库根。
	"fmt"     // 为终端提供非敏感阶段上下文和成功计数。
	"log"     // 只记录 migration 阶段与固定错误，不输出 SQL 或数据库行。
	"os"      // 读取已授权环境配置并反馈进程退出状态。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"   // 验证数据库、运行模式和密码文件来源。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate"  // 加载并原子应用编号 SQL。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/postgres" // 建立不在 URL 中携带密码的 PostgreSQL 连接。
)

var ErrNonSyntheticRuntime = errors.New("migration command is synthetic-only") // 防止本地入口被误用于正式库。

// --- 运行显式 migration 指令 ---
func main() {
	migrationDirectory := flag.String("migration-dir", "database/migrations", "path to reviewed v2 SQL migrations") // 默认适配从仓库根运行。
	flag.Parse()                                                                                                    // 在任何连接副作用前完成参数解析。

	migrationCount, migrateError := migrateDatabase(*migrationDirectory) // 执行一次完整的连接、加载和应用主线。
	if migrateError != nil {                                             // 任何未知阶段都以非零状态失败关闭。
		log.Printf("careerpathdesk-migrate status=failed reason=%v", migrateError)
		os.Exit(1)
	}
	fmt.Printf("careerpathdesk-migrate status=ok migrations=%d runtime=synthetic\n", migrationCount) // 只反馈版本数量和已知环境。
}

// --- 连接合成数据库并应用 schema ---
func migrateDatabase(migrationDirectory string) (int, error) {
	database, configurationError := config.LoadDatabase(os.Getenv) // 在文件和数据库副作用前验证数据边界。
	if configurationError != nil {                                 // 配置错误只包含固定分类。
		return 0, configurationError
	}
	if database.RuntimeMode != "synthetic" { // 当前入口只允许明确合成环境。
		return 0, ErrNonSyntheticRuntime
	}

	connection, connectError := postgres.Connect(context.Background(), database) // 从受保护密码文件建立唯一连接。
	if connectError != nil {                                                     // 连接层已经去除 URL、密码和服务器细节。
		return 0, connectError
	}
	defer func() { _ = connection.Close(context.Background()) }() // 指令结束时释放 PostgreSQL 会话。

	migrations, loadError := migrate.Load(os.DirFS(migrationDirectory)) // 从人工指定目录读取完整编号 SQL。
	if loadError != nil {                                               // 未知文件、顺序或内容读取失败时不执行部分列表。
		return 0, loadError
	}
	if applyError := migrate.Apply(context.Background(), connection, migrations); applyError != nil { // 原子应用每个版本并验证 checksum。
		return 0, applyError
	}

	return len(migrations), nil // 反馈已审查列表数量，不输出 SQL 或数据库内容。
}
