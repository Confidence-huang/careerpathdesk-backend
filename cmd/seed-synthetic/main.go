/*
CareerPathDesk 合成 seed 入口：验证运行配置和 SQL 来源后，在一个 PostgreSQL 事务中恢复固定数据包。
入口只解析触发、调用 seed 指令并输出四个计数；它不读取 v1、不输出账号密码或数据库行。
调用示例：go run ./cmd/seed-synthetic --seed-file ../database/seeds/synthetic.sql。
*/
package main

import (
	"context" // 把终端取消传给 PostgreSQL 连接和 seed 事务。
	"errors"  // 定义不包含文件路径或 SQL 内容的固定读取失败。
	"flag"    // 接收人工明确的已审查 seed 文件路径。
	"fmt"     // 只输出固定档案身份和四个合成计数。
	"log"     // 失败时只记录稳定错误分类。
	"os"      // 读取已授权环境和仓库内 seed 文件。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"   // 证明 synthetic 数据库、schema 与 seed 档案身份。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/postgres" // 从受保护密码文件建立唯一 PostgreSQL 连接。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/secret"   // 从第二个 0600 文件读取合成账号初始密码。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/seed"     // 验证并原子恢复固定 Foundation 数据包。
)

var ErrSeedFileUnavailable = errors.New("synthetic seed file is unavailable")            // 文件读取失败不向日志复制宿主路径。
var ErrAccountPasswordUnavailable = errors.New("synthetic account password unavailable") // 账号秘密文件无效时保持固定反馈。

// --- 接收一次明确的合成 seed 触发 ---
func main() {
	seedFile := flag.String("seed-file", "database/seeds/synthetic.sql", "path to the reviewed synthetic seed SQL") // 默认适配从仓库根运行。
	flag.Parse()                                                                                                    // 在配置、文件和数据库副作用前完成参数解析。

	counts, seedError := seedDatabase(*seedFile) // 执行配置—文件—连接—事务完整链条。
	if seedError != nil {                        // 任何未知阶段都以非零状态失败关闭。
		log.Printf("careerpathdesk-seed status=failed reason=%v", seedError)
		os.Exit(1)
	}
	fmt.Printf(
		"careerpathdesk-seed status=ok profile=%s staff_profiles=%d accounts=%d students=%d assignments=%d\n",
		config.SyntheticFoundationProfile, counts.StaffProfiles, counts.Accounts, counts.Students, counts.Assignments,
	) // 反馈固定档案与计数，不反馈合成正文、密码 hash 或数据库行。
}

// --- 验证边界并执行一次 Foundation 合成 seed ---
func seedDatabase(seedFile string) (seed.Counts, error) {
	seedConfiguration, configurationError := config.LoadSyntheticSeed(os.Getenv) // 在读取文件和连接前证明 synthetic-only 边界。
	if configurationError != nil {
		return seed.Counts{}, configurationError
	}
	seedBytes, readError := os.ReadFile(seedFile) // 只读取调用方明确指定的仓库内 SQL 文件。
	if readError != nil {
		return seed.Counts{}, ErrSeedFileUnavailable
	}
	seedSQL := string(seedBytes)                                       // 保留已审查 SQL 的精确字节语义。
	if validateError := seed.Validate(seedSQL); validateError != nil { // 在数据库连接前拒绝真实来源和破坏性词汇。
		return seed.Counts{}, validateError
	}

	connection, connectError := postgres.Connect(context.Background(), seedConfiguration.Database) // 从受保护密码文件连接唯一合成库。
	if connectError != nil {
		return seed.Counts{}, connectError
	}
	defer func() { _ = connection.Close(context.Background()) }()                               // 指令结束释放本次单一连接。
	accountPassword, accountPasswordError := secret.Read(seedConfiguration.AccountPasswordFile) // 账号秘密只在 seed 事务前读入内存。
	if accountPasswordError != nil {                                                            // 路径、权限和正文均不进入日志。
		return seed.Counts{}, ErrAccountPasswordUnavailable
	}

	return seed.Apply(context.Background(), connection, seedSQL, seedConfiguration.ExpectedSchemaVersion, accountPassword) // 原子写入并反馈固定计数。
}
