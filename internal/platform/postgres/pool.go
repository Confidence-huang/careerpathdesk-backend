/*
PostgreSQL 运行池：为 API 提供有上限的连接复用和调用方事务边界。
池装配沿用受保护密码文件；WithinTransaction 只协调提交/回滚，不承载业务规则。
*/
package postgres

import (
	"context" // 将请求取消传给建池、探测和事务。
	"time"    // 控制空闲连接健康检查周期。

	"github.com/jackc/pgx/v5"         // 暴露命令层使用的事务接口。
	"github.com/jackc/pgx/v5/pgxpool" // 提供并发安全且有上限的 PostgreSQL 连接池。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config" // 接收已验证的运行数据库事实。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/secret" // 从 0600 普通文件读取内存秘密。
)

// Transaction 是业务命令在同一提交边界内可使用的 PostgreSQL 能力。
type Transaction = pgx.Tx

// Pool 包装 pgxpool，使事务入口保持项目固定语义。
type Pool struct {
	*pgxpool.Pool // 嵌入查询能力，连接生命周期仍由 Pool 统一拥有。
}

// --- 建立有上限的 API 数据库连接池 ---
func OpenPool(context context.Context, database config.Database) (*Pool, error) {
	password, secretError := secret.Read(database.PasswordFile) // 从受保护文件读取密码，不拼接到 URL。
	if secretError != nil {
		return nil, ErrSecretUnavailable
	}
	poolConfig, parseError := pgxpool.ParseConfig(database.URL) // 解析已经通过配置边界的无密码 URL。
	if parseError != nil {
		return nil, ErrInvalidURL
	}
	poolConfig.ConnConfig.Password = password       // 密码仅存于进程内连接配置。
	poolConfig.MinConns = 0                         // 空闲本地环境不维持不必要连接。
	poolConfig.MaxConns = 4                         // 单实例小规模服务限制数据库并发占用。
	poolConfig.HealthCheckPeriod = 30 * time.Second // 定期淘汰失效连接，不输出服务器细节。

	connectionPool, openError := pgxpool.NewWithConfig(context, poolConfig) // 创建池但不假设延迟连接代表可用。
	if openError != nil {
		return nil, ErrUnavailable
	}
	if pingError := connectionPool.Ping(context); pingError != nil { // 监听前必须完成一次真实认证和探测。
		connectionPool.Close()
		return nil, ErrUnavailable
	}
	return &Pool{Pool: connectionPool}, nil
}

// --- 在一个短事务中执行调用方命令 ---
func (pool *Pool) WithinTransaction(context context.Context, command func(Transaction) error) error {
	transaction, beginError := pool.Begin(context) // 从池中借用一个连接并建立原子边界。
	if beginError != nil {
		return beginError
	}
	defer func() { _ = transaction.Rollback(context) }() // 任何提前返回都回滚；提交后为空操作。

	if commandError := command(transaction); commandError != nil { // 命令失败保留原始稳定业务错误。
		return commandError
	}
	return transaction.Commit(context) // 只有命令完整成功才提交全部事实。
}
