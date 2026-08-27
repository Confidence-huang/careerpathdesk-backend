/*
PostgreSQL 连接入口：把已验证的无密码 URL 与受保护文件合成为内存连接配置。
错误只反馈固定分类，避免连接串、文件路径或数据库服务器细节进入普通日志。
调用示例：connection, connectError := postgres.Connect(context, database)。
*/
package postgres

import (
	"context" // 把启动取消和超时传递到 PostgreSQL 认证阶段。
	"errors"  // 暴露不包含配置内容的稳定失败分类。

	"github.com/jackc/pgx/v5" // 提供 PostgreSQL 原生连接配置和协议实现。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config" // 接收已经通过环境边界检查的数据库事实。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/secret" // 从 0600 普通文件读取内存秘密。
)

var ErrSecretUnavailable = errors.New("database secret unavailable") // 标识密码文件身份、权限或内容不可用。
var ErrInvalidURL = errors.New("database URL is invalid")            // 标识无密码 PostgreSQL URL 无法解析。
var ErrUnavailable = errors.New("database connection unavailable")   // 标识 PostgreSQL 认证或网络连接失败。

// --- 建立受保护的 PostgreSQL 连接 ---
func Connect(context context.Context, database config.Database) (*pgx.Conn, error) {
	password, secretError := secret.Read(database.PasswordFile) // 从 Git 外的受保护文件读取密码到内存。
	if secretError != nil {                                     // 不向调用方复制文件路径或系统细节。
		return nil, ErrSecretUnavailable
	}
	connectionConfig, parseError := pgx.ParseConfig(database.URL) // 解析已经通过边界检查的无密码 URL。
	if parseError != nil {                                        // 无效 URL 不允许回退到 libpq 宿主默认值。
		return nil, ErrInvalidURL
	}
	connectionConfig.Password = password // 只在内存配置中加入秘密，不改写 URL 或环境变量。

	connection, connectError := pgx.ConnectConfig(context, connectionConfig) // 建立调用方拥有的唯一 PostgreSQL 连接。
	if connectError != nil {                                                 // 不复制认证、网络或服务器错误细节。
		return nil, ErrUnavailable
	}
	return connection, nil // 反馈已经完成认证的连接，由调用方负责关闭。
}
