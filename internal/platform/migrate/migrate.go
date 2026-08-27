/*
PostgreSQL migration 指令：按版本顺序把显式 SQL 与 checksum 账本放在同一短事务。
重复运行相同 migration 安全跳过，版本相同但内容变化立即失败，不进行隐式修复。
调用示例：migrate.Apply(context, connection, migrations)。
*/
package migrate

import (
	"context"       // 把取消和超时传递到每一个 PostgreSQL 操作。
	"crypto/sha256" // 为 migration SQL 生成稳定内容身份。
	"encoding/hex"  // 将 checksum 转成可审查的固定长度文本。
	"errors"        // 区分未应用版本与真实数据库错误。
	"fmt"           // 为错误增加 migration 版本上下文，不复制 SQL 或秘密。

	"github.com/jackc/pgx/v5" // 提供 PostgreSQL 原生连接与事务边界。
)

var ErrChecksumMismatch = errors.New("migration checksum mismatch")                         // 标识已应用版本被事后改写。
var ErrMigrationOrder = errors.New("migrations must be strictly ordered")                   // 标识调用方提交了倒序或重复版本。
var ErrUnknownAppliedVersion = errors.New("database contains an unknown migration version") // 标识数据库历史不属于本 runner 的完整声明。

// Migration 是一个具有不可变版本身份的显式 schema 变化。
type Migration struct {
	Version int64  // Version 决定全局应用顺序且永不复用。
	Name    string // Name 提供不含业务数据的人工审查说明。
	SQL     string // SQL 是必须与账本同一事务提交的 schema 指令。
}

// --- 按顺序应用全部 migration ---
func Apply(context context.Context, connection *pgx.Conn, migrations []Migration) error {
	if orderError := validateOrder(migrations); orderError != nil { // 在建立事务前拒绝倒序、重复或无效版本。
		return orderError
	}
	declaredVersions := make(map[int64]struct{}, len(migrations)) // 固定本次 runner 完整声明的版本集合。
	for _, migration := range migrations {                        // 只从已通过严格顺序验证的输入建立集合。
		declaredVersions[migration.Version] = struct{}{}
	}

	for _, migration := range migrations { // 保持调用方提供的已审查顺序，不在运行时猜测排序。
		if applyError := applyOne(context, connection, migration, declaredVersions); applyError != nil { // 任一版本失败即停止后续 schema 变化。
			return fmt.Errorf("apply migration version %d: %w", migration.Version, applyError)
		}
	}

	return nil // 全部版本已经应用或被同 checksum 安全跳过。
}

// --- 验证 migration 版本严格递增 ---
func validateOrder(migrations []Migration) error {
	previousVersion := int64(0)            // migration 从正整数开始，零代表尚未读取任何版本。
	for _, migration := range migrations { // 顺序检查全部输入，不触碰数据库。
		if migration.Version <= previousVersion { // 零、负数、重复和倒序都不能形成可信账本。
			return ErrMigrationOrder
		}
		previousVersion = migration.Version // 保存当前版本供下一项比较。
	}

	return nil // 全部版本严格递增，可以进入事务阶段。
}

// --- 在一个事务内应用一个 migration ---
func applyOne(context context.Context, connection *pgx.Conn, migration Migration, declaredVersions map[int64]struct{}) error {
	transaction, beginError := connection.Begin(context) // 为 schema、账本和并发锁建立共同提交边界。
	if beginError != nil {                               // 无法建立事务时不允许执行任何 migration SQL。
		return beginError
	}
	defer func() { _ = transaction.Rollback(context) }() // 提前返回时回滚；提交后 Rollback 是安全空操作。

	if ledgerError := ensureLedger(context, transaction); ledgerError != nil { // 首次运行也在当前 migration 事务创建账本。
		return ledgerError
	}
	if historyError := rejectUnknownAppliedVersions(context, transaction, declaredVersions); historyError != nil { // 锁内证明数据库历史属于完整声明。
		return historyError
	}
	existingChecksum, lookupError := getAppliedChecksum(context, transaction, migration.Version) // 在排他锁下读取版本事实。
	if lookupError != nil {                                                                      // 账本读取未知时失败关闭。
		return lookupError
	}
	wantedChecksum := checksum(migration.SQL) // 只对将执行的 SQL 内容生成身份。
	if existingChecksum != "" {               // 已应用版本只能相同跳过或明确冲突。
		if existingChecksum != wantedChecksum {
			return ErrChecksumMismatch
		}
		return transaction.Commit(context)
	}

	if _, executeError := transaction.Exec(context, migration.SQL); executeError != nil { // 执行显式 SQL，不输出失败正文。
		return executeError
	}
	_, insertError := transaction.Exec(context, "INSERT INTO schema_migrations(version, name, checksum) VALUES ($1, $2, $3)", migration.Version, migration.Name, wantedChecksum) // 与 schema 同时记录版本事实。
	if insertError != nil {                                                                                                                                                      // 账本失败时 schema 必须一并回滚。
		return insertError
	}

	return transaction.Commit(context) // 只在 schema 与账本都成功后反馈完成。
}

// --- 拒绝数据库账本中 runner 没有声明的历史 ---
func rejectUnknownAppliedVersions(context context.Context, transaction pgx.Tx, declaredVersions map[int64]struct{}) error {
	rows, queryError := transaction.Query(context, "SELECT version FROM schema_migrations ORDER BY version") // 在排他锁持有期间读取全部版本身份。
	if queryError != nil {                                                                                   // 账本不可读时不继续 schema 变化。
		return queryError
	}
	defer rows.Close() // 无论发现未知版本或读完都释放结果集。

	for rows.Next() { // 逐个核对稳定整数身份，不读取 migration 名称或 SQL。
		var appliedVersion int64
		if scanError := rows.Scan(&appliedVersion); scanError != nil { // 未知数据类型或协议错误立即失败。
			return scanError
		}
		if _, isDeclared := declaredVersions[appliedVersion]; !isDeclared { // 数据库多出的版本禁止被静默跳过。
			return ErrUnknownAppliedVersion
		}
	}
	return rows.Err() // 反馈迭代阶段的真实数据库错误。
}

// --- 建立并锁定 migration 账本 ---
func ensureLedger(context context.Context, transaction pgx.Tx) error {
	const createLedger = `CREATE TABLE IF NOT EXISTS schema_migrations (
        version bigint PRIMARY KEY,
        name text NOT NULL,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT statement_timestamp()
    )` // 账本只保存版本元数据，不保存业务行或秘密。
	if _, createError := transaction.Exec(context, createLedger); createError != nil { // 首次 migration 在同一事务创建账本。
		return createError
	}
	_, lockError := transaction.Exec(context, "LOCK TABLE schema_migrations IN EXCLUSIVE MODE") // 串行化并发 migration 进程。
	return lockError                                                                            // 反馈锁结果，未知状态不继续。
}

// --- 读取已应用版本的 checksum ---
func getAppliedChecksum(context context.Context, transaction pgx.Tx, version int64) (string, error) {
	var existingChecksum string                                                                                                                // 接收账本中的固定长度内容身份。
	lookupError := transaction.QueryRow(context, "SELECT checksum FROM schema_migrations WHERE version = $1", version).Scan(&existingChecksum) // 参数化读取目标版本。
	if errors.Is(lookupError, pgx.ErrNoRows) {                                                                                                 // 未找到代表该版本尚未应用，不是数据库失败。
		return "", nil
	}
	return existingChecksum, lookupError // 反馈已应用 checksum 或真实查询错误。
}

// --- 生成 migration 内容身份 ---
func checksum(sql string) string {
	digest := sha256.Sum256([]byte(sql)) // 对完整 SQL 字节生成不可逆内容摘要。
	return hex.EncodeToString(digest[:]) // 反馈可持久化和人工比较的 64 字符文本。
}
