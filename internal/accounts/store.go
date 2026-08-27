/*
账号 PostgreSQL 数据包：只执行账号模块私有 SQL，不决定角色、输入或 HTTP 反馈。
所有方法由 commands.go 在明确事务内调用；本文件不创建连接、不提交事务。
*/
package accounts

import (
	"context" // 把请求取消传递到每条 PostgreSQL 语句。
	"errors"  // 区分无行结果与真实依赖失败。
	"time"    // 持久化命令层提供的可信会话撤销时刻。

	"github.com/jackc/pgx/v5"        // 使用事务、行扫描和无行分类。
	"github.com/jackc/pgx/v5/pgconn" // 将约束失败收敛为稳定账号冲突。
)

type store struct {
	database transactionSource // database 可以是正式连接池或真实合成测试连接。
}

const accountProjection = `id, username_display, display_name, role, state, staff_profile_id, credential_version, must_change_password, version` // 所有账号反馈共享固定无秘密字段。

// --- 在事务内复核当前老板身份 ---
func (data *store) requireOwner(ctx context.Context, transaction pgx.Tx, actorID string) error {
	var role string
	var state string
	var mustChangePassword bool
	queryError := transaction.QueryRow(ctx, `SELECT role, state, must_change_password FROM accounts WHERE id = $1 FOR UPDATE`, actorID).Scan(&role, &state, &mustChangePassword)
	if queryError != nil || role != "owner" || state != "active" || mustChangePassword { // 缺失、停用、角色变化和首次改密共享拒绝。
		return ErrForbidden
	}
	return nil // 当前老板事实被锁定到事务结束。
}

// --- 锁定并复核本人账号仍可执行普通资料修改 ---
func (data *store) requireActiveSelf(ctx context.Context, transaction pgx.Tx, actorID string) (Account, error) {
	account, accountError := data.getAccount(ctx, transaction, actorID, true)
	if accountError != nil || account.State != "active" || account.MustChangePassword || (account.Role != "owner" && account.Role != "staff") {
		return Account{}, ErrForbidden
	}
	return account, nil
}

// --- 查找已提交的同一账号创建意图 ---
func (data *store) findCreateReplay(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, requestDigest [32]byte) (Account, bool, error) {
	var storedDigest []byte
	var resourceID *string
	queryError := transaction.QueryRow(ctx, `SELECT request_digest, resource_id FROM idempotency_records WHERE actor_scope = $1 AND action = 'account.create' AND idempotency_key = $2 FOR UPDATE`, actorID, idempotencyKey).Scan(&storedDigest, &resourceID)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return Account{}, false, nil // 首次意图继续创建。
	}
	if queryError != nil {
		return Account{}, false, ErrWriteFailed
	}
	if !equalDigest(storedDigest, requestDigest[:]) {
		return Account{}, true, ErrIdempotencyConflict
	}
	if resourceID == nil {
		return Account{}, true, ErrWriteFailed
	}
	account, accountError := data.getAccount(ctx, transaction, *resourceID, false)
	return account, true, accountError // 重试反馈第一次提交的账号。
}

// --- 为未绑定既有档案的新员工原子建立责任身份 ---
func (data *store) insertStaffProfile(ctx context.Context, transaction pgx.Tx, staffProfileID string, displayName string) error {
	result, writeError := transaction.Exec(ctx, `INSERT INTO staff_profiles (id, display_name, state, version) VALUES ($1, $2, 'active', 1)`, staffProfileID, displayName)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	if result.RowsAffected() != 1 {
		return ErrWriteFailed
	}
	return nil
}

// --- 插入已经准备完成的逐人账号 ---
func (data *store) insertAccount(ctx context.Context, transaction pgx.Tx, prepared preparedCreate) (Account, error) {
	row := transaction.QueryRow(ctx, `
		INSERT INTO accounts (id, username_normalized, username_display, display_name, password_hash, role, state, staff_profile_id, credential_version, must_change_password, version)
		SELECT $1, $2, $3, $4, $5, $6, 'active', $7, 1, true, 1
		WHERE $7::text IS NULL OR EXISTS (SELECT 1 FROM staff_profiles WHERE id = $7 AND state = 'active' FOR UPDATE)
		RETURNING `+accountProjection,
		prepared.accountID, prepared.usernameNormalized, prepared.usernameDisplay, prepared.displayName,
		prepared.passwordHash, prepared.role, prepared.staffProfileID,
	)
	account, scanError := scanAccount(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if scanError != nil {
		return Account{}, classifyWriteError(scanError)
	}
	return account, nil
}

// --- 写入固定最小账号审计 ---
func (data *store) insertAudit(ctx context.Context, transaction pgx.Tx, auditID string, actorID string, action string, accountID string, requestID string, version int64) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata) VALUES ($1, 'account', $2, $3, 'account', $4, 'success', $5, jsonb_build_object('version', $6::bigint))`, auditID, actorID, action, accountID, requestID, version)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 写入创建命令的幂等完成事实 ---
func (data *store) insertCreateIdempotency(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, requestDigest [32]byte, accountID string) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO idempotency_records (actor_scope, action, idempotency_key, request_digest, response_code, response_body, resource_id, expires_at) VALUES ($1, 'account.create', $2, $3, 201, jsonb_build_object('id', $4::text), $4, statement_timestamp() + interval '24 hours')`, actorID, idempotencyKey, requestDigest[:], accountID)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	return nil
}

// --- 按账号 ID 读取管理投影 ---
func (data *store) getAccount(ctx context.Context, transaction pgx.Tx, accountID string, lock bool) (Account, error) {
	lockClause := ""
	if lock { // 写命令锁定目标版本和当前状态。
		lockClause = " FOR UPDATE"
	}
	account, queryError := scanAccount(transaction.QueryRow(ctx, `SELECT `+accountProjection+` FROM accounts WHERE id = $1`+lockClause, accountID))
	if errors.Is(queryError, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if queryError != nil {
		return Account{}, ErrWriteFailed
	}
	return account, nil
}

// --- 列出管理页所需的全部账号投影 ---
func (data *store) listAccounts(ctx context.Context, transaction pgx.Tx) ([]Account, error) {
	rows, queryError := transaction.Query(ctx, `SELECT `+accountProjection+` FROM accounts ORDER BY created_at ASC, id ASC`)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	accounts := make([]Account, 0, 16)
	for rows.Next() {
		account, scanError := scanAccount(rows)
		if scanError != nil {
			return nil, ErrWriteFailed
		}
		accounts = append(accounts, account)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return accounts, nil
}

// --- 锁定并验证员工责任档案仍可绑定 ---
func (data *store) staffProfileActive(ctx context.Context, transaction pgx.Tx, staffProfileID string) (bool, error) {
	var state string
	queryError := transaction.QueryRow(ctx, `SELECT state FROM staff_profiles WHERE id = $1 FOR UPDATE`, staffProfileID).Scan(&state)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return false, nil
	}
	if queryError != nil {
		return false, ErrWriteFailed
	}
	return state == "active", nil
}

// --- 写入已经验证的账号版本和权限事实 ---
func (data *store) updateAccount(ctx context.Context, transaction pgx.Tx, accountID string, input UpdateInput, permissionsChanged bool) (Account, error) {
	row := transaction.QueryRow(ctx, `
		UPDATE accounts
		SET state = $2, staff_profile_id = $3,
			credential_version = credential_version + CASE WHEN $4 THEN 1 ELSE 0 END,
			version = version + 1, updated_at = statement_timestamp()
		WHERE id = $1
		RETURNING `+accountProjection, accountID, input.State, input.StaffProfileID, permissionsChanged)
	account, scanError := scanAccount(row)
	if scanError != nil {
		return Account{}, classifyWriteError(scanError)
	}
	return account, nil
}

// --- 原子更新账号显示名，员工同步更新导出使用的责任档案 ---
func (data *store) renameSelf(ctx context.Context, transaction pgx.Tx, current Account, displayName string) (Account, error) {
	if current.StaffProfileID != nil {
		profileResult, profileError := transaction.Exec(ctx, `UPDATE staff_profiles SET display_name = $2, version = version + 1, updated_at = statement_timestamp() WHERE id = $1 AND state = 'active'`, *current.StaffProfileID, displayName)
		if profileError != nil || profileResult.RowsAffected() != 1 {
			return Account{}, ErrWriteFailed
		}
	}
	updated, scanError := scanAccount(transaction.QueryRow(ctx, `
		UPDATE accounts
		SET display_name = $2, version = version + 1, updated_at = statement_timestamp()
		WHERE id = $1
		RETURNING `+accountProjection, current.ID, displayName))
	if scanError != nil {
		return Account{}, classifyWriteError(scanError)
	}
	return updated, nil
}

// --- 在账号权限变化时终止全部活动浏览器会话 ---
func (data *store) revokeActiveSessions(ctx context.Context, transaction pgx.Tx, accountID string, revokedAt time.Time, reason string) error {
	_, writeError := transaction.Exec(ctx, `UPDATE account_sessions SET revoked_at = $2, revoke_reason = $3 WHERE account_id = $1 AND revoked_at IS NULL`, accountID, revokedAt, reason)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 原子替换密码材料并推进账号凭据和管理版本 ---
func (data *store) resetPassword(ctx context.Context, transaction pgx.Tx, accountID string, passwordHash string) (Account, error) {
	row := transaction.QueryRow(ctx, `
		UPDATE accounts
		SET password_hash = $2, credential_version = credential_version + 1,
			must_change_password = true, version = version + 1, updated_at = statement_timestamp()
		WHERE id = $1
		RETURNING `+accountProjection, accountID, passwordHash)
	account, scanError := scanAccount(row)
	if scanError != nil {
		return Account{}, classifyWriteError(scanError)
	}
	if _, invalidateError := transaction.Exec(ctx, `
		UPDATE mfa_challenges SET remaining_attempts = 0
		WHERE account_id = $1 AND consumed_at IS NULL AND remaining_attempts > 0`, accountID,
	); invalidateError != nil { // 管理员重置后，任何由旧密码取得的短期 challenge 都必须同时终止。
		return Account{}, ErrWriteFailed
	}
	return account, nil
}

// --- 扫描固定无秘密账号投影 ---
func scanAccount(row pgx.Row) (Account, error) {
	account := Account{}
	scanError := row.Scan(&account.ID, &account.Username, &account.DisplayName, &account.Role, &account.State, &account.StaffProfileID, &account.CredentialVersion, &account.MustChangePassword, &account.Version)
	return account, scanError
}

// --- 将数据库约束收敛为公开账号错误 ---
func classifyWriteError(writeError error) error {
	var postgresError *pgconn.PgError
	if errors.As(writeError, &postgresError) {
		if postgresError.Code == "23505" { // 用户名、员工关联或幂等主键冲突不泄露索引名。
			return ErrConflict
		}
		if postgresError.Code == "23503" || postgresError.Code == "23514" {
			return ErrInvalidInput
		}
	}
	return ErrWriteFailed
}

// --- 比较两个固定摘要内容 ---
func equalDigest(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left { // 固定 32 字节循环不按首个差异提前返回。
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
