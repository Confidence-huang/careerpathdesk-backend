/*
刷新会话命令：用数据库事务承载启动、轮换、过期与重放撤销，不把安全状态机泄漏给 HTTP 层。
原始刷新秘密只在 Start/Rotate 成功反馈中出现一次；PostgreSQL 永远只保存 SHA-256 digest。
*/
package auth

import (
	"context"         // 将请求取消传给行锁、写入和事务提交。
	"crypto/rand"     // 生成不可预测的刷新秘密。
	"crypto/sha256"   // 将刷新秘密变成固定 32 字节数据库 digest。
	"crypto/subtle"   // 以恒定时间比较调用方秘密和数据库 digest。
	"encoding/base64" // 将随机字节编码为 Cookie 安全 opaque 文本。
	"errors"          // 暴露不包含账号、会话或秘密的稳定失败分类。
	"strings"         // 去除登录名外部空白后执行 Unicode 规范化。
	"time"            // 计算统一的三十天设备会话期限。
	"unicode/utf8"    // 在截断设备摘要前验证文本边界。

	"github.com/jackc/pgx/v5"        // 提供真实 PostgreSQL 事务和未找到行分类。
	"golang.org/x/text/cases"        // 使用 Unicode case folding 形成稳定登录身份。
	"golang.org/x/text/unicode/norm" // 在大小写折叠前执行 NFKC 兼容规范化。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/identity" // 生成 AS/RF 前缀不透明身份。
)

const RefreshIdleLifetime = 30 * 24 * time.Hour                                                                                        // 小工具模式取消短闲置门槛，闲置上限与最终期限一致。
const RefreshAbsoluteLifetime = 30 * 24 * time.Hour                                                                                    // 一个设备会话最多保持三十天，之后重新验证密码。
const refreshSecretBytes = 32                                                                                                          // 256 位刷新秘密抵抗在线和离线猜测。
const maxUserAgentRunes = 240                                                                                                          // 与数据库设备摘要长度约束一致。
const unknownAccountPasswordHash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 固定非凭据 PHC 只为未知账号承担同等 Argon2id 成本。

var ErrInvalidSessionDependencies = errors.New("session dependencies are invalid") // 标识数据库或 UTC 时钟没有装配。
var ErrSessionIdentityUnavailable = errors.New("session identity is unavailable")  // 标识系统随机源无法生成 ID 或秘密。
var ErrInvalidRefreshSession = errors.New("refresh session is invalid")            // 隐藏不存在、过期、撤销和凭据变化差异。
var ErrRefreshReplay = errors.New("refresh secret replay detected")                // 标识旧轮换秘密触发了 family 撤销。
var ErrAccountDisabled = errors.New("account is disabled")                         // 标识账号停用并使全部活动会话终止。
var ErrInvalidCredentials = errors.New("credentials are invalid")                  // 隐藏账号缺失、旧密码错误和损坏 hash 差异。
var ErrSessionWriteFailed = errors.New("session write failed")                     // 标识事务未形成完整会话事实。
var ErrAuthenticationRequired = errors.New("authentication is required")           // 隐藏访问会话不存在、撤销、过期和凭据漂移差异。
var ErrSessionNotFound = errors.New("session not found")                           // 隐藏目标会话不存在、属于他人或已经终止的差异。

// transactionSource 只允许命令开启自身事务，确保安全撤销不会被错误响应意外回滚。
type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error)
}

// SessionCredential 是浏览器建立或轮换会话后得到的一次性最小凭据。
type SessionCredential struct {
	SessionID         string    // SessionID 同时绑定访问 JWT sid。
	RefreshToken      string    // RefreshToken 只反馈本次新生成的 opaque secret。
	CredentialVersion int64     // CredentialVersion 绑定账号当前凭据版本。
	IdleExpiresAt     time.Time // IdleExpiresAt 是本次活动窗口终点。
	AbsoluteExpiresAt time.Time // AbsoluteExpiresAt 是 family 不可延长的最终终点。
}

// Account 是认证 HTTP 可以反馈的最小当前账号投影，不含密码 hash 或内部时间。
type Account struct {
	ID                 string  `json:"id"`                   // ID 是后续服务端授权的逐人身份。
	Username           string  `json:"username"`             // Username 保留管理员批准的显示形式。
	DisplayName        string  `json:"display_name"`         // DisplayName 供工作台识别人，不参与登录比较。
	Role               string  `json:"role"`                 // Role 只供展示；每个命令仍从数据库重新授权。
	State              string  `json:"state"`                // State 是登录锁定时的账号状态。
	StaffProfileID     *string `json:"staff_profile_id"`     // StaffProfileID 限定员工责任范围，老板为 null。
	CredentialVersion  int64   `json:"credential_version"`   // CredentialVersion 绑定访问令牌和刷新会话。
	MustChangePassword bool    `json:"must_change_password"` // MustChangePassword 限制首次登录只能进入改密旅程。
}

// AccountSession 把登录得到的公开账号状态与一次性会话凭据组合成一个命令反馈。
type AccountSession struct {
	Account    Account           // Account 供 HTTP 构造无秘密 JSON。
	Credential SessionCredential // Credential 只供 HTTP 设置安全 Cookie。
}

// Session 是本人设备页可展示的最小会话事实，不含 refresh digest、family 或撤销原因。
type Session struct {
	ID                string    `json:"id"`                  // ID 供本人撤销明确目标设备。
	Current           bool      `json:"current"`             // Current 标识发起列表请求的访问会话。
	UserAgentSummary  string    `json:"user_agent_summary"`  // UserAgentSummary 是登录时截断的非敏感设备摘要。
	CreatedAt         time.Time `json:"created_at"`          // CreatedAt 说明该设备首次建立时间。
	LastSeenAt        time.Time `json:"last_seen_at"`        // LastSeenAt 反映最近一次成功轮换。
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"` // AbsoluteExpiresAt 是 family 不可延长的终点。
	State             string    `json:"state"`               // State 只使用 active、revoked 或 expired。
}

// SessionCommands 集中刷新会话状态机和其事务边界。
type SessionCommands struct {
	database transactionSource // database 为每个公开命令提供独立提交边界。
	now      func() time.Time  // now 由 UTC 系统时钟注入，测试可固定。
}

// sessionRecord 是轮换行锁读取的内部完整状态，不向 HTTP 响应暴露。
type sessionRecord struct {
	accountID                 string     // 账号归属用于新会话和批量撤销。
	accountUsername           string     // 轮换成功后反馈管理员批准的登录名显示形式。
	accountDisplayName        string     // 轮换成功后恢复工作台人员名称。
	accountRole               string     // 轮换成功后反馈当前角色，服务端命令仍重新授权。
	accountStaffProfileID     *string    // 员工责任范围随刷新读取最新账号事实。
	accountMustChangePassword bool       // 初始密码限制必须随刷新继续生效。
	familyID                  string     // familyID 连接完整轮换链。
	refreshDigest             []byte     // refreshDigest 是唯一持久化的秘密投影。
	credentialVersion         int64      // 会话签发时凭据版本。
	userAgentSummary          string     // 新会话继承当前设备摘要。
	idleExpiresAt             time.Time  // 当前闲置期限。
	absoluteExpiresAt         time.Time  // family 固定最终期限。
	revokedAt                 *time.Time // revokedAt 非空代表终态。
	revokeReason              *string    // revokeReason 用于识别旧轮换秘密重放。
	accountState              string     // accountState 在同一锁读取中验证。
	accountCredentialVersion  int64      // accountCredentialVersion 是最新账号事实。
}

// --- 装配一个拥有自身事务的会话命令入口 ---
func NewSessionCommands(database transactionSource, now func() time.Time) (*SessionCommands, error) {
	if database == nil || now == nil { // 缺少任一依赖都不允许推测系统默认连接或墙钟。
		return nil, ErrInvalidSessionDependencies
	}
	return &SessionCommands{database: database, now: now}, nil
}

// --- 验证逐人账号并原子建立浏览器会话 ---
func (commands *SessionCommands) Login(context context.Context, username string, password string, userAgentSummary string) (AccountSession, error) {
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 账号验证、会话写入和最终反馈共享一个提交边界。

	account := Account{}
	var passwordHash string
	normalizedUsername := cases.Fold().String(norm.NFKC.String(strings.TrimSpace(username))) // 与账号唯一键采用同一 NFKC/casefold 规则。
	queryError := transaction.QueryRow(context, `
		SELECT id, username_display, display_name, role, state, staff_profile_id,
			credential_version, must_change_password, password_hash
		FROM accounts WHERE username_normalized = $1 FOR UPDATE`, normalizedUsername,
	).Scan(
		&account.ID, &account.Username, &account.DisplayName, &account.Role, &account.State, &account.StaffProfileID,
		&account.CredentialVersion, &account.MustChangePassword, &passwordHash,
	)
	if errors.Is(queryError, pgx.ErrNoRows) { // 未知账号仍执行一次受限 Argon2id，关闭可观测的快速枚举路径。
		_ = VerifyPassword(unknownAccountPasswordHash, password)
		return AccountSession{}, ErrInvalidCredentials
	}
	if queryError != nil { // 数据库异常不能伪装成普通密码错误，否则会隐藏服务故障。
		return AccountSession{}, ErrSessionWriteFailed
	}
	if !VerifyPassword(passwordHash, password) { // 已知账号的错误密码与未知账号共享公开失败分类。
		return AccountSession{}, ErrInvalidCredentials
	}
	if account.State != "active" { // 只有持有正确密码时才反馈停用状态，避免账号枚举。
		return AccountSession{}, ErrAccountDisabled
	}

	credential, createError := insertSession(context, transaction, commands.now().UTC(), account.ID, account.CredentialVersion, userAgentSummary)
	if createError != nil {
		return AccountSession{}, createError
	}
	if commitError := transaction.Commit(context); commitError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	return AccountSession{Account: account, Credential: credential}, nil // HTTP 使用账号构造 JSON，使用凭据设置 Cookie。
}

// --- 为一个已验证账号启动新的 token family ---
func (commands *SessionCommands) Start(context context.Context, accountID string, userAgentSummary string) (SessionCredential, error) {
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return SessionCredential{}, ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 提交后为空操作；任何提前返回都不留部分事实。

	var accountState string
	var credentialVersion int64
	queryError := transaction.QueryRow(context,
		"SELECT state, credential_version FROM accounts WHERE id = $1 FOR UPDATE", accountID,
	).Scan(&accountState, &credentialVersion)
	if queryError != nil { // 不向登录边界区分未知账号和数据库读取细节。
		return SessionCredential{}, ErrInvalidRefreshSession
	}
	if accountState != "active" { // 停用账号不能建立新的浏览器设备事实。
		return SessionCredential{}, ErrAccountDisabled
	}

	credential, createError := insertSession(context, transaction, commands.now().UTC(), accountID, credentialVersion, userAgentSummary)
	if createError != nil {
		return SessionCredential{}, createError
	}
	if commitError := transaction.Commit(context); commitError != nil {
		return SessionCredential{}, ErrSessionWriteFailed
	}
	return credential, nil // 反馈只出现一次的原始刷新秘密和会话期限。
}

// --- 轮换刷新秘密并只反馈一次性凭据 ---
func (commands *SessionCommands) Rotate(context context.Context, sessionID string, refreshToken string) (SessionCredential, error) {
	accountSession, refreshError := commands.refresh(context, sessionID, refreshToken) // 复用 HTTP 所需的完整原子轮换。
	return accountSession.Credential, refreshError                                     // 命令测试只消费一次性凭据投影。
}

// --- 轮换刷新秘密并恢复当前账号投影 ---
func (commands *SessionCommands) Refresh(context context.Context, sessionID string, refreshToken string) (AccountSession, error) {
	return commands.refresh(context, sessionID, refreshToken) // HTTP 不需要在提交后另开一次账号查询。
}

// --- 读取一个访问 JWT 当前仍对应的活动账号会话 ---
func (commands *SessionCommands) Current(context context.Context, accountID string, sessionID string, credentialVersion int64) (Account, error) {
	if accountID == "" || sessionID == "" || credentialVersion < 1 { // 不完整 JWT 投影不允许进入数据库查询。
		return Account{}, ErrAuthenticationRequired
	}
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return Account{}, ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 当前账号读取不修改数据，完成后释放一致快照。

	account := Account{}
	var sessionCredentialVersion int64
	var idleExpiresAt time.Time
	var absoluteExpiresAt time.Time
	var revokedAt *time.Time
	queryError := transaction.QueryRow(context, `
		SELECT a.id, a.username_display, a.display_name, a.role, a.state, a.staff_profile_id,
			a.credential_version, a.must_change_password,
			s.credential_version, s.idle_expires_at, s.absolute_expires_at, s.revoked_at
		FROM account_sessions AS s
		JOIN accounts AS a ON a.id = s.account_id
		WHERE s.id = $1 AND a.id = $2`, sessionID, accountID,
	).Scan(
		&account.ID, &account.Username, &account.DisplayName, &account.Role, &account.State, &account.StaffProfileID,
		&account.CredentialVersion, &account.MustChangePassword,
		&sessionCredentialVersion, &idleExpiresAt, &absoluteExpiresAt, &revokedAt,
	)
	if errors.Is(queryError, pgx.ErrNoRows) { // 未知账号与未知会话共享一个外部分类。
		return Account{}, ErrAuthenticationRequired
	}
	if queryError != nil { // 数据库异常保持服务不可用语义，不伪装成退出登录。
		return Account{}, ErrSessionWriteFailed
	}
	now := commands.now().UTC()
	if account.State != "active" || revokedAt != nil || sessionCredentialVersion != credentialVersion || account.CredentialVersion != credentialVersion || !now.Before(idleExpiresAt) || !now.Before(absoluteExpiresAt) { // 所有撤销与版本/期限终态统一拒绝。
		return Account{}, ErrAuthenticationRequired
	}
	return account, nil // 反馈与活动会话同一查询读取的最新账号投影。
}

// --- 撤销当前逐人账号会话 ---
func (commands *SessionCommands) Logout(context context.Context, accountID string, sessionID string) error {
	if accountID == "" || sessionID == "" { // 缺失访问身份时不允许构造宽泛更新条件。
		return ErrAuthenticationRequired
	}
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 更新或提交失败时保持原会话事实。

	revokedAt := commands.now().UTC() // 撤销时间只来自命令层可信时钟。
	commandTag, revokeError := transaction.Exec(context, `
		UPDATE account_sessions
		SET revoked_at = $3, revoke_reason = 'logout'
		WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL`, sessionID, accountID, revokedAt,
	)
	if revokeError != nil {
		return ErrSessionWriteFailed
	}
	if commandTag.RowsAffected() != 1 { // 未知、他人或已经终止的会话共享认证失效反馈。
		return ErrAuthenticationRequired
	}
	if commitError := transaction.Commit(context); commitError != nil {
		return ErrSessionWriteFailed
	}
	return nil // HTTP 层随后清除浏览器 Cookie。
}

// --- 列出本人最近设备会话 ---
func (commands *SessionCommands) List(context context.Context, accountID string, currentSessionID string) ([]Session, error) {
	if accountID == "" || currentSessionID == "" { // 缺失账号范围时不允许宽表查询。
		return nil, ErrAuthenticationRequired
	}
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return nil, ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 只读列表结束后释放一致快照。

	rows, queryError := transaction.Query(context, `
		SELECT id, user_agent_summary, created_at, last_seen_at,
			idle_expires_at, absolute_expires_at, revoked_at
		FROM account_sessions
		WHERE account_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT 50`, accountID,
	)
	if queryError != nil {
		return nil, ErrSessionWriteFailed
	}
	defer rows.Close() // 数据读取完成或提前失败时立即释放数据库游标。

	now := commands.now().UTC() // 所有列表项使用同一个可信状态判断时刻。
	sessions := make([]Session, 0, 8)
	for rows.Next() {
		session := Session{}
		var idleExpiresAt time.Time
		var revokedAt *time.Time
		if scanError := rows.Scan(&session.ID, &session.UserAgentSummary, &session.CreatedAt, &session.LastSeenAt, &idleExpiresAt, &session.AbsoluteExpiresAt, &revokedAt); scanError != nil {
			return nil, ErrSessionWriteFailed
		}
		session.Current = session.ID == currentSessionID // 仅精确匹配访问 JWT 的 sid。
		session.State = "active"                         // 活动是所有终态判断均未命中的默认。
		if revokedAt != nil {
			session.State = "revoked" // 显式撤销优先于期限显示。
		} else if !now.Before(idleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
			session.State = "expired" // 任一期限到达都成为过期展示状态。
		}
		sessions = append(sessions, session) // 只加入最小可展示字段。
	}
	if rowsError := rows.Err(); rowsError != nil {
		return nil, ErrSessionWriteFailed
	}
	return sessions, nil // 最多反馈本人最近 50 条设备事实。
}

// --- 撤销本人一个明确目标会话 ---
func (commands *SessionCommands) Revoke(context context.Context, accountID string, targetSessionID string) error {
	if accountID == "" || targetSessionID == "" { // 不完整目标不能形成数据库更新范围。
		return ErrSessionNotFound
	}
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 目标不存在或提交失败都不产生部分终态。

	revokedAt := commands.now().UTC() // 本人撤销使用独立固定原因和可信时间。
	commandTag, revokeError := transaction.Exec(context, `
		UPDATE account_sessions
		SET revoked_at = $3, revoke_reason = 'self_revoked'
		WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL`, targetSessionID, accountID, revokedAt,
	)
	if revokeError != nil {
		return ErrSessionWriteFailed
	}
	if commandTag.RowsAffected() != 1 { // 他人、未知和已经撤销的目标都不泄露存在性。
		return ErrSessionNotFound
	}
	if commitError := transaction.Commit(context); commitError != nil {
		return ErrSessionWriteFailed
	}
	return nil // HTTP 根据是否撤销当前 sid 决定是否清除 Cookie。
}

// --- 在一个事务中完成轮换、重放终态和账号恢复 ---
func (commands *SessionCommands) refresh(context context.Context, sessionID string, refreshToken string) (AccountSession, error) {
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 所有普通拒绝回滚；安全终态会在返回错误前显式提交。

	record, readError := lockSession(context, transaction, sessionID)
	if readError != nil {
		return AccountSession{}, ErrInvalidRefreshSession
	}
	presentedDigest := refreshDigest(refreshToken)
	if subtle.ConstantTimeCompare(presentedDigest[:], record.refreshDigest) != 1 { // 先验证秘密，再依据行状态采取动作。
		return AccountSession{}, ErrInvalidRefreshSession
	}
	if record.revokedAt != nil { // 已轮换行的正确旧秘密代表明确重放证据。
		if record.revokeReason != nil && *record.revokeReason == "refresh_rotated" {
			if replayError := revokeFamily(context, transaction, record.familyID, commands.now().UTC(), "refresh_replayed"); replayError != nil {
				return AccountSession{}, ErrSessionWriteFailed
			}
			if commitError := transaction.Commit(context); commitError != nil { // 先永久保存安全撤销，再向调用方反馈拒绝。
				return AccountSession{}, ErrSessionWriteFailed
			}
			return AccountSession{}, ErrRefreshReplay
		}
		return AccountSession{}, ErrInvalidRefreshSession
	}

	now := commands.now().UTC()
	if record.accountState != "active" { // 账号停用时提交该账号全部活动会话撤销。
		if revokeError := revokeAccount(context, transaction, record.accountID, now, "account_disabled"); revokeError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
		if commitError := transaction.Commit(context); commitError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
		return AccountSession{}, ErrAccountDisabled
	}
	if record.credentialVersion != record.accountCredentialVersion { // 改密或权限变化前的 family 不再可信。
		if revokeError := revokeFamily(context, transaction, record.familyID, now, "credential_changed"); revokeError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
		if commitError := transaction.Commit(context); commitError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
		return AccountSession{}, ErrInvalidRefreshSession
	}
	if !now.Before(record.idleExpiresAt) || !now.Before(record.absoluteExpiresAt) { // 任一期限到达即提交终态。
		if _, expireError := transaction.Exec(context,
			"UPDATE account_sessions SET revoked_at = $2, revoke_reason = 'expired' WHERE id = $1 AND revoked_at IS NULL", sessionID, now,
		); expireError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
		if commitError := transaction.Commit(context); commitError != nil {
			return AccountSession{}, ErrSessionWriteFailed
		}
		return AccountSession{}, ErrInvalidRefreshSession
	}

	newSessionID, _, newRefreshToken, randomError := newSessionMaterial() // family 必须继承，因此丢弃新生成的 family ID。
	if randomError != nil {
		return AccountSession{}, ErrSessionIdentityUnavailable
	}
	newIdleExpiresAt := now.Add(RefreshIdleLifetime)
	if newIdleExpiresAt.After(record.absoluteExpiresAt) { // 闲置续期永远不能越过原 family 绝对期限。
		newIdleExpiresAt = record.absoluteExpiresAt
	}
	newDigest := refreshDigest(newRefreshToken)
	_, insertError := transaction.Exec(context, `
		INSERT INTO account_sessions (
			id, account_id, token_family_id, refresh_digest, credential_version,
			user_agent_summary, created_at, last_seen_at, idle_expires_at, absolute_expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9)`,
		newSessionID, record.accountID, record.familyID, newDigest[:], record.accountCredentialVersion,
		record.userAgentSummary, now, newIdleExpiresAt, record.absoluteExpiresAt,
	)
	if insertError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	commandTag, revokeError := transaction.Exec(context, `
		UPDATE account_sessions
		SET revoked_at = $2, revoke_reason = 'refresh_rotated', replaced_by_session_id = $3
		WHERE id = $1 AND revoked_at IS NULL`, sessionID, now, newSessionID,
	)
	if revokeError != nil || commandTag.RowsAffected() != 1 { // 并发变化必须让新行和旧行更新一起回滚。
		return AccountSession{}, ErrInvalidRefreshSession
	}
	if commitError := transaction.Commit(context); commitError != nil {
		return AccountSession{}, ErrSessionWriteFailed
	}
	credential := SessionCredential{
		SessionID: newSessionID, RefreshToken: newRefreshToken, CredentialVersion: record.accountCredentialVersion,
		IdleExpiresAt: newIdleExpiresAt, AbsoluteExpiresAt: record.absoluteExpiresAt,
	}
	account := Account{
		ID: record.accountID, Username: record.accountUsername, DisplayName: record.accountDisplayName,
		Role: record.accountRole, State: record.accountState, StaffProfileID: record.accountStaffProfileID,
		CredentialVersion: record.accountCredentialVersion, MustChangePassword: record.accountMustChangePassword,
	}
	return AccountSession{Account: account, Credential: credential}, nil // 轮换和账号投影来自同一个已提交锁定快照。
}

// --- 修改本人密码并在同一提交中撤销全部设备 ---
func (commands *SessionCommands) ChangePassword(context context.Context, accountID string, currentPassword string, newPassword string) error {
	transaction, beginError := commands.database.Begin(context)
	if beginError != nil {
		return ErrSessionWriteFailed
	}
	defer func() { _ = transaction.Rollback(context) }() // 验证、账号更新和会话撤销任一步失败都整体回滚。

	var currentPasswordHash string
	var accountState string
	queryError := transaction.QueryRow(context,
		"SELECT password_hash, state FROM accounts WHERE id = $1 FOR UPDATE", accountID,
	).Scan(&currentPasswordHash, &accountState)
	if queryError != nil || !VerifyPassword(currentPasswordHash, currentPassword) { // 未知账号、损坏 hash 和错误旧密码共享最小反馈。
		return ErrInvalidCredentials
	}
	if accountState != "active" { // 停用身份不能用仍记得的旧密码重新激活自己。
		return ErrAccountDisabled
	}
	newPasswordHash, hashError := HashPassword(newPassword) // 只有旧凭据通过后才承担第二次 Argon2id 成本，降低无效请求资源消耗。
	if hashError != nil {
		return hashError // 新密码无效或随机源失败时，行锁随事务回滚释放且账号保持原状。
	}

	changedAt := commands.now().UTC() // 账号和全部会话使用同一个可信修改时间。
	commandTag, updateError := transaction.Exec(context, `
		UPDATE accounts
		SET password_hash = $2, credential_version = credential_version + 1,
			must_change_password = false, version = version + 1, updated_at = $3
		WHERE id = $1`, accountID, newPasswordHash, changedAt)
	if updateError != nil || commandTag.RowsAffected() != 1 { // 行锁后的精确单行更新是提交前置条件。
		return ErrSessionWriteFailed
	}
	if revokeError := revokeAccount(context, transaction, accountID, changedAt, "password_changed"); revokeError != nil { // 所有设备撤销与新 hash 共享事务。
		return ErrSessionWriteFailed
	}
	if _, invalidateError := transaction.Exec(context, `
		UPDATE mfa_challenges SET remaining_attempts = 0
		WHERE account_id = $1 AND consumed_at IS NULL AND remaining_attempts > 0`, accountID,
	); invalidateError != nil { // 旧密码已证明的短期 challenge 不能越过本次凭据版本变化。
		return ErrSessionWriteFailed
	}
	if commitError := transaction.Commit(context); commitError != nil {
		return ErrSessionWriteFailed
	}
	return nil // HTTP 层只需清除 Cookie 并要求使用新密码重新登录。
}

// --- 锁定会话及其最新账号安全状态 ---
func lockSession(context context.Context, transaction pgx.Tx, sessionID string) (sessionRecord, error) {
	record := sessionRecord{}
	queryError := transaction.QueryRow(context, `
		SELECT s.account_id, s.token_family_id, s.refresh_digest, s.credential_version,
			s.user_agent_summary, s.idle_expires_at, s.absolute_expires_at,
			s.revoked_at, s.revoke_reason, a.state, a.credential_version,
			a.username_display, a.display_name, a.role, a.staff_profile_id, a.must_change_password
		FROM account_sessions AS s
		JOIN accounts AS a ON a.id = s.account_id
		WHERE s.id = $1
		FOR UPDATE OF s, a`, sessionID,
	).Scan(
		&record.accountID, &record.familyID, &record.refreshDigest, &record.credentialVersion,
		&record.userAgentSummary, &record.idleExpiresAt, &record.absoluteExpiresAt,
		&record.revokedAt, &record.revokeReason, &record.accountState, &record.accountCredentialVersion,
		&record.accountUsername, &record.accountDisplayName, &record.accountRole, &record.accountStaffProfileID, &record.accountMustChangePassword,
	)
	if queryError != nil {
		if errors.Is(queryError, pgx.ErrNoRows) { // 未知会话不泄露是否曾存在。
			return sessionRecord{}, ErrInvalidRefreshSession
		}
		return sessionRecord{}, ErrSessionWriteFailed
	}
	return record, nil
}

// --- 在调用方事务内写入一个新的 token family ---
func insertSession(context context.Context, transaction pgx.Tx, issuedAt time.Time, accountID string, credentialVersion int64, userAgentSummary string) (SessionCredential, error) {
	sessionID, familyID, refreshToken, randomError := newSessionMaterial() // 一次生成会话、family 和只反馈一次的原始秘密。
	if randomError != nil {
		return SessionCredential{}, ErrSessionIdentityUnavailable
	}
	idleExpiresAt := issuedAt.Add(RefreshIdleLifetime)         // 闲置窗口从本次可信活动时间开始。
	absoluteExpiresAt := issuedAt.Add(RefreshAbsoluteLifetime) // family 最终期限只在首次登录产生。
	digest := refreshDigest(refreshToken)                      // 进入数据库前将原始秘密收敛为 SHA-256 投影。
	_, insertError := transaction.Exec(context, `
		INSERT INTO account_sessions (
			id, account_id, token_family_id, refresh_digest, credential_version,
			user_agent_summary, created_at, last_seen_at, idle_expires_at, absolute_expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9)`,
		sessionID, accountID, familyID, digest[:], credentialVersion,
		truncateUserAgent(userAgentSummary), issuedAt, idleExpiresAt, absoluteExpiresAt,
	)
	if insertError != nil {
		return SessionCredential{}, ErrSessionWriteFailed
	}
	return SessionCredential{
		SessionID: sessionID, RefreshToken: refreshToken, CredentialVersion: credentialVersion,
		IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
	}, nil // 调用方仍负责提交账号验证和会话创建的完整事务。
}

// --- 撤销一个 family 当前仍活动的全部会话 ---
func revokeFamily(context context.Context, transaction pgx.Tx, familyID string, revokedAt time.Time, reason string) error {
	_, revokeError := transaction.Exec(context, `
		UPDATE account_sessions SET revoked_at = $2, revoke_reason = $3
		WHERE token_family_id = $1 AND revoked_at IS NULL`, familyID, revokedAt, reason)
	return revokeError
}

// --- 撤销一个账号当前仍活动的全部会话 ---
func revokeAccount(context context.Context, transaction pgx.Tx, accountID string, revokedAt time.Time, reason string) error {
	_, revokeError := transaction.Exec(context, `
		UPDATE account_sessions SET revoked_at = $2, revoke_reason = $3
		WHERE account_id = $1 AND revoked_at IS NULL`, accountID, revokedAt, reason)
	return revokeError
}

// --- 生成一次会话所需的不透明 ID 与刷新秘密 ---
func newSessionMaterial() (string, string, string, error) {
	sessionID, sessionIDError := identity.New("AS")
	if sessionIDError != nil {
		return "", "", "", sessionIDError
	}
	familyID, familyIDError := identity.New("RF")
	if familyIDError != nil {
		return "", "", "", familyIDError
	}
	randomBytes := make([]byte, refreshSecretBytes)
	if _, randomError := rand.Read(randomBytes); randomError != nil {
		return "", "", "", randomError
	}
	return sessionID, familyID, base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// --- 将原始刷新秘密变成唯一可持久化投影 ---
func refreshDigest(refreshToken string) [sha256.Size]byte {
	return sha256.Sum256([]byte(refreshToken))
}

// --- 将设备摘要按字符截断，禁止无效 UTF-8 穿过数据库边界 ---
func truncateUserAgent(summary string) string {
	if !utf8.ValidString(summary) {
		return ""
	}
	runes := []rune(summary)
	if len(runes) > maxUserAgentRunes {
		runes = runes[:maxUserAgentRunes]
	}
	return string(runes)
}
