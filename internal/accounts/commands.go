/*
账号管理指令：老板通过一个窄接口完成账号创建、修改、停用、重置和会话撤销。
每个写动作先做可信角色门禁，再把 PostgreSQL 事务、审计和幂等细节隐藏在本模块内。
调用示例：account, err := commands.Create(ctx, actor, requestID, key, input)。
*/
package accounts

import (
	"context"       // 将 HTTP 取消和期限传入账号事务。
	"crypto/sha256" // 将幂等创建意图压缩为不暴露密码的固定摘要。
	"encoding/json" // 用稳定字段结构形成创建意图摘要。
	"errors"        // 暴露固定业务失败分类，不泄露 SQL 或输入正文。
	"strings"       // 清理用户可见名称的外部空白。
	"time"          // 注入可信 UTC 时间用于审计和会话撤销。
	"unicode/utf8"  // 按用户可见字符验证合同长度。

	"github.com/jackc/pgx/v5"        // 抽象连接池与测试连接共同拥有的事务入口。
	"golang.org/x/text/cases"        // 对登录身份执行完整 Unicode casefold。
	"golang.org/x/text/unicode/norm" // 对兼容字符执行 NFKC 规范化。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth" // 接收认证模块已经验证的当前账号投影和密码能力。
)

var ErrInvalidDependencies = errors.New("account dependencies are invalid") // 数据库、时钟或身份生成能力未装配。
var ErrForbidden = errors.New("account management is forbidden")            // 当前逐人账号不是可用老板身份。
var ErrInvalidInput = errors.New("account input is invalid")                // 字段形状或角色关联不满足合同。
var ErrConflict = errors.New("account identity conflicts")                  // 用户名或员工档案已被占用。
var ErrNotFound = errors.New("account was not found")                       // 目标账号或员工档案不存在。
var ErrVersionConflict = errors.New("account version conflicts")            // 客户端版本不是最新事实。
var ErrIdempotencyConflict = errors.New("account idempotency conflicts")    // 同一幂等键对应不同创建意图。
var ErrWriteFailed = errors.New("account write failed")                     // PostgreSQL 未形成完整原子结果。

// Account 是账号管理页获准读取的投影，不包含密码、规范化键或会话秘密。
type Account struct {
	ID                 string  `json:"id"`                   // ID 是不可推测的历史身份。
	Username           string  `json:"username"`             // Username 保留合法显示形式。
	DisplayName        string  `json:"display_name"`         // DisplayName 供管理页识别人。
	Role               string  `json:"role"`                 // Role 只允许 owner 或 staff。
	State              string  `json:"state"`                // State 保留 active 或 disabled 终态。
	StaffProfileID     *string `json:"staff_profile_id"`     // 员工必须唯一关联责任档案，老板为 null。
	CredentialVersion  int64   `json:"credential_version"`   // 权限或凭据变化使旧会话失效。
	MustChangePassword bool    `json:"must_change_password"` // 初始或重置密码要求首次改密。
	Version            int64   `json:"version"`              // 管理修改使用的乐观并发版本。
}

// CreateInput 是老板创建逐人账号的一次意图。
type CreateInput struct {
	Username        string  // Username 会被 NFKC、trim 和 casefold 后判重。
	DisplayName     string  // DisplayName 是管理页显示名称。
	Role            string  // Role 只允许 owner 或 staff。
	StaffProfileID  *string // StaffProfileID 可绑定既有档案；staff 为空时由事务自动建立。
	InitialPassword string  // InitialPassword 只在当前调用内生成 Argon2id hash。
}

// UpdateInput 是账号状态和员工责任关联的一次版本化修改。
type UpdateInput struct {
	State          string  // State 只允许 active 或 disabled。
	StaffProfileID *string // StaffProfileID 必须符合目标账号既有角色。
	Version        int64   // Version 防止覆盖另一位管理员的修改。
}

// RenameSelfInput 是老板或老师修改本人对外显示名称的唯一指令。
type RenameSelfInput struct {
	DisplayName string // DisplayName 不参与登录唯一性或权限裁决。
}

// Commands 收拢账号管理公开接口，调用方无需了解 SQL、审计或幂等表。
type Commands struct {
	data        *store                       // data 执行模块私有 PostgreSQL 操作。
	now         func() time.Time             // now 提供统一 UTC 撤销时间。
	newIdentity func(string) (string, error) // newIdentity 生成不透明账号和审计 ID。
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error) // Begin 同时由 pgx.Conn 与 pgxpool.Pool 实现。
}

type preparedCreate struct {
	accountID          string            // accountID 是提交前准备的账号身份。
	auditID            string            // auditID 与业务身份分离。
	usernameNormalized string            // usernameNormalized 是唯一登录比较键。
	usernameDisplay    string            // usernameDisplay 是合法显示形式。
	displayName        string            // displayName 是管理页人员名称。
	passwordHash       string            // passwordHash 是唯一持久化密码材料。
	role               string            // role 已验证为 owner 或 staff。
	staffProfileID     *string           // staffProfileID 已通过角色形状校验。
	createStaffProfile bool              // createStaffProfile 只在 staff 未指定既有档案时为真。
	requestDigest      [sha256.Size]byte // requestDigest 绑定完整创建意图。
}

// --- 装配账号管理指令 ---
func NewCommands(database transactionSource, now func() time.Time, newIdentity func(string) (string, error)) (*Commands, error) {
	if database == nil || now == nil || newIdentity == nil { // 任一依赖未知时不构造部分可用模块。
		return nil, ErrInvalidDependencies
	}
	return &Commands{data: &store{database: database}, now: now, newIdentity: newIdentity}, nil // 只暴露深模块指令接口。
}

// --- 创建一个逐人账号 ---
func (commands *Commands) Create(ctx context.Context, actor auth.Account, requestID string, idempotencyKey string, input CreateInput) (Account, error) {
	if !isOwnerActor(actor) { // 角色门禁必须先于用户名、密码和员工关联处理。
		return Account{}, ErrForbidden
	}
	prepared, prepareError := commands.prepareCreate(input, requestID, idempotencyKey) // 所有随机和 hash 依赖在事务前成功。
	if prepareError != nil {
		return Account{}, prepareError
	}

	transaction, beginError := commands.data.database.Begin(ctx) // 角色复核、账号、审计和幂等事实共享事务。
	if beginError != nil {
		return Account{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }() // 任一提前返回都移除部分写入。
	if ownerError := commands.data.requireOwner(ctx, transaction, actor.ID); ownerError != nil {
		return Account{}, ownerError
	}
	if replay, found, replayError := commands.data.findCreateReplay(ctx, transaction, actor.ID, idempotencyKey, prepared.requestDigest); replayError != nil || found { // 同一意图只产生一个账号。
		return replay, replayError
	}
	if prepared.createStaffProfile {
		if profileError := commands.data.insertStaffProfile(ctx, transaction, *prepared.staffProfileID, prepared.displayName); profileError != nil {
			return Account{}, profileError
		}
	}
	created, insertError := commands.data.insertAccount(ctx, transaction, prepared)
	if insertError != nil {
		return Account{}, insertError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, prepared.auditID, actor.ID, "account.created", created.ID, requestID, created.Version); auditError != nil {
		return Account{}, auditError
	}
	if idempotencyError := commands.data.insertCreateIdempotency(ctx, transaction, actor.ID, idempotencyKey, prepared.requestDigest, created.ID); idempotencyError != nil {
		return Account{}, idempotencyError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Account{}, ErrWriteFailed
	}
	return created, nil // 只反馈无密码、无规范化键的账号投影。
}

// --- 修改本人显示名称，员工责任档案与账号保持同名 ---
func (commands *Commands) RenameSelf(ctx context.Context, actor auth.Account, requestID string, input RenameSelfInput) (Account, error) {
	if actor.ID == "" || actor.State != "active" || actor.MustChangePassword || (actor.Role != "owner" && actor.Role != "staff") { // 调用方投影先拒绝非活动或首次改密身份。
		return Account{}, ErrForbidden
	}
	displayName := norm.NFKC.String(strings.TrimSpace(input.DisplayName))
	if !validText(displayName, 1, 80) || !validText(requestID, 8, 100) {
		return Account{}, ErrInvalidInput
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Account{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, currentError := commands.data.requireActiveSelf(ctx, transaction, actor.ID)
	if currentError != nil {
		return Account{}, currentError
	}
	if current.DisplayName == displayName { // 同名重试不推进版本或制造重复审计。
		if commitError := transaction.Commit(ctx); commitError != nil {
			return Account{}, ErrWriteFailed
		}
		return current, nil
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || auditID == "" {
		return Account{}, ErrWriteFailed
	}
	updated, renameError := commands.data.renameSelf(ctx, transaction, current, displayName)
	if renameError != nil {
		return Account{}, renameError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, actor.ID, "account.display_name_changed", actor.ID, requestID, updated.Version); auditError != nil {
		return Account{}, auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Account{}, ErrWriteFailed
	}
	return updated, nil
}

// --- 列出全部历史账号，包括已停用身份 ---
func (commands *Commands) List(ctx context.Context, actor auth.Account) ([]Account, error) {
	if !isOwnerActor(actor) { // 角色门禁先于数据库列表查询。
		return nil, ErrForbidden
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return nil, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if ownerError := commands.data.requireOwner(ctx, transaction, actor.ID); ownerError != nil {
		return nil, ownerError
	}
	accounts, listError := commands.data.listAccounts(ctx, transaction)
	if listError != nil {
		return nil, listError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return nil, ErrWriteFailed
	}
	return accounts, nil
}

// --- 版本化修改账号状态或员工责任关联 ---
func (commands *Commands) Update(ctx context.Context, actor auth.Account, requestID string, accountID string, input UpdateInput) (Account, error) {
	if !isOwnerActor(actor) { // 未授权调用不解析目标身份、状态或版本。
		return Account{}, ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validText(accountID, 15, 83) || (input.State != "active" && input.State != "disabled") || input.Version < 1 {
		return Account{}, ErrInvalidInput
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || auditID == "" {
		return Account{}, ErrWriteFailed
	}

	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Account{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if ownerError := commands.data.requireOwner(ctx, transaction, actor.ID); ownerError != nil {
		return Account{}, ownerError
	}
	current, currentError := commands.data.getAccount(ctx, transaction, accountID, true)
	if currentError != nil {
		return Account{}, currentError
	}
	if current.Version != input.Version {
		return Account{}, ErrVersionConflict
	}
	if (current.Role == "owner" && input.StaffProfileID != nil) || (current.Role == "staff" && !validStaffProfileID(input.StaffProfileID)) {
		return Account{}, ErrInvalidInput
	}
	if input.StaffProfileID != nil {
		active, profileError := commands.data.staffProfileActive(ctx, transaction, *input.StaffProfileID)
		if profileError != nil {
			return Account{}, profileError
		}
		if !active {
			return Account{}, ErrNotFound
		}
	}
	permissionsChanged := current.State != input.State || !sameOptionalText(current.StaffProfileID, input.StaffProfileID)
	updated, updateError := commands.data.updateAccount(ctx, transaction, accountID, input, permissionsChanged)
	if updateError != nil {
		return Account{}, updateError
	}
	if permissionsChanged {
		reason := "credential_changed"
		if input.State == "disabled" {
			reason = "account_disabled"
		}
		if revokeError := commands.data.revokeActiveSessions(ctx, transaction, accountID, commands.now().UTC(), reason); revokeError != nil {
			return Account{}, revokeError
		}
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, actor.ID, "account.updated", accountID, requestID, updated.Version); auditError != nil {
		return Account{}, auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Account{}, ErrWriteFailed
	}
	return updated, nil
}

// --- 设置一次性初始密码并撤销目标账号全部会话 ---
func (commands *Commands) ResetPassword(ctx context.Context, actor auth.Account, requestID string, accountID string, password string) (Account, error) {
	if !isOwnerActor(actor) { // 未授权调用不得触发昂贵密码派生或目标账号查询。
		return Account{}, ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validText(accountID, 15, 83) {
		return Account{}, ErrInvalidInput
	}
	passwordHash, hashError := auth.HashPassword(password)
	if hashError != nil {
		return Account{}, ErrInvalidInput
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || auditID == "" {
		return Account{}, ErrWriteFailed
	}

	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Account{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if ownerError := commands.data.requireOwner(ctx, transaction, actor.ID); ownerError != nil {
		return Account{}, ownerError
	}
	if _, targetError := commands.data.getAccount(ctx, transaction, accountID, true); targetError != nil {
		return Account{}, targetError
	}
	reset, resetError := commands.data.resetPassword(ctx, transaction, accountID, passwordHash)
	if resetError != nil {
		return Account{}, resetError
	}
	if revokeError := commands.data.revokeActiveSessions(ctx, transaction, accountID, commands.now().UTC(), "password_changed"); revokeError != nil {
		return Account{}, revokeError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, actor.ID, "account.password_reset", accountID, requestID, reset.Version); auditError != nil {
		return Account{}, auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Account{}, ErrWriteFailed
	}
	return reset, nil
}

// --- 由老板明确撤销目标账号全部活动会话 ---
func (commands *Commands) RevokeSessions(ctx context.Context, actor auth.Account, requestID string, accountID string) error {
	if !isOwnerActor(actor) { // 角色门禁先于目标身份解析和行锁。
		return ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validText(accountID, 15, 83) {
		return ErrInvalidInput
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || auditID == "" {
		return ErrWriteFailed
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if ownerError := commands.data.requireOwner(ctx, transaction, actor.ID); ownerError != nil {
		return ownerError
	}
	target, targetError := commands.data.getAccount(ctx, transaction, accountID, true)
	if targetError != nil {
		return targetError
	}
	if revokeError := commands.data.revokeActiveSessions(ctx, transaction, accountID, commands.now().UTC(), "owner_revoked"); revokeError != nil {
		return revokeError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, actor.ID, "account.sessions_revoked", accountID, requestID, target.Version); auditError != nil {
		return auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 准备不产生数据库部分写入的创建意图 ---
func (commands *Commands) prepareCreate(input CreateInput, requestID string, idempotencyKey string) (preparedCreate, error) {
	usernameDisplay := norm.NFKC.String(strings.TrimSpace(input.Username))                                                                                                                       // 兼容字符统一但保留合法大小写。
	usernameNormalized := cases.Fold().String(usernameDisplay)                                                                                                                                   // casefold 只用于唯一比较。
	displayName := norm.NFKC.String(strings.TrimSpace(input.DisplayName))                                                                                                                        // 清理人员名称外部空白。
	if !validText(usernameDisplay, 1, 128) || !validText(usernameNormalized, 1, 128) || !validText(displayName, 1, 80) || !validText(requestID, 8, 100) || !validText(idempotencyKey, 16, 128) { // 固定所有持久化文本上限。
		return preparedCreate{}, ErrInvalidInput
	}
	if input.Role != "owner" && input.Role != "staff" { // 未注册角色不交给数据库猜测。
		return preparedCreate{}, ErrInvalidInput
	}
	if (input.Role == "owner" && input.StaffProfileID != nil) || (input.Role == "staff" && input.StaffProfileID != nil && !validStaffProfileID(input.StaffProfileID)) { // 员工可绑定既有档案，也可由本事务自动建立。
		return preparedCreate{}, ErrInvalidInput
	}
	passwordHash, hashError := auth.HashPassword(input.InitialPassword) // 原始密码只参与本次派生。
	if hashError != nil {
		return preparedCreate{}, ErrInvalidInput
	}
	accountID, accountIdentityError := commands.newIdentity("A")
	auditID, auditIdentityError := commands.newIdentity("AU")
	staffProfileID := input.StaffProfileID
	createStaffProfile := input.Role == "staff" && staffProfileID == nil
	if createStaffProfile {
		generatedStaffProfileID, profileIdentityError := commands.newIdentity("T")
		if profileIdentityError != nil || !validStaffProfileID(&generatedStaffProfileID) {
			return preparedCreate{}, ErrWriteFailed
		}
		staffProfileID = &generatedStaffProfileID
	}
	if accountIdentityError != nil || auditIdentityError != nil || accountID == "" || auditID == "" {
		return preparedCreate{}, ErrWriteFailed
	}
	digestBody, marshalError := json.Marshal(struct {
		Username       string  `json:"username"`
		DisplayName    string  `json:"display_name"`
		Role           string  `json:"role"`
		StaffProfileID *string `json:"staff_profile_id"`
		IdempotencyKey string  `json:"idempotency_key"`
	}{usernameNormalized, displayName, input.Role, input.StaffProfileID, idempotencyKey}) // 上下文只含已验证非秘密；密码单独进入高成本绑定。
	if marshalError != nil {
		return preparedCreate{}, ErrWriteFailed
	}
	requestDigest, digestError := auth.DerivePasswordIntentDigest(input.InitialPassword, digestBody)
	if digestError != nil {
		return preparedCreate{}, ErrWriteFailed
	}
	return preparedCreate{
		accountID: accountID, auditID: auditID, usernameNormalized: usernameNormalized,
		usernameDisplay: usernameDisplay, displayName: displayName, passwordHash: passwordHash,
		role: input.Role, staffProfileID: staffProfileID, createStaffProfile: createStaffProfile,
		requestDigest: requestDigest,
	}, nil
}

// --- 判断认证投影是否可进入老板管理命令 ---
func isOwnerActor(actor auth.Account) bool {
	return actor.ID != "" && actor.Role == "owner" && actor.State == "active" && !actor.MustChangePassword // 首次改密只允许改密或退出。
}

// --- 验证用户可见 UTF-8 文本长度 ---
func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value) // 合同长度按字符而不是字节。
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}

// --- 验证员工责任档案身份形状 ---
func validStaffProfileID(value *string) bool {
	return value != nil && strings.HasPrefix(*value, "T-") && validText(*value, 15, 83) // 存在性由事务查询决定。
}

// --- 比较两个可空责任档案身份 ---
func sameOptionalText(left *string, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
