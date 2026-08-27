/*
团队计划业务指令：让活动老板和老师读取同一份工作台计划，并只允许老板版本化保存。
调用方只提交当前账号和一次编辑意图；本模块在事务中重验账号、规范化正文、写入计划与最小审计。
调用示例：commands.Read(ctx, actor)、commands.Update(ctx, actor, requestID, input)。
*/
package teamplan

import (
	"context"      // 将请求取消传入 PostgreSQL 事务。
	"errors"       // 暴露与 SQL 和正文无关的稳定失败分类。
	"strings"      // 清理成员输入的首尾空白，同时保留正文内部换行。
	"time"         // 反馈计划最近保存时间。
	"unicode/utf8" // 按用户可见字符限制中文正文长度。

	"github.com/jackc/pgx/v5"        // 让连接池和测试连接共享事务入口。
	"golang.org/x/text/unicode/norm" // 统一兼容字符，避免视觉相同内容形成不同数据。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth" // 接收认证层已经恢复的最小账号投影。
)

var ErrInvalidDependencies = errors.New("team plan dependencies are invalid") // 数据库或身份能力不完整。
var ErrForbidden = errors.New("team plan access is forbidden")                // 当前账号不能读取或修改目标计划。
var ErrInvalidInput = errors.New("team plan input is invalid")                // 字段长度、版本或请求身份不符合合同。
var ErrNotFound = errors.New("team plan was not found")                       // 唯一计划尚未建立或被移除。
var ErrVersionConflict = errors.New("team plan version conflicts")            // 页面版本落后，拒绝静默覆盖。
var ErrWriteFailed = errors.New("team plan write failed")                     // 事务没有形成完整事实。

// Plan 是老板与老师工作台共享的唯一团队安排。
type Plan struct {
	ID        string    `json:"id"`         // ID 固定为不透明单例身份 TP-primary。
	Title     string    `json:"title"`      // Title 是工作台区块标题。
	Summary   string    `json:"summary"`    // Summary 用一句话解释本周优先级。
	Content   string    `json:"content"`    // Content 是保留真实换行的普通文本。
	Version   int64     `json:"version"`    // Version 防止老板旧页面静默覆盖。
	UpdatedAt time.Time `json:"updated_at"` // UpdatedAt 说明最近保存时间。
}

// UpdateInput 是老板编辑表单提交的完整计划快照。
type UpdateInput struct {
	Title   string // Title 必填 1..80 字符。
	Summary string // Summary 可空且最多 160 字符。
	Content string // Content 可空且最多 4000 字符。
	Version int64  // Version 绑定页面读取的旧计划。
}

// Commands 隐藏账号复核、正文规则、版本写入和最小审计格式。
type Commands struct {
	data        *store                       // data 集中执行团队计划 PostgreSQL 操作。
	newIdentity func(string) (string, error) // newIdentity 只生成最小审计身份。
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error) // pgx.Conn 与连接池都满足该事务入口。
}

type preparedUpdate struct {
	title, summary, content string // 三个字段是规范化后的完整编辑快照。
	version                 int64  // version 绑定旧页面事实。
}

// --- 装配团队计划深模块 ---
func NewCommands(database transactionSource, newIdentity func(string) (string, error)) (*Commands, error) {
	if database == nil || newIdentity == nil { // 缺少任一能力时不构造半可用模块。
		return nil, ErrInvalidDependencies
	}
	return &Commands{data: &store{database: database}, newIdentity: newIdentity}, nil // 数据库副作用全部留在私有 store。
}

// --- 读取工作台唯一团队计划 ---
func (commands *Commands) Read(ctx context.Context, actor auth.Account) (Plan, error) {
	if !canRead(actor) { // 认证投影先于任何数据库读取拦截明显无权请求。
		return Plan{}, ErrForbidden
	}
	transaction, beginError := commands.data.database.Begin(ctx) // 账号复核和计划读取共享一致边界。
	if beginError != nil {
		return Plan{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }() // 任何提前返回都结束事务。

	if _, actorError := commands.data.requireActor(ctx, transaction, actor.ID); actorError != nil { // 重新读取数据库最新账号状态。
		return Plan{}, actorError
	}
	plan, readError := commands.data.read(ctx, transaction) // 读取唯一计划，不携带第二套任务数据。
	if readError != nil {
		return Plan{}, readError
	}
	if commitError := transaction.Commit(ctx); commitError != nil { // 只有两次读取都成功才反馈一致快照。
		return Plan{}, ErrWriteFailed
	}
	return plan, nil
}

// --- 由老板版本化保存团队计划 ---
func (commands *Commands) Update(ctx context.Context, actor auth.Account, requestID string, input UpdateInput) (Plan, error) {
	if !canEdit(actor) { // 员工在解析正文和打开事务前即被拒绝。
		return Plan{}, ErrForbidden
	}
	prepared, prepareError := prepareUpdate(requestID, input) // 先规范化全部纯输入，避免失败事务占用连接。
	if prepareError != nil {
		return Plan{}, prepareError
	}
	auditID, identityError := commands.newIdentity("AU") // 审计身份在事务前准备，避免提交后才发现随机源失败。
	if identityError != nil || auditID == "" {
		return Plan{}, ErrWriteFailed
	}
	transaction, beginError := commands.data.database.Begin(ctx) // 账号、计划和审计共用一次原子写入。
	if beginError != nil {
		return Plan{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }() // 任何失败都撤销计划和审计。

	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID) // 使用数据库最新角色裁决写权限。
	if actorError != nil || currentActor.role != "owner" {
		return Plan{}, ErrForbidden
	}
	updated, updateError := commands.data.update(ctx, transaction, currentActor.id, prepared) // 用旧版本条件保存完整计划。
	if updateError != nil {
		return Plan{}, updateError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, currentActor.id, requestID, updated.Version); auditError != nil { // 审计不复制标题或正文。
		return Plan{}, auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil { // 计划和审计都成功后才形成反馈。
		return Plan{}, ErrWriteFailed
	}
	return updated, nil
}

// --- 在事务前规范化完整编辑快照 ---
func prepareUpdate(requestID string, input UpdateInput) (preparedUpdate, error) {
	title := clean(input.Title)                                                                                                                        // 标题使用单行式 NFKC 与首尾清理。
	summary := clean(input.Summary)                                                                                                                    // 摘要允许为空但不保留无意义边缘空白。
	content := norm.NFKC.String(strings.TrimSpace(input.Content))                                                                                      // 正文只清理边缘空白，内部真实换行原样保留。
	if !validText(requestID, 8, 100) || !validText(title, 1, 80) || !validText(summary, 0, 160) || !validText(content, 0, 4000) || input.Version < 1 { // 任一不变量失败都返回统一输入问题。
		return preparedUpdate{}, ErrInvalidInput
	}
	return preparedUpdate{title: title, summary: summary, content: content, version: input.Version}, nil // 反馈可直接写库的明确数据。
}

func canRead(actor auth.Account) bool {
	return actor.ID != "" && actor.State == "active" && !actor.MustChangePassword && (actor.Role == "owner" || actor.Role == "staff") // 只有活动后台账号可读。
}

func canEdit(actor auth.Account) bool {
	return canRead(actor) && actor.Role == "owner" // 计划编辑是老板专属动作。
}

func clean(value string) string {
	return norm.NFKC.String(strings.TrimSpace(value)) // 统一视觉等价字符并移除边缘空白。
}

func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)       // 中文按字符而不是 UTF-8 字节计数。
	return length >= minimum && length <= maximum // 反馈是否落在公开长度合同内。
}
