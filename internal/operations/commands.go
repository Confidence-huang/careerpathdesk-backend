/*
运营命令入口：把老板审计、同定义范围统计和一次确认导出收束到一个 PostgreSQL 深模块。
公开反馈只包含固定聚合、最小审计字段或提交后 XLSX；授权、游标、digest 与事务状态均留在模块内部。
*/
package operations

import (
	"context" // 把请求取消传给模块拥有的 PostgreSQL 事务。
	"errors"  // 暴露不包含输入、正文或数据库细节的稳定失败分类。
	"time"    // 为导出确认提供可注入的精确 UTC 边界。

	"github.com/jackc/pgx/v5" // 提供明确事务和 Repeatable Read 快照能力。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/identity" // 生成审计和导出操作的不透明身份。
)

const exportConfirmationLifetime = 5 * time.Minute // 二次确认只代表一个短期、一次性的当前导出意图。

var ErrInvalidDependencies = errors.New("operations dependencies are invalid")          // 模块缺少数据库或收到多个时钟。
var ErrForbidden = errors.New("operations action is forbidden")                         // 未知、停用、角色变化或会话失效共享最小权限反馈。
var ErrInvalidInput = errors.New("operations input is invalid")                         // 固定过滤、游标或导出输入不符合公开合同。
var ErrOperationFailed = errors.New("operations query failed")                          // 非导出数据库读取没有形成可信结果。
var ErrExportConfirmationUnavailable = errors.New("export confirmation is unavailable") // 未知、误绑、过期或已使用确认不可枚举。
var ErrExportFailed = errors.New("export failed")                                       // 导出文件、消费、审计或提交没有原子完成。

// AuditQuery 是老板可用的固定精确过滤和不透明游标。
type AuditQuery struct {
	Action     string // Action 只执行精确相等，不接受模式语义。
	ObjectType string // ObjectType 只执行精确相等。
	Cursor     string // Cursor 是上一页末项的模块私有复合边界。
	Limit      int    // Limit 必须位于 1..100。
}

// AuditEvent 是审计列表唯一公开的最小投影，不包含 metadata 或业务正文。
type AuditEvent struct {
	ID         string    `json:"id"`
	ActorKind  string    `json:"actor_kind"`
	ActorID    string    `json:"actor_id"`
	Action     string    `json:"action"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
	Outcome    string    `json:"outcome"`
	RequestID  string    `json:"request_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

// AuditPage 保存一页稳定审计及可选的下一页边界。
type AuditPage struct {
	Events     []AuditEvent `json:"events"`
	NextCursor *string      `json:"next_cursor"`
}

// Statistics 让团队和本人范围复用完全相同的三个当前业务定义。
type Statistics struct {
	Scope              string `json:"scope"`
	InServiceStudents  int    `json:"in_service_students"`
	OverdueFollowUps   int    `json:"overdue_follow_ups"`
	OpenAttentionCases int    `json:"open_attention_cases"`
}

// ExportConfirmationInput 绑定当前浏览器会话与一种导出。
type ExportConfirmationInput struct {
	SessionID  string
	ExportType string
}

// ExportConfirmation 只反馈一次原始确认及其精确终点。
type ExportConfirmation struct {
	Confirmation string
	ExpiresAt    time.Time
}

// RunExportInput 必须完整复述确认绑定并提供最小请求证据。
type RunExportInput struct {
	SessionID    string
	ExportType   string
	Confirmation string
	RequestID    string
}

// ExportArtifact 只在消费、审计和事务提交全部成功后出现。
type ExportArtifact struct {
	MediaType string
	Body      []byte
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error)                  // 普通读取和确认签发使用短事务。
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) // 导出显式建立 Repeatable Read 快照。
}

// Commands 隐藏三类运营动作的授权、查询和提交编排。
type Commands struct {
	database    transactionSource            // database 是所有公开动作唯一事务入口。
	now         func() time.Time             // now 固定确认、会话和审计的同一 UTC 事实。
	newIdentity func(string) (string, error) // newIdentity 只生成不透明领域引用。
}

// currentActor 是从数据库动态恢复的最小权限范围。
type currentActor struct {
	id             string  // id 进入审计主体，不进入错误输出。
	role           string  // role 决定团队、本人或老板专属路径。
	staffProfileID *string // staffProfileID 只来自当前数据库事实。
}

// --- 装配一个窄而完整的运营命令入口 ---
func NewCommands(database transactionSource, clocks ...func() time.Time) (*Commands, error) {
	if database == nil || len(clocks) > 1 || (len(clocks) == 1 && clocks[0] == nil) {
		return nil, ErrInvalidDependencies // 不允许半可用数据库或含糊时钟依赖。
	}
	now := time.Now
	if len(clocks) == 1 {
		now = clocks[0] // 测试和应用均通过同一函数决定精确安全边界。
	}
	return &Commands{database: database, now: now, newIdentity: identity.New}, nil
}
