/*
审计查询：角色门禁、数据库当前权限、固定过滤和复合游标在一个短事务内完成。
查询永不选择 metadata，避免业务正文先进入 Go 内存再依赖 HTTP 层删减。
*/
package operations

import (
	"context"         // 驱动授权、列表和事务提交。
	"encoding/base64" // 将复合边界编码为不透明 URL 安全文本。
	"fmt"             // 只拼接固定 SQL 占位符编号，不拼接调用方值。
	"strings"         // 严格拆分游标内部两个固定字段。
	"time"            // 解析 RFC3339Nano UTC 游标时间。
	"unicode/utf8"    // 按公开字符而不是字节执行字段上限。

	"github.com/jackc/pgx/v5" // 分类无行授权并扫描真实 PostgreSQL 结果。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth" // 接受认证边界形成的最小账号投影。
)

const maxAuditCursorLength = 512 // 与 OpenAPI 游标上限一致，拒绝无界解码输入。

type auditCursor struct {
	occurredAt time.Time // occurredAt 是上一页末项的首排序键。
	id         string    // id 为同时刻事实提供稳定决胜键。
}

// --- 老板按固定条件读取一页最小审计 ---
func (commands *Commands) ListAuditEvents(ctx context.Context, actor auth.Account, query AuditQuery) (AuditPage, error) {
	if actor.Role != "owner" { // 投影角色门禁先于过滤和游标解析，避免越权探测输入合同。
		return AuditPage{}, ErrForbidden
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return AuditPage{}, ErrOperationFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, actorError := requireCurrentActor(ctx, transaction, actor)
	if actorError != nil || current.role != "owner" {
		return AuditPage{}, actorErrorOrForbidden(actorError)
	}
	if !validAuditQuery(query) {
		return AuditPage{}, ErrInvalidInput
	}
	var cursor *auditCursor
	if query.Cursor != "" {
		decoded, decodeError := decodeAuditCursor(query.Cursor)
		if decodeError != nil {
			return AuditPage{}, ErrInvalidInput
		}
		cursor = &decoded
	}
	page, listError := listAuditEvents(ctx, transaction, query, cursor)
	if listError != nil {
		return AuditPage{}, listError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return AuditPage{}, ErrOperationFailed
	}
	return page, nil
}

// --- 从数据库恢复当前账号角色和员工范围 ---
func requireCurrentActor(ctx context.Context, transaction pgx.Tx, projection auth.Account) (currentActor, error) {
	current := currentActor{id: projection.ID}
	var state string
	var mustChangePassword bool
	queryError := transaction.QueryRow(ctx, `
		SELECT role, state, staff_profile_id, must_change_password
		FROM accounts WHERE id = $1 FOR SHARE`, projection.ID,
	).Scan(&current.role, &state, &current.staffProfileID, &mustChangePassword)
	if queryError != nil {
		if queryError == pgx.ErrNoRows {
			return currentActor{}, ErrForbidden
		}
		return currentActor{}, ErrOperationFailed
	}
	if state != "active" || mustChangePassword || current.role != projection.Role ||
		(current.role == "staff" && current.staffProfileID == nil) || (current.role != "owner" && current.role != "staff") {
		return currentActor{}, ErrForbidden // 旧投影或不完整员工范围均不能扩大当前权限。
	}
	return current, nil
}

func actorErrorOrForbidden(actorError error) error {
	if actorError == nil {
		return ErrForbidden
	}
	return actorError // 数据库故障保留服务失败；权限事实仍统一为 ErrForbidden。
}

func validAuditQuery(query AuditQuery) bool {
	return query.Limit >= 1 && query.Limit <= 100 && utf8.ValidString(query.Action) && utf8.RuneCountInString(query.Action) <= 80 &&
		utf8.ValidString(query.ObjectType) && utf8.RuneCountInString(query.ObjectType) <= 40 && len(query.Cursor) <= maxAuditCursorLength
}

// --- 使用参数化精确条件和 limit+1 判断下一页 ---
func listAuditEvents(ctx context.Context, transaction pgx.Tx, query AuditQuery, cursor *auditCursor) (AuditPage, error) {
	conditions := []string{"TRUE"}
	arguments := make([]any, 0, 5)
	if query.Action != "" {
		arguments = append(arguments, query.Action)
		conditions = append(conditions, fmt.Sprintf("action = $%d", len(arguments)))
	}
	if query.ObjectType != "" {
		arguments = append(arguments, query.ObjectType)
		conditions = append(conditions, fmt.Sprintf("object_type = $%d", len(arguments)))
	}
	if cursor != nil {
		arguments = append(arguments, cursor.occurredAt, cursor.id)
		conditions = append(conditions, fmt.Sprintf("(occurred_at, id) < ($%d, $%d)", len(arguments)-1, len(arguments)))
	}
	arguments = append(arguments, query.Limit+1)
	statement := `SELECT id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, occurred_at
		FROM audit_events WHERE ` + strings.Join(conditions, " AND ") +
		` ORDER BY occurred_at DESC, id DESC LIMIT $` + fmt.Sprint(len(arguments))
	rows, queryError := transaction.Query(ctx, statement, arguments...)
	if queryError != nil {
		return AuditPage{}, ErrOperationFailed
	}
	defer rows.Close()
	events := make([]AuditEvent, 0, query.Limit+1)
	for rows.Next() {
		event := AuditEvent{}
		if scanError := rows.Scan(&event.ID, &event.ActorKind, &event.ActorID, &event.Action, &event.ObjectType, &event.ObjectID, &event.Outcome, &event.RequestID, &event.OccurredAt); scanError != nil {
			return AuditPage{}, ErrOperationFailed
		}
		event.OccurredAt = event.OccurredAt.UTC()
		events = append(events, event)
	}
	if rows.Err() != nil {
		return AuditPage{}, ErrOperationFailed
	}
	page := AuditPage{Events: events}
	if len(events) > query.Limit {
		page.Events = events[:query.Limit]
		last := page.Events[len(page.Events)-1]
		next := encodeAuditCursor(auditCursor{occurredAt: last.OccurredAt, id: last.ID})
		page.NextCursor = &next
	}
	return page, nil
}

func encodeAuditCursor(cursor auditCursor) string {
	payload := cursor.occurredAt.UTC().Format(time.RFC3339Nano) + "\n" + cursor.id
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeAuditCursor(encoded string) (auditCursor, error) {
	payload, decodeError := base64.RawURLEncoding.DecodeString(encoded)
	if decodeError != nil {
		return auditCursor{}, ErrInvalidInput
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 2 || len(parts[1]) < 1 || len(parts[1]) > 100 || !strings.HasPrefix(parts[1], "AU-") {
		return auditCursor{}, ErrInvalidInput
	}
	occurredAt, timeError := time.Parse(time.RFC3339Nano, parts[0])
	if timeError != nil {
		return auditCursor{}, ErrInvalidInput
	}
	return auditCursor{occurredAt: occurredAt.UTC(), id: parts[1]}, nil
}
