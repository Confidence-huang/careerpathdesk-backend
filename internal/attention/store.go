/*
关注 PostgreSQL 数据包：读取确定性规则事实、执行逐人账号复核，并原子保存事项与人工结论。
所有方法都运行在 Commands 明确创建的事务中；本文件不提交事务、不解释规则，也不复制业务正文。
*/
package attention

import (
	"bytes"         // 恒定比较已保存的请求摘要与当前确认投诉意图。
	"context"       // 把取消信号传递给每条 PostgreSQL 操作。
	"crypto/sha256" // 保存规范化证据集合的固定 32 字节指纹。
	"encoding/json" // 在公开 Case 与最小 evidence JSON 之间转换。
	"errors"        // 区分无行与普通数据库失败。
	"time"          // 查询规则截止点并保存可信结论时间。

	"github.com/jackc/pgx/v5"        // 使用事务、行锁和统一扫描接口。
	"github.com/jackc/pgx/v5/pgconn" // 将 PostgreSQL 约束收敛为稳定领域失败。
)

type store struct {
	database transactionSource // database 只作为 Commands 的事务入口。
}

type currentActor struct {
	id             string  // id 是数据库最新账号身份。
	role           string  // role 必须与公开动作要求一致。
	staffProfileID *string // staffProfileID 限定员工提醒范围。
}

const caseProjection = `id, student_id, rule_code, trigger_codes, evidence, first_triggered_at, last_triggered_at, status, conclusion_code, conclusion_reason, concluded_by_account_id, concluded_at, version, created_at, updated_at`

// --- 在事务内恢复最新可用账号和所需角色 ---
func (data *store) requireActor(requestContext context.Context, transaction pgx.Tx, actorID string, requiredRole string) (currentActor, error) {
	actor := currentActor{id: actorID}
	var state string
	var mustChangePassword bool
	queryError := transaction.QueryRow(requestContext, `SELECT role, state, staff_profile_id, must_change_password FROM accounts WHERE id = $1 FOR UPDATE`, actorID).Scan(&actor.role, &state, &actor.staffProfileID, &mustChangePassword)
	if queryError != nil || state != "active" || mustChangePassword || actor.role != requiredRole || requiredRole == "staff" && actor.staffProfileID == nil {
		return currentActor{}, ErrForbidden // 不区分账号缺失、停用、首次改密或错误角色。
	}
	return actor, nil
}

// --- 恢复可操作学生的老板或员工账号 ---
func (data *store) requireOperator(requestContext context.Context, transaction pgx.Tx, actorID string) (currentActor, error) {
	actor := currentActor{id: actorID}
	var state string
	var mustChangePassword bool
	queryError := transaction.QueryRow(requestContext, `SELECT role, state, staff_profile_id, must_change_password FROM accounts WHERE id = $1 FOR UPDATE`, actorID).Scan(&actor.role, &state, &actor.staffProfileID, &mustChangePassword)
	if queryError != nil || state != "active" || mustChangePassword || (actor.role != "owner" && actor.role != "staff") || (actor.role == "staff" && actor.staffProfileID == nil) {
		return currentActor{}, ErrForbidden
	}
	return actor, nil
}

// --- 锁定当前账号可见的学生，统一隐藏未知与范围外对象 ---
func (data *store) lockScopedStudent(requestContext context.Context, transaction pgx.Tx, actor currentActor, studentID string) error {
	var foundID string
	queryError := transaction.QueryRow(requestContext, `SELECT student.id FROM students AS student WHERE student.id = $1 AND ($2::text = 'owner' OR EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $3 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $3 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id))) FOR UPDATE`, studentID, actor.role, actor.staffProfileID).Scan(&foundID)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if queryError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 返回稳定学生身份列表，供一次老板全量规则扫描 ---
func (data *store) listStudentIDs(requestContext context.Context, transaction pgx.Tx) ([]string, error) {
	rows, queryError := transaction.Query(requestContext, `SELECT id FROM students ORDER BY id`)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	studentIDs := make([]string, 0, 32)
	for rows.Next() {
		var studentID string
		if scanError := rows.Scan(&studentID); scanError != nil {
			return nil, ErrWriteFailed
		}
		studentIDs = append(studentIDs, studentID)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return studentIDs, nil
}

// --- 读取确认投诉命令的幂等重放结果 ---
func (data *store) findComplaintReplay(requestContext context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, digest [sha256.Size]byte) (Case, bool, error) {
	var storedDigest []byte
	var caseID *string
	queryError := transaction.QueryRow(requestContext, `SELECT request_digest, resource_id FROM idempotency_records WHERE actor_scope = $1 AND action = 'attention.complaint_confirm' AND idempotency_key = $2 FOR UPDATE`, actorID, idempotencyKey).Scan(&storedDigest, &caseID)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return Case{}, false, nil
	}
	if queryError != nil {
		return Case{}, false, ErrWriteFailed
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return Case{}, true, ErrIdempotencyConflict
	}
	if caseID == nil {
		return Case{}, true, ErrWriteFailed
	}
	attentionCase, caseError := data.getCase(requestContext, transaction, *caseID, false)
	return attentionCase, true, caseError
}

// --- 保存确认投诉的最小事件事实 ---
func (data *store) insertComplaintEvent(requestContext context.Context, transaction pgx.Tx, eventID string, actorID string, studentID string, occurredAt time.Time) error {
	_, writeError := transaction.Exec(requestContext, `INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload, occurred_at) VALUES ($1, $2, 'complaint.confirmed', 'account', $3, '{}'::jsonb, $4)`, eventID, studentID, actorID, occurredAt)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	return nil
}

// --- 保存不含学生正文与投诉内容的成功审计 ---
func (data *store) insertComplaintAudit(requestContext context.Context, transaction pgx.Tx, auditID string, actorID string, caseID string, requestID string) error {
	_, writeError := transaction.Exec(requestContext, `INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata) VALUES ($1, 'account', $2, 'attention.complaint_confirmed', 'attention_case', $3, 'success', $4, '{}'::jsonb)`, auditID, actorID, caseID, requestID)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 把一次确认意图绑定到最终关注事项供安全重放 ---
func (data *store) insertComplaintIdempotency(requestContext context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, digest [sha256.Size]byte, caseID string) error {
	_, writeError := transaction.Exec(requestContext, `INSERT INTO idempotency_records (actor_scope, action, idempotency_key, request_digest, response_code, response_body, resource_id, expires_at) VALUES ($1, 'attention.complaint_confirm', $2, $3, 201, jsonb_build_object('id', $4::text), $4, statement_timestamp() + interval '24 hours')`, actorID, idempotencyKey, digest[:], caseID)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	return nil
}

// --- 锁定评估学生以串行化同聚合证据消费 ---
func (data *store) lockStudent(requestContext context.Context, transaction pgx.Tx, studentID string) error {
	var foundID string
	queryError := transaction.QueryRow(requestContext, `SELECT id FROM students WHERE id = $1 FOR UPDATE`, studentID).Scan(&foundID)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if queryError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 读取一个学生在当前时间点之前的全部规则事实 ---
func (data *store) loadAttentionFacts(requestContext context.Context, transaction pgx.Tx, studentID string, now time.Time) (attentionFacts, error) {
	facts := attentionFacts{}
	var contactID string
	var contactedAt time.Time
	contactError := transaction.QueryRow(requestContext, `SELECT id, contacted_at FROM follow_up_records WHERE student_id = $1 AND valid_contact AND contacted_at <= $2 ORDER BY contacted_at DESC, id DESC LIMIT 1`, studentID, now).Scan(&contactID, &contactedAt)
	if contactError == nil {
		facts.lastValidContact = &evidenceFact{reference: EvidenceRef{ObjectType: "follow_up", ObjectID: contactID}, occurredAt: contactedAt.UTC()}
	} else if !errors.Is(contactError, pgx.ErrNoRows) {
		return attentionFacts{}, ErrWriteFailed
	}
	complaints, complaintError := data.listTimedEvidence(requestContext, transaction, `SELECT id, occurred_at FROM student_events WHERE student_id = $1 AND event_type = 'complaint.confirmed' AND occurred_at <= $2 ORDER BY occurred_at, id`, studentID, now, "student_event")
	if complaintError != nil {
		return attentionFacts{}, complaintError
	}
	facts.complaints = complaints // 投诉事实只携带事件引用与发生时间。
	overdueFollowUps, overdueError := data.listTimedEvidence(requestContext, transaction, `SELECT id, contacted_at FROM follow_up_records WHERE student_id = $1 AND overdue_occurrence AND contacted_at <= $2 ORDER BY contacted_at, id`, studentID, now, "follow_up")
	if overdueError != nil {
		return attentionFacts{}, overdueError
	}
	facts.overdueFollowUps = overdueFollowUps // 每行不同主键天然保证逾期次数不同。
	replyFollowUps, replyError := data.listReplyFacts(requestContext, transaction, studentID, now)
	if replyError != nil {
		return attentionFacts{}, replyError
	}
	facts.replyFollowUps = replyFollowUps // 命令层按线程应用回复重置和双门槛。
	return facts, nil
}

// --- 查询一种按时间排序的最小证据 ---
func (data *store) listTimedEvidence(requestContext context.Context, transaction pgx.Tx, query string, studentID string, now time.Time, objectType string) ([]evidenceFact, error) {
	rows, queryError := transaction.Query(requestContext, query, studentID, now)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	facts := make([]evidenceFact, 0, 8)
	for rows.Next() {
		var objectID string
		var occurredAt time.Time
		if scanError := rows.Scan(&objectID, &occurredAt); scanError != nil {
			return nil, ErrWriteFailed
		}
		facts = append(facts, evidenceFact{reference: EvidenceRef{ObjectType: objectType, ObjectID: objectID}, occurredAt: occurredAt.UTC()})
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return facts, nil
}

// --- 读取按线程和联系时间稳定排序的待回复事实 ---
func (data *store) listReplyFacts(requestContext context.Context, transaction pgx.Tx, studentID string, now time.Time) ([]replyFact, error) {
	rows, queryError := transaction.Query(requestContext, `
		SELECT id, contacted_at, reply_thread_id, student_replied_at
		FROM follow_up_records
		WHERE student_id = $1 AND reply_required AND reply_thread_id IS NOT NULL AND contacted_at <= $2
		ORDER BY reply_thread_id, contacted_at, id`, studentID, now)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	facts := make([]replyFact, 0, 8)
	for rows.Next() {
		var objectID string
		var contactedAt time.Time
		var threadID string
		var repliedAt *time.Time
		if scanError := rows.Scan(&objectID, &contactedAt, &threadID, &repliedAt); scanError != nil {
			return nil, ErrWriteFailed
		}
		facts = append(facts, replyFact{evidenceFact: evidenceFact{reference: EvidenceRef{ObjectType: "follow_up", ObjectID: objectID}, occurredAt: contactedAt.UTC()}, threadID: threadID, repliedAt: utcOptional(repliedAt)})
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return facts, nil
}

// --- 在员工最新数据库范围内计算 48 小时提醒 ---
func (data *store) listStaffReminders(requestContext context.Context, transaction pgx.Tx, actor currentActor, now time.Time) ([]Reminder, error) {
	threshold := now.Add(-staffReminderDelay) // 等于边界时已经到期，查询使用 <=。
	rows, queryError := transaction.Query(requestContext, `
		SELECT student.id, max(followup.contacted_at) AS last_valid_contact_at
		FROM students AS student
		JOIN follow_up_records AS followup ON followup.student_id = student.id
		WHERE student.owner_staff_id = $1 AND followup.valid_contact AND followup.contacted_at <= $2
		GROUP BY student.id
		HAVING max(followup.contacted_at) <= $3
		ORDER BY max(followup.contacted_at), student.id`, actor.staffProfileID, now, threshold)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	reminders := make([]Reminder, 0, 8)
	for rows.Next() {
		reminder := Reminder{}
		if scanError := rows.Scan(&reminder.StudentID, &reminder.LastValidContactAt); scanError != nil {
			return nil, ErrWriteFailed
		}
		reminder.LastValidContactAt = reminder.LastValidContactAt.UTC() // 公开时间统一为 UTC。
		reminder.DueAt = reminder.LastValidContactAt.Add(staffReminderDelay)
		reminders = append(reminders, reminder)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return reminders, nil
}

// --- 返回一个学生的全部历史事项供证据消费判断 ---
func (data *store) listStudentCases(requestContext context.Context, transaction pgx.Tx, studentID string) ([]Case, error) {
	return data.queryCases(requestContext, transaction, `SELECT `+caseProjection+` FROM student_attention_cases WHERE student_id = $1 ORDER BY first_triggered_at, id`, studentID)
}

// --- 返回老板队列中的开放与历史事项 ---
func (data *store) listCases(requestContext context.Context, transaction pgx.Tx) ([]Case, error) {
	return data.queryCases(requestContext, transaction, `SELECT `+caseProjection+` FROM student_attention_cases ORDER BY last_triggered_at DESC, id DESC`)
}

// --- 执行一个固定投影的事项列表查询 ---
func (data *store) queryCases(requestContext context.Context, transaction pgx.Tx, query string, arguments ...any) ([]Case, error) {
	rows, queryError := transaction.Query(requestContext, query, arguments...)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	cases := make([]Case, 0, 8)
	for rows.Next() {
		attentionCase, scanError := scanCase(rows)
		if scanError != nil {
			return nil, ErrWriteFailed
		}
		cases = append(cases, attentionCase)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return cases, nil
}

// --- 插入一个拥有规范证据指纹的新开放事项 ---
func (data *store) insertCase(requestContext context.Context, transaction pgx.Tx, attentionCase Case) (Case, error) {
	evidenceJSON, fingerprint, prepareError := prepareEvidenceStorage(attentionCase.Evidence)
	if prepareError != nil {
		return Case{}, ErrWriteFailed
	}
	row := transaction.QueryRow(requestContext, `
		INSERT INTO student_attention_cases (id, student_id, rule_code, trigger_codes, evidence, evidence_fingerprint, first_triggered_at, last_triggered_at, status)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, 'open')
		RETURNING `+caseProjection,
		attentionCase.ID, attentionCase.StudentID, attentionCase.RuleCode, attentionCase.TriggerCodes,
		evidenceJSON, fingerprint[:], attentionCase.FirstTriggeredAt, attentionCase.LastTriggeredAt)
	created, scanError := scanCase(row)
	if scanError != nil {
		return Case{}, classifyWriteError(scanError)
	}
	return created, nil
}

// --- 用新证据扩展当前开放事项并推进版本 ---
func (data *store) updateOpenCase(requestContext context.Context, transaction pgx.Tx, attentionCase Case, now time.Time) (Case, error) {
	evidenceJSON, fingerprint, prepareError := prepareEvidenceStorage(attentionCase.Evidence)
	if prepareError != nil {
		return Case{}, ErrWriteFailed
	}
	row := transaction.QueryRow(requestContext, `
		UPDATE student_attention_cases
		SET trigger_codes = $2, evidence = $3::jsonb, evidence_fingerprint = $4,
			last_triggered_at = $5, version = version + 1, updated_at = statement_timestamp()
		WHERE id = $1 AND status = 'open' AND version = $6
		RETURNING `+caseProjection,
		attentionCase.ID, attentionCase.TriggerCodes, evidenceJSON, fingerprint[:], now, attentionCase.Version)
	updated, scanError := scanCase(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Case{}, ErrVersionConflict
	}
	if scanError != nil {
		return Case{}, classifyWriteError(scanError)
	}
	return updated, nil
}

// --- 锁定一个事项供老板版本化结论 ---
func (data *store) getCase(requestContext context.Context, transaction pgx.Tx, caseID string, lock bool) (Case, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE"
	}
	row := transaction.QueryRow(requestContext, `SELECT `+caseProjection+` FROM student_attention_cases WHERE id = $1`+lockClause, caseID)
	attentionCase, scanError := scanCase(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Case{}, ErrNotFound
	}
	if scanError != nil {
		return Case{}, ErrWriteFailed
	}
	return attentionCase, nil
}

// --- 条件写入不可变人工结论并推进事项版本 ---
func (data *store) concludeCase(requestContext context.Context, transaction pgx.Tx, actorID string, caseID string, input preparedConclusion, concludedAt time.Time) (Case, error) {
	row := transaction.QueryRow(requestContext, `
		UPDATE student_attention_cases
		SET status = $3, conclusion_code = $4, conclusion_reason = $5,
			concluded_by_account_id = $2, concluded_at = $6,
			version = version + 1, updated_at = statement_timestamp()
		WHERE id = $1 AND status = 'open' AND version = $7
		RETURNING `+caseProjection,
		caseID, actorID, input.status, input.code, input.reason, concludedAt, input.version)
	concluded, scanError := scanCase(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Case{}, ErrVersionConflict
	}
	if scanError != nil {
		return Case{}, classifyWriteError(scanError)
	}
	return concluded, nil
}

// --- 写入不含理由和证据的最小结论审计 ---
func (data *store) insertConclusionAudit(requestContext context.Context, transaction pgx.Tx, auditID string, actorID string, caseID string, requestID string, attentionCase Case) error {
	_, writeError := transaction.Exec(requestContext, `
		INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata)
		VALUES ($1, 'account', $2, 'attention.concluded', 'attention_case', $3, 'success', $4,
			jsonb_build_object('conclusion_code', $5::text, 'version', $6::bigint))`,
		auditID, actorID, caseID, requestID, attentionCase.ConclusionCode, attentionCase.Version)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 编码证据并形成与 JSON 顺序一致的指纹 ---
func prepareEvidenceStorage(evidence []EvidenceRef) (string, [sha256.Size]byte, error) {
	encoded, marshalError := json.Marshal(evidence)
	if marshalError != nil {
		return "", [sha256.Size]byte{}, marshalError
	}
	fingerprint := sha256.Sum256(encoded) // 指纹与实际写入的规范 JSON 完全同源。
	return string(encoded), fingerprint, nil
}

// --- 将数据库约束收敛为稳定关注失败 ---
func classifyWriteError(writeError error) error {
	var postgresError *pgconn.PgError
	if errors.As(writeError, &postgresError) && (postgresError.Code == "23503" || postgresError.Code == "23514") {
		return ErrInvalidInput
	}
	return ErrWriteFailed
}

// --- 扫描固定事项公开投影并严格解码证据数组 ---
func scanCase(row pgx.Row) (Case, error) {
	attentionCase := Case{}
	var evidenceJSON []byte
	scanError := row.Scan(
		&attentionCase.ID, &attentionCase.StudentID, &attentionCase.RuleCode, &attentionCase.TriggerCodes,
		&evidenceJSON, &attentionCase.FirstTriggeredAt, &attentionCase.LastTriggeredAt, &attentionCase.Status,
		&attentionCase.ConclusionCode, &attentionCase.ConclusionReason, &attentionCase.ConcludedByAccountID,
		&attentionCase.ConcludedAt, &attentionCase.Version, &attentionCase.CreatedAt, &attentionCase.UpdatedAt,
	)
	if scanError != nil {
		return Case{}, scanError
	}
	if unmarshalError := json.Unmarshal(evidenceJSON, &attentionCase.Evidence); unmarshalError != nil {
		return Case{}, unmarshalError
	}
	return attentionCase, nil
}

// --- 把可选 PostgreSQL 时间统一为 UTC 副本 ---
func utcOptional(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}
