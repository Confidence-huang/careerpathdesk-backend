/*
跟进 PostgreSQL 数据包：执行逐人账号复核、学生继承范围、派生重建和最小证据 SQL。
所有方法都由 Commands 放进同一事务；本文件不提交事务，也不向审计复制下一步正文。
*/
package followups

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type store struct{ database transactionSource }

type currentActor struct {
	id             string
	role           string
	staffProfileID *string
}

const followUpProjection = `followup.id, followup.student_id, followup.contacted_at, followup.channel, followup.content, followup.valid_contact, followup.reply_required, followup.reply_thread_id, followup.student_replied_at, followup.overdue_occurrence, followup.next_action, followup.next_follow_up_at, followup.next_staff_id, next_staff.display_name, followup.created_by, creator.display_name, followup.version, followup.created_at, followup.updated_at`
const followUpWriteProjection = `id, student_id, contacted_at, channel, content, valid_contact, reply_required, reply_thread_id, student_replied_at, overdue_occurrence, next_action, next_follow_up_at, next_staff_id, NULL::text, created_by, ''::text, version, created_at, updated_at`

func (data *store) requireActor(ctx context.Context, transaction pgx.Tx, actorID string) (currentActor, error) {
	actor := currentActor{id: actorID}
	var state string
	var mustChangePassword bool
	queryError := transaction.QueryRow(ctx, `SELECT role, state, staff_profile_id, must_change_password FROM accounts WHERE id = $1 FOR UPDATE`, actorID).Scan(&actor.role, &state, &actor.staffProfileID, &mustChangePassword)
	if queryError != nil || state != "active" || mustChangePassword || (actor.role != "owner" && actor.role != "staff") || (actor.role == "staff" && actor.staffProfileID == nil) {
		return currentActor{}, ErrForbidden
	}
	return actor, nil
}

// getScopedStudent 同时隐藏未知学生和员工范围外学生；写命令锁定聚合根。
func (data *store) getScopedStudent(ctx context.Context, transaction pgx.Tx, actor currentActor, studentID string, lock bool) (int64, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE"
	}
	var version int64
	queryError := transaction.QueryRow(ctx, `SELECT student.version FROM students AS student WHERE student.id = $1 AND ($2::text = 'owner' OR EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $3 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $3 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))`+lockClause, studentID, actor.role, actor.staffProfileID).Scan(&version)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if queryError != nil {
		return 0, ErrWriteFailed
	}
	return version, nil
}

func (data *store) list(ctx context.Context, transaction pgx.Tx, studentID string) ([]FollowUp, error) {
	rows, queryError := transaction.Query(ctx, `SELECT `+followUpProjection+` FROM follow_up_records AS followup JOIN accounts AS creator ON creator.id = followup.created_by LEFT JOIN staff_profiles AS next_staff ON next_staff.id = followup.next_staff_id WHERE followup.student_id = $1 ORDER BY followup.contacted_at DESC, followup.id DESC`, studentID)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	items := make([]FollowUp, 0, 8)
	for rows.Next() {
		item, scanError := scanFollowUp(rows)
		if scanError != nil {
			return nil, ErrWriteFailed
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return items, nil
}

func (data *store) findCreateReplay(ctx context.Context, transaction pgx.Tx, actor currentActor, idempotencyKey string, digest [32]byte) (FollowUp, bool, error) {
	var storedDigest []byte
	var resourceID *string
	queryError := transaction.QueryRow(ctx, `SELECT request_digest, resource_id FROM idempotency_records WHERE actor_scope = $1 AND action = 'follow_up.create' AND idempotency_key = $2 FOR UPDATE`, actor.id, idempotencyKey).Scan(&storedDigest, &resourceID)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return FollowUp{}, false, nil
	}
	if queryError != nil {
		return FollowUp{}, false, ErrWriteFailed
	}
	if !equalDigest(storedDigest, digest[:]) {
		return FollowUp{}, true, ErrIdempotencyConflict
	}
	if resourceID == nil {
		return FollowUp{}, true, ErrWriteFailed
	}
	item, itemError := data.getScoped(ctx, transaction, actor, *resourceID, false)
	return item, true, itemError
}

func (data *store) insert(ctx context.Context, transaction pgx.Tx, actorID string, followUpID string, studentID string, input preparedFollowUp) (FollowUp, error) {
	row := transaction.QueryRow(ctx, `
		INSERT INTO follow_up_records (id, student_id, contacted_at, channel, content, valid_contact, reply_required, reply_thread_id, student_replied_at, overdue_occurrence, next_action, next_follow_up_at, next_staff_id, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
		RETURNING `+followUpWriteProjection,
		followUpID, studentID, input.contactedAt, input.channel, input.content, input.validContact, input.replyRequired,
		input.replyThreadID, input.studentRepliedAt, input.overdueOccurrence, input.nextAction, input.nextFollowUpAt, input.nextStaffID, actorID)
	item, scanError := scanFollowUp(row)
	if scanError != nil {
		return FollowUp{}, classifyWriteError(scanError)
	}
	return item, nil
}

func (data *store) getScoped(ctx context.Context, transaction pgx.Tx, actor currentActor, followUpID string, lock bool) (FollowUp, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE OF student, followup"
	}
	row := transaction.QueryRow(ctx, `
		SELECT `+followUpProjection+`
		FROM follow_up_records AS followup
		JOIN students AS student ON student.id = followup.student_id
		JOIN accounts AS creator ON creator.id = followup.created_by
		LEFT JOIN staff_profiles AS next_staff ON next_staff.id = followup.next_staff_id
		WHERE followup.id = $1 AND ($2::text = 'owner' OR EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $3 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $3 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))`+lockClause,
		followUpID, actor.role, actor.staffProfileID)
	item, scanError := scanFollowUp(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return FollowUp{}, ErrNotFound
	}
	if scanError != nil {
		return FollowUp{}, ErrWriteFailed
	}
	return item, nil
}

func (data *store) update(ctx context.Context, transaction pgx.Tx, actorID string, followUpID string, input preparedFollowUp) (FollowUp, error) {
	row := transaction.QueryRow(ctx, `
		UPDATE follow_up_records
		SET contacted_at = $3, channel = $4, content = $5, valid_contact = $6, reply_required = $7,
			reply_thread_id = $8, student_replied_at = $9, overdue_occurrence = $10,
			next_action = $11, next_follow_up_at = $12, next_staff_id = $13, version = version + 1,
			updated_by = $2, updated_at = statement_timestamp()
		WHERE id = $1 AND version = $14
		RETURNING `+followUpWriteProjection,
		followUpID, actorID, input.contactedAt, input.channel, input.content, input.validContact, input.replyRequired,
		input.replyThreadID, input.studentRepliedAt, input.overdueOccurrence, input.nextAction, input.nextFollowUpAt, input.nextStaffID, input.version)
	item, scanError := scanFollowUp(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return FollowUp{}, ErrVersionConflict
	}
	if scanError != nil {
		return FollowUp{}, classifyWriteError(scanError)
	}
	return item, nil
}

func (data *store) requireActiveStudentStaff(ctx context.Context, transaction pgx.Tx, studentID string, staffID string) error {
	var exists bool
	if queryError := transaction.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM student_staff_assignments AS assignment JOIN staff_profiles AS staff ON staff.id = assignment.staff_profile_id WHERE assignment.student_id = $1 AND assignment.staff_profile_id = $2 AND assignment.ended_at IS NULL AND staff.state = 'active')`, studentID, staffID).Scan(&exists); queryError != nil {
		return ErrWriteFailed
	}
	if !exists {
		return ErrInvalidInput
	}
	return nil
}

func (data *store) delete(ctx context.Context, transaction pgx.Tx, followUpID string, version int64) error {
	commandTag, deleteError := transaction.Exec(ctx, `DELETE FROM follow_up_records WHERE id = $1 AND version = $2`, followUpID, version)
	if deleteError != nil {
		return ErrWriteFailed
	}
	if commandTag.RowsAffected() != 1 {
		return ErrVersionConflict
	}
	return nil
}

// rebuildStudentDerivation 从同一条最新联系记录复制下一步与时间，并推进学生版本。
func (data *store) rebuildStudentDerivation(ctx context.Context, transaction pgx.Tx, actorID string, studentID string) (int64, error) {
	var version int64
	queryError := transaction.QueryRow(ctx, `
		UPDATE students
		SET next_action = latest.next_action, next_follow_up_at = latest.next_follow_up_at,
			version = students.version + 1, updated_by = $2, updated_at = statement_timestamp()
		FROM (SELECT
			(SELECT next_action FROM follow_up_records WHERE student_id = $1 ORDER BY contacted_at DESC, id DESC LIMIT 1) AS next_action,
			(SELECT next_follow_up_at FROM follow_up_records WHERE student_id = $1 ORDER BY contacted_at DESC, id DESC LIMIT 1) AS next_follow_up_at
		) AS latest
		WHERE students.id = $1
		RETURNING students.version`, studentID, actorID).Scan(&version)
	if queryError != nil {
		return 0, ErrWriteFailed
	}
	return version, nil
}

func (data *store) insertEvent(ctx context.Context, transaction pgx.Tx, eventID string, actorID string, eventType string, item FollowUp, occurredAt time.Time) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload, occurred_at)
		VALUES ($1, $2, $3, 'account', $4, jsonb_build_object('follow_up_id', $5::text, 'valid_contact', $6::boolean, 'reply_required', $7::boolean), $8)`,
		eventID, item.StudentID, eventType, actorID, item.ID, item.ValidContact, item.ReplyRequired, occurredAt)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

func (data *store) insertAudit(ctx context.Context, transaction pgx.Tx, auditID string, actorID string, action string, followUpID string, requestID string, version int64, studentVersion int64) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata)
		VALUES ($1, 'account', $2, $3, 'follow_up', $4, 'success', $5, jsonb_build_object('version', $6::bigint, 'student_version', $7::bigint))`,
		auditID, actorID, action, followUpID, requestID, version, studentVersion)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

func (data *store) insertCreateIdempotency(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, digest [32]byte, followUpID string) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO idempotency_records (actor_scope, action, idempotency_key, request_digest, response_code, response_body, resource_id, expires_at)
		VALUES ($1, 'follow_up.create', $2, $3, 201, jsonb_build_object('id', $4::text), $4, statement_timestamp() + interval '24 hours')`,
		actorID, idempotencyKey, digest[:], followUpID)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	return nil
}

func classifyWriteError(writeError error) error {
	var postgresError *pgconn.PgError
	if errors.As(writeError, &postgresError) {
		if postgresError.Code == "23505" {
			return ErrIdempotencyConflict
		}
		if postgresError.Code == "23503" || postgresError.Code == "23514" {
			return ErrInvalidInput
		}
	}
	return ErrWriteFailed
}

func equalDigest(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func scanFollowUp(row pgx.Row) (FollowUp, error) {
	item := FollowUp{}
	scanError := row.Scan(
		&item.ID, &item.StudentID, &item.ContactedAt, &item.Channel, &item.Content, &item.ValidContact,
		&item.ReplyRequired, &item.ReplyThreadID, &item.StudentRepliedAt, &item.OverdueOccurrence,
		&item.NextAction, &item.NextFollowUpAt, &item.NextStaffID, &item.NextStaffName,
		&item.CreatedByAccountID, &item.CreatedByName, &item.Version, &item.CreatedAt, &item.UpdatedAt,
	)
	return item, scanError
}
