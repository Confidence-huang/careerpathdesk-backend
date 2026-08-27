/*
邀请 PostgreSQL 数据包：执行逐人账号复核、学生继承范围、摘要状态迁移与最小证据 SQL。
所有方法都由 Commands 放进同一事务；本文件不提交事务，也不接触任何原始秘密。
*/
package invitations

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

type invitationRecord struct {
	ID                string
	StudentID         string
	AssessmentVersion string
	ExpiresAt         time.Time
}

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

// getScopedStudent 先锁住聚合根，使补发、兑换和负责人变化按同一学生串行化。
func (data *store) getScopedStudent(ctx context.Context, transaction pgx.Tx, actor currentActor, studentID string) (int64, error) {
	var version int64
	queryError := transaction.QueryRow(ctx, `SELECT student.version FROM students AS student WHERE student.id = $1 AND ($2::text = 'owner' OR EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $3 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $3 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id))) FOR UPDATE`, studentID, actor.role, actor.staffProfileID).Scan(&version)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if queryError != nil {
		return 0, ErrWriteFailed
	}
	return version, nil
}

func (data *store) requireActiveQuestionnaire(ctx context.Context, transaction pgx.Tx, version string) error {
	var activeVersion string
	queryError := transaction.QueryRow(ctx, `SELECT version FROM assessment_questionnaires WHERE version = $1 AND is_active`, version).Scan(&activeVersion)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return ErrInvalidInput
	}
	if queryError != nil {
		return ErrWriteFailed
	}
	return nil
}

// requireUnusedIssueKey 防止同一一次性响应意图重复建立资源；原始秘密永不缓存，因此重放明确冲突。
func (data *store) requireUnusedIssueKey(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string) error {
	var storedDigest []byte
	queryError := transaction.QueryRow(ctx, `SELECT request_digest FROM idempotency_records WHERE actor_scope = $1 AND action = 'invitation.issue' AND idempotency_key = $2 FOR UPDATE`, actorID, idempotencyKey).Scan(&storedDigest)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return nil
	}
	if queryError != nil {
		return ErrWriteFailed
	}
	return ErrIdempotencyConflict
}

func (data *store) replaceLive(ctx context.Context, transaction pgx.Tx, studentID string, now time.Time) error {
	_, updateError := transaction.Exec(ctx, `
		UPDATE student_invitations
		SET state = 'replaced', invite_digest = NULL, restricted_session_id = NULL,
			restricted_session_digest = NULL, restricted_session_expires_at = NULL,
			exchanged_at = NULL, completed_at = NULL, revoked_at = NULL,
			replaced_at = $2, revoke_reason = NULL, version = version + 1, updated_at = $2
		WHERE student_id = $1 AND state IN ('pending', 'exchanged')`, studentID, now)
	if updateError != nil {
		return ErrWriteFailed
	}
	return nil
}

func (data *store) insertInvitation(ctx context.Context, transaction pgx.Tx, invitationID string, studentID string, actorID string, assessmentVersion string, studentVersion int64, digest [32]byte, expiresAt time.Time, now time.Time) error {
	_, insertError := transaction.Exec(ctx, `
		INSERT INTO student_invitations (
			id, student_id, issued_by_account_id, assessment_version, student_version,
			state, invite_digest, expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $8)`,
		invitationID, studentID, actorID, assessmentVersion, studentVersion, digest[:], expiresAt, now)
	if insertError != nil {
		return classifyInvitationWriteError(insertError)
	}
	return nil
}

func (data *store) getScopedLiveInvitation(ctx context.Context, transaction pgx.Tx, actor currentActor, invitationID string) (invitationRecord, error) {
	item := invitationRecord{}
	queryError := transaction.QueryRow(ctx, `
		SELECT invitation.id, invitation.student_id, invitation.assessment_version, invitation.expires_at
		FROM student_invitations AS invitation
		JOIN students AS student ON student.id = invitation.student_id
		WHERE invitation.id = $1 AND invitation.state IN ('pending', 'exchanged')
			AND ($2::text = 'owner' OR EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $3 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $3 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))
		FOR UPDATE OF invitation, student`, invitationID, actor.role, actor.staffProfileID).Scan(&item.ID, &item.StudentID, &item.AssessmentVersion, &item.ExpiresAt)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return invitationRecord{}, ErrNotFound
	}
	if queryError != nil {
		return invitationRecord{}, ErrWriteFailed
	}
	return item, nil
}

func (data *store) revoke(ctx context.Context, transaction pgx.Tx, invitationID string, now time.Time) error {
	commandTag, updateError := transaction.Exec(ctx, `
		UPDATE student_invitations
		SET state = 'revoked', invite_digest = NULL, restricted_session_digest = NULL,
			revoked_at = $2, revoke_reason = 'manual', version = version + 1, updated_at = $2
		WHERE id = $1 AND state IN ('pending', 'exchanged')`, invitationID, now)
	if updateError != nil || commandTag.RowsAffected() != 1 {
		return ErrWriteFailed
	}
	return nil
}

// getExchangeable 把所有公开无效原因收束为无行，同时锁定邀请、学生和签发账号快照。
func (data *store) getExchangeable(ctx context.Context, transaction pgx.Tx, digest [32]byte, now time.Time) (invitationRecord, error) {
	item := invitationRecord{}
	queryError := transaction.QueryRow(ctx, `
		SELECT invitation.id, invitation.student_id, invitation.assessment_version, invitation.expires_at
		FROM student_invitations AS invitation
		JOIN students AS student ON student.id = invitation.student_id
		JOIN accounts AS issuer ON issuer.id = invitation.issued_by_account_id
		JOIN assessment_questionnaires AS questionnaire ON questionnaire.version = invitation.assessment_version
		WHERE invitation.invite_digest = $1 AND invitation.state = 'pending'
			AND invitation.expires_at > $2 AND questionnaire.is_active
			AND issuer.state = 'active' AND NOT issuer.must_change_password
			AND (issuer.role = 'owner' OR (issuer.role = 'staff' AND issuer.staff_profile_id IS NOT NULL AND (EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = issuer.staff_profile_id AND assignment.ended_at IS NULL) OR (student.owner_staff_id = issuer.staff_profile_id AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))))
		FOR UPDATE OF invitation, student, issuer`, digest[:], now).Scan(&item.ID, &item.StudentID, &item.AssessmentVersion, &item.ExpiresAt)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return invitationRecord{}, ErrInvalidInvitation
	}
	if queryError != nil {
		return invitationRecord{}, ErrInvalidInvitation
	}
	return item, nil
}

func (data *store) exchange(ctx context.Context, transaction pgx.Tx, invitationID string, sessionID string, digest [32]byte, sessionExpiresAt time.Time, now time.Time) error {
	commandTag, updateError := transaction.Exec(ctx, `
		UPDATE student_invitations
		SET state = 'exchanged', invite_digest = NULL, restricted_session_id = $2,
			restricted_session_digest = $3, restricted_session_expires_at = $4,
			exchanged_at = $5, version = version + 1, updated_at = $5
		WHERE id = $1 AND state = 'pending'`, invitationID, sessionID, digest[:], sessionExpiresAt, now)
	if updateError != nil || commandTag.RowsAffected() != 1 {
		return ErrInvalidInvitation
	}
	return nil
}

// resolve 返回受限投影前仍锁定并重验动态授权，避免与撤销或负责人转移交错。
func (data *store) resolve(ctx context.Context, transaction pgx.Tx, sessionID string, digest [32]byte, now time.Time) (CapabilityScope, error) {
	scope := CapabilityScope{}
	queryError := transaction.QueryRow(ctx, `
		SELECT invitation.student_id, invitation.assessment_version, invitation.id
		FROM student_invitations AS invitation
		JOIN students AS student ON student.id = invitation.student_id
		JOIN accounts AS issuer ON issuer.id = invitation.issued_by_account_id
		JOIN assessment_questionnaires AS questionnaire ON questionnaire.version = invitation.assessment_version
		WHERE invitation.restricted_session_id = $1 AND invitation.restricted_session_digest = $2
			AND invitation.state = 'exchanged' AND invitation.restricted_session_expires_at > $3
			AND invitation.expires_at > $3 AND questionnaire.is_active
			AND issuer.state = 'active' AND NOT issuer.must_change_password
			AND (issuer.role = 'owner' OR (issuer.role = 'staff' AND issuer.staff_profile_id IS NOT NULL AND (EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = issuer.staff_profile_id AND assignment.ended_at IS NULL) OR (student.owner_staff_id = issuer.staff_profile_id AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))))
		FOR UPDATE OF invitation, student, issuer`, sessionID, digest[:], now).Scan(&scope.StudentID, &scope.AssessmentVersion, &scope.InvitationID)
	if queryError != nil {
		return CapabilityScope{}, ErrInvalidCapability
	}
	return scope, nil
}

func (data *store) insertAccountEvent(ctx context.Context, transaction pgx.Tx, eventID string, studentID string, actorID string, eventType string, invitationID string, assessmentVersion string, reason string, occurredAt time.Time) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload, occurred_at)
		VALUES ($1, $2, $3, 'account', $4,
			jsonb_strip_nulls(jsonb_build_object('invitation_id', $5::text, 'assessment_version', $6::text, 'reason', NULLIF($7::text, ''))), $8)`,
		eventID, studentID, eventType, actorID, invitationID, assessmentVersion, reason, occurredAt)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

func (data *store) insertInvitationEvent(ctx context.Context, transaction pgx.Tx, eventID string, studentID string, sessionID string, eventType string, invitationID string, assessmentVersion string, occurredAt time.Time) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload, occurred_at)
		VALUES ($1, $2, $3, 'invitation', $4, jsonb_build_object('invitation_id', $5::text, 'assessment_version', $6::text), $7)`,
		eventID, studentID, eventType, sessionID, invitationID, assessmentVersion, occurredAt)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

func (data *store) insertAudit(ctx context.Context, transaction pgx.Tx, auditID string, actorKind string, actorID string, action string, invitationID string, requestID string, assessmentVersion string, reason string) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata)
		VALUES ($1, $2, $3, $4, 'invitation', $5, 'success', $6,
			jsonb_strip_nulls(jsonb_build_object('assessment_version', $7::text, 'reason', NULLIF($8::text, ''))))`,
		auditID, actorKind, actorID, action, invitationID, requestID, assessmentVersion, reason)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

func (data *store) insertIssueIdempotency(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, digest [32]byte, invitationID string, now time.Time) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO idempotency_records (
			actor_scope, action, idempotency_key, request_digest, response_code,
			response_body, resource_id, created_at, expires_at
		) VALUES ($1, 'invitation.issue', $2, $3, 201, jsonb_build_object('id', $4::text), $4::text, $5::timestamptz, $5::timestamptz + interval '24 hours')`,
		actorID, idempotencyKey, digest[:], invitationID, now)
	if writeError != nil {
		return classifyIdempotencyWriteError(writeError)
	}
	return nil
}

func classifyInvitationWriteError(writeError error) error {
	var postgresError *pgconn.PgError
	if errors.As(writeError, &postgresError) && (postgresError.Code == "23503" || postgresError.Code == "23514") {
		return ErrInvalidInput
	}
	return ErrWriteFailed
}

func classifyIdempotencyWriteError(writeError error) error {
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
