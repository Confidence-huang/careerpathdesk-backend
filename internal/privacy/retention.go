/*
隐私保留命令：先形成不含学生业务内容的 dry-run 摘要，再由当前老板以相同摘要执行安全删除。
到期只是候选条件；开放任务、活跃邀请或未处理关注事项始终阻断删除。
*/
package privacy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
)

var ErrInvalidDependencies = errors.New("privacy dependencies are invalid")
var ErrForbidden = errors.New("privacy access is forbidden")
var ErrInvalidInput = errors.New("privacy input is invalid")
var ErrNotFound = errors.New("privacy request was not found")
var ErrVersionConflict = errors.New("privacy request version conflicts")
var ErrIdempotencyConflict = errors.New("privacy request idempotency conflicts")
var ErrConfirmationMismatch = errors.New("retention confirmation does not match")
var ErrDeletionBlocked = errors.New("student deletion is blocked")
var ErrWriteFailed = errors.New("privacy write failed")

const BackupRetention = 30 * 24 * time.Hour
const AuditRetention = 365 * 24 * time.Hour

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error)
}

type RetentionSummary struct {
	AsOf              time.Time `json:"as_of"`
	EligibleCount     int       `json:"eligible_count"`
	BlockedCount      int       `json:"blocked_count"`
	ExpiredAuditCount int       `json:"expired_audit_count"`
	AnonymousIDs      []string  `json:"anonymous_ids"`
	Digest            string    `json:"digest"`
	DeletedCount      int       `json:"deleted_count,omitempty"`
	DeletedAuditCount int       `json:"deleted_audit_count,omitempty"`
}

type retentionCandidate struct {
	studentID   string
	anonymousID string
	blocked     bool
}

type expiredAuditSet struct {
	count       int
	fingerprint string
}

type RetentionCommands struct {
	database transactionSource
	now      func() time.Time
}

func NewRetentionCommands(database transactionSource, now func() time.Time) (*RetentionCommands, error) {
	if database == nil || now == nil {
		return nil, ErrInvalidDependencies
	}
	return &RetentionCommands{database: database, now: now}, nil
}

func BackupExpiresAt(createdAt time.Time) time.Time { return createdAt.UTC().Add(BackupRetention) }

func (commands *RetentionCommands) DryRun(ctx context.Context, asOf time.Time) (RetentionSummary, error) {
	if asOf.IsZero() || asOf.After(commands.now().UTC()) {
		return RetentionSummary{}, ErrInvalidInput
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return RetentionSummary{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	candidates, queryError := loadRetentionCandidates(ctx, transaction, asOf.UTC(), false)
	if queryError != nil {
		return RetentionSummary{}, queryError
	}
	expiredAudits, auditQueryError := loadExpiredAuditSet(ctx, transaction, asOf.UTC(), false)
	if auditQueryError != nil {
		return RetentionSummary{}, auditQueryError
	}
	summary := buildSummary(asOf.UTC(), candidates, expiredAudits)
	if commitError := transaction.Commit(ctx); commitError != nil {
		return RetentionSummary{}, ErrWriteFailed
	}
	return summary, nil
}

func (commands *RetentionCommands) Execute(ctx context.Context, actor auth.Account, asOf time.Time, digest string) (RetentionSummary, error) {
	if !eligibleOwner(actor) {
		return RetentionSummary{}, ErrForbidden
	}
	decodedDigest, decodeError := hex.DecodeString(digest)
	if asOf.IsZero() || asOf.After(commands.now().UTC()) || decodeError != nil || len(decodedDigest) != sha256.Size {
		return RetentionSummary{}, ErrConfirmationMismatch
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return RetentionSummary{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if actorError := requireCurrentActor(ctx, transaction, actor.ID, "owner"); actorError != nil {
		return RetentionSummary{}, actorError
	}
	candidates, queryError := loadRetentionCandidates(ctx, transaction, asOf.UTC(), true)
	if queryError != nil {
		return RetentionSummary{}, queryError
	}
	expiredAudits, auditQueryError := loadExpiredAuditSet(ctx, transaction, asOf.UTC(), true)
	if auditQueryError != nil {
		return RetentionSummary{}, auditQueryError
	}
	summary := buildSummary(asOf.UTC(), candidates, expiredAudits)
	if !constantTextEqual(summary.Digest, strings.ToLower(digest)) {
		return RetentionSummary{}, ErrConfirmationMismatch
	}
	for _, candidate := range candidates {
		if candidate.blocked {
			continue
		}
		if deleteError := safelyDeleteStudent(ctx, transaction, candidate.studentID, candidate.anonymousID, commands.now().UTC()); deleteError != nil {
			return RetentionSummary{}, deleteError
		}
		summary.DeletedCount++
	}
	deletedAuditCount, auditDeleteError := deleteExpiredAudits(ctx, transaction, asOf.UTC())
	if auditDeleteError != nil || deletedAuditCount != summary.ExpiredAuditCount {
		return RetentionSummary{}, ErrWriteFailed
	}
	summary.DeletedAuditCount = deletedAuditCount
	if commitError := transaction.Commit(ctx); commitError != nil {
		return RetentionSummary{}, ErrWriteFailed
	}
	return summary, nil
}

func loadRetentionCandidates(ctx context.Context, transaction pgx.Tx, asOf time.Time, lock bool) ([]retentionCandidate, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE OF student"
	}
	rows, queryError := transaction.Query(ctx, `
		SELECT student.id,
			EXISTS (SELECT 1 FROM student_invitations invitation WHERE invitation.student_id = student.id AND invitation.state IN ('pending', 'exchanged'))
			OR EXISTS (SELECT 1 FROM student_attention_cases attention WHERE attention.student_id = student.id AND attention.status = 'open') AS blocked
		FROM students student
		WHERE student.closed_at IS NOT NULL AND student.retention_due_at <= $1
		ORDER BY student.id`+lockClause, asOf)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	candidates := make([]retentionCandidate, 0)
	for rows.Next() {
		candidate := retentionCandidate{}
		if scanError := rows.Scan(&candidate.studentID, &candidate.blocked); scanError != nil {
			return nil, ErrWriteFailed
		}
		candidate.anonymousID = anonymousSubjectID(candidate.studentID)
		candidates = append(candidates, candidate)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return candidates, nil
}

func loadExpiredAuditSet(ctx context.Context, transaction pgx.Tx, asOf time.Time, lock bool) (expiredAuditSet, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE"
	}
	rows, queryError := transaction.Query(ctx, `
		SELECT id, occurred_at
		FROM audit_events
		WHERE occurred_at <= $1
		ORDER BY id`+lockClause, asOf.Add(-AuditRetention))
	if queryError != nil {
		return expiredAuditSet{}, ErrWriteFailed
	}
	defer rows.Close()

	fingerprint := sha256.New()
	auditSet := expiredAuditSet{}
	for rows.Next() {
		var id string
		var occurredAt time.Time
		if scanError := rows.Scan(&id, &occurredAt); scanError != nil {
			return expiredAuditSet{}, ErrWriteFailed
		}
		_, _ = fingerprint.Write([]byte(id))
		_, _ = fingerprint.Write([]byte{'\x00'})
		_, _ = fingerprint.Write([]byte(occurredAt.UTC().Format(time.RFC3339Nano)))
		_, _ = fingerprint.Write([]byte{'\x00'})
		auditSet.count++
	}
	if rows.Err() != nil {
		return expiredAuditSet{}, ErrWriteFailed
	}
	auditSet.fingerprint = hex.EncodeToString(fingerprint.Sum(nil))
	return auditSet, nil
}

func deleteExpiredAudits(ctx context.Context, transaction pgx.Tx, asOf time.Time) (int, error) {
	commandTag, deleteError := transaction.Exec(ctx, `DELETE FROM audit_events WHERE occurred_at <= $1`, asOf.Add(-AuditRetention))
	if deleteError != nil {
		return 0, ErrWriteFailed
	}
	return int(commandTag.RowsAffected()), nil
}

func buildSummary(asOf time.Time, candidates []retentionCandidate, expiredAudits expiredAuditSet) RetentionSummary {
	summary := RetentionSummary{AsOf: asOf.UTC(), ExpiredAuditCount: expiredAudits.count, AnonymousIDs: make([]string, 0, len(candidates))}
	for _, candidate := range candidates {
		if candidate.blocked {
			summary.BlockedCount++
			continue
		}
		summary.AnonymousIDs = append(summary.AnonymousIDs, candidate.anonymousID)
	}
	sort.Strings(summary.AnonymousIDs)
	summary.EligibleCount = len(summary.AnonymousIDs)
	digestInput := summary.AsOf.Format(time.RFC3339Nano) + "\x00" + strings.Join(summary.AnonymousIDs, "\x00") + "\x00" + strconv.Itoa(summary.BlockedCount) + "\x00" + strconv.Itoa(summary.ExpiredAuditCount) + "\x00" + expiredAudits.fingerprint
	digest := sha256.Sum256([]byte(digestInput))
	summary.Digest = hex.EncodeToString(digest[:])
	return summary
}

func anonymousSubjectID(studentID string) string {
	digest := sha256.Sum256([]byte("careerpathdesk-retention-subject\x00" + studentID))
	return "ANON-" + hex.EncodeToString(digest[:])
}

func safelyDeleteStudent(ctx context.Context, transaction pgx.Tx, studentID string, anonymousID string, occurredAt time.Time) error {
	var stillBlocked bool
	if queryError := transaction.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM student_invitations WHERE student_id = $1 AND state IN ('pending', 'exchanged'))
		OR EXISTS (SELECT 1 FROM student_attention_cases WHERE student_id = $1 AND status = 'open')`, studentID).Scan(&stillBlocked); queryError != nil {
		return ErrWriteFailed
	}
	if stillBlocked {
		return ErrDeletionBlocked
	}
	if _, deleteError := transaction.Exec(ctx, `
		DELETE FROM idempotency_records WHERE resource_id = $1
			OR resource_id IN (SELECT id FROM coaching_tasks WHERE student_id = $1)
			OR resource_id IN (SELECT id FROM follow_up_records WHERE student_id = $1)
			OR resource_id IN (SELECT id FROM student_events WHERE student_id = $1)
			OR resource_id IN (SELECT id FROM student_invitations WHERE student_id = $1)
			OR resource_id IN (SELECT id FROM assessments WHERE student_id = $1)
			OR resource_id IN (SELECT id FROM student_status_history WHERE student_id = $1)
			OR resource_id IN (SELECT id FROM student_attention_cases WHERE student_id = $1)
			OR resource_id IN (SELECT id FROM privacy_requests WHERE student_id = $1)`, studentID); deleteError != nil {
		return ErrWriteFailed
	}
	if _, updateError := transaction.Exec(ctx, `
		UPDATE audit_events SET object_type = 'deleted_student', object_id = $2, metadata = '{}'::jsonb WHERE object_id = $1
			OR object_id IN (SELECT id FROM coaching_tasks WHERE student_id = $1)
			OR object_id IN (SELECT id FROM follow_up_records WHERE student_id = $1)
			OR object_id IN (SELECT id FROM student_events WHERE student_id = $1)
			OR object_id IN (SELECT id FROM student_invitations WHERE student_id = $1)
			OR object_id IN (SELECT id FROM assessments WHERE student_id = $1)
			OR object_id IN (SELECT id FROM student_status_history WHERE student_id = $1)
			OR object_id IN (SELECT id FROM student_attention_cases WHERE student_id = $1)
			OR object_id IN (SELECT id FROM privacy_requests WHERE student_id = $1)`, studentID, anonymousID); updateError != nil {
		return ErrWriteFailed
	}
	if _, deleteError := transaction.Exec(ctx, `DELETE FROM assessments WHERE student_id = $1`, studentID); deleteError != nil {
		return ErrWriteFailed
	}
	if _, deleteError := transaction.Exec(ctx, `DELETE FROM student_status_history WHERE student_id = $1 AND reverses_status_change_id IS NOT NULL`, studentID); deleteError != nil {
		return ErrWriteFailed
	}
	if _, deleteError := transaction.Exec(ctx, `DELETE FROM student_status_history WHERE student_id = $1`, studentID); deleteError != nil {
		return ErrWriteFailed
	}
	commandTag, deleteError := transaction.Exec(ctx, `DELETE FROM students WHERE id = $1`, studentID)
	if deleteError != nil || commandTag.RowsAffected() != 1 {
		return ErrWriteFailed
	}
	auditID := "AU-" + anonymousID[len("ANON-"):]
	if _, auditError := transaction.Exec(ctx, `
		INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at)
		VALUES ($1, 'system', 'retention-maintenance', 'student.retention_deleted', 'deleted_student', $2, 'success', 'retention-maintenance', '{}'::jsonb, $3)`, auditID, anonymousID, occurredAt); auditError != nil {
		return ErrWriteFailed
	}
	return nil
}

func requireCurrentActor(ctx context.Context, transaction pgx.Tx, accountID string, requiredRole string) error {
	var role, state string
	var mustChange bool
	queryError := transaction.QueryRow(ctx, `SELECT role, state, must_change_password FROM accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&role, &state, &mustChange)
	if queryError != nil || role != requiredRole || state != "active" || mustChange {
		return ErrForbidden
	}
	return nil
}

func eligibleOwner(actor auth.Account) bool {
	return actor.ID != "" && actor.Role == "owner" && actor.State == "active" && !actor.MustChangePassword
}

func constantTextEqual(left string, right string) bool {
	leftDigest := sha256.Sum256([]byte(left))
	rightDigest := sha256.Sum256([]byte(right))
	return leftDigest == rightDigest
}
