/* 隐私请求命令：员工可在本人学生范围登记，老板统一查看并作出完成或分类拒绝决定。 */
package privacy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
)

type PrivacyRequest struct {
	ID                  string     `json:"id"`
	StudentID           string     `json:"student_id"`
	RequestType         string     `json:"request_type"`
	Status              string     `json:"status"`
	ReceivedByAccountID string     `json:"received_by_account_id"`
	ReasonCategory      *string    `json:"resolution_reason_category"`
	Note                *string    `json:"resolution_note"`
	CompletedAt         *time.Time `json:"completed_at"`
	Version             int64      `json:"version"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type CreateRequestInput struct {
	StudentID   string
	RequestType string
}

type CompleteRequestInput struct {
	Decision       string
	ReasonCategory string
	Note           string
	Version        int64
}

type RequestCommands struct {
	database    transactionSource
	now         func() time.Time
	newIdentity func(string) (string, error)
}

func NewRequestCommands(database transactionSource, now func() time.Time, newIdentity func(string) (string, error)) (*RequestCommands, error) {
	if database == nil || now == nil || newIdentity == nil {
		return nil, ErrInvalidDependencies
	}
	return &RequestCommands{database: database, now: now, newIdentity: newIdentity}, nil
}

func (commands *RequestCommands) Create(ctx context.Context, actor auth.Account, requestID string, idempotencyKey string, input CreateRequestInput) (PrivacyRequest, error) {
	if !eligibleOperator(actor) {
		return PrivacyRequest{}, ErrForbidden
	}
	if !validRequestID(requestID) || !validText(idempotencyKey, 16, 128) || !validStudentID(input.StudentID) || !validRequestType(input.RequestType) {
		return PrivacyRequest{}, ErrInvalidInput
	}
	digestBody, marshalError := json.Marshal(input)
	if marshalError != nil {
		return PrivacyRequest{}, ErrWriteFailed
	}
	requestDigest := sha256.Sum256(digestBody)
	privacyRequestID, identityError := commands.newIdentity("PR")
	auditID, auditIdentityError := commands.newIdentity("AU")
	if identityError != nil || auditIdentityError != nil || !validPrivacyRequestID(privacyRequestID) || !validAuditID(auditID) {
		return PrivacyRequest{}, ErrWriteFailed
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return PrivacyRequest{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, actorError := loadOperator(ctx, transaction, actor.ID)
	if actorError != nil {
		return PrivacyRequest{}, actorError
	}
	if scopeError := requireStudentScope(ctx, transaction, current, input.StudentID); scopeError != nil {
		return PrivacyRequest{}, scopeError
	}
	if replay, found, replayError := findRequestReplay(ctx, transaction, current.id, idempotencyKey, requestDigest); replayError != nil || found {
		if replayError != nil {
			return PrivacyRequest{}, replayError
		}
		if commitError := transaction.Commit(ctx); commitError != nil {
			return PrivacyRequest{}, ErrWriteFailed
		}
		return replay, nil
	}
	createdAt := commands.now().UTC()
	created, insertError := insertPrivacyRequest(ctx, transaction, privacyRequestID, input, current.id, createdAt)
	if insertError != nil {
		return PrivacyRequest{}, insertError
	}
	if auditError := insertRequestAudit(ctx, transaction, auditID, current.id, "privacy_request.created", created.ID, requestID, created.RequestType, "", createdAt); auditError != nil {
		return PrivacyRequest{}, auditError
	}
	if idempotencyError := insertRequestIdempotency(ctx, transaction, current.id, idempotencyKey, requestDigest, created.ID, createdAt); idempotencyError != nil {
		return PrivacyRequest{}, idempotencyError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return PrivacyRequest{}, ErrWriteFailed
	}
	return created, nil
}

func (commands *RequestCommands) List(ctx context.Context, actor auth.Account) ([]PrivacyRequest, error) {
	if !eligibleOwner(actor) {
		return nil, ErrForbidden
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return nil, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if actorError := requireCurrentActor(ctx, transaction, actor.ID, "owner"); actorError != nil {
		return nil, actorError
	}
	rows, queryError := transaction.Query(ctx, `SELECT `+privacyRequestProjection+` FROM privacy_requests ORDER BY created_at, id`)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	requests := make([]PrivacyRequest, 0)
	for rows.Next() {
		request, scanError := scanPrivacyRequest(rows)
		if scanError != nil {
			return nil, ErrWriteFailed
		}
		requests = append(requests, request)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return nil, ErrWriteFailed
	}
	return requests, nil
}

func (commands *RequestCommands) Complete(ctx context.Context, actor auth.Account, requestID string, privacyRequestID string, input CompleteRequestInput) (PrivacyRequest, error) {
	if !eligibleOwner(actor) {
		return PrivacyRequest{}, ErrForbidden
	}
	prepared, prepareError := prepareCompletion(requestID, privacyRequestID, input)
	if prepareError != nil {
		return PrivacyRequest{}, prepareError
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || !validAuditID(auditID) {
		return PrivacyRequest{}, ErrWriteFailed
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return PrivacyRequest{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if actorError := requireCurrentActor(ctx, transaction, actor.ID, "owner"); actorError != nil {
		return PrivacyRequest{}, actorError
	}
	completedAt := commands.now().UTC()
	completed, updateError := completePrivacyRequest(ctx, transaction, privacyRequestID, prepared, completedAt)
	if updateError != nil {
		return PrivacyRequest{}, updateError
	}
	if auditError := insertRequestAudit(ctx, transaction, auditID, actor.ID, "privacy_request."+prepared.decision, completed.ID, requestID, completed.RequestType, prepared.reasonCategory, completedAt); auditError != nil {
		return PrivacyRequest{}, auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return PrivacyRequest{}, ErrWriteFailed
	}
	return completed, nil
}

type completion struct {
	decision       string
	reasonCategory string
	note           string
	version        int64
}

func prepareCompletion(requestID string, privacyRequestID string, input CompleteRequestInput) (completion, error) {
	category := norm.NFKC.String(strings.TrimSpace(input.ReasonCategory))
	note := norm.NFKC.String(strings.TrimSpace(input.Note))
	if !validRequestID(requestID) || !validPrivacyRequestID(privacyRequestID) || input.Version < 1 || (input.Decision != "completed" && input.Decision != "refused") {
		return completion{}, ErrInvalidInput
	}
	if input.Decision == "completed" && (category != "" || note != "") {
		return completion{}, ErrInvalidInput
	}
	if input.Decision == "refused" && (!validReasonCategory(category) || !validText(note, 1, 500)) {
		return completion{}, ErrInvalidInput
	}
	return completion{decision: input.Decision, reasonCategory: category, note: note, version: input.Version}, nil
}

const privacyRequestProjection = `id, student_id, request_type, status, received_by_account_id, resolution_reason_category, resolution_note, completed_at, version, created_at, updated_at`

func findRequestReplay(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, digest [sha256.Size]byte) (PrivacyRequest, bool, error) {
	var storedDigest []byte
	var resourceID *string
	queryError := transaction.QueryRow(ctx, `SELECT request_digest, resource_id FROM idempotency_records WHERE actor_scope = $1 AND action = 'privacy_request.create' AND idempotency_key = $2 FOR UPDATE`, actorID, idempotencyKey).Scan(&storedDigest, &resourceID)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return PrivacyRequest{}, false, nil
	}
	if queryError != nil {
		return PrivacyRequest{}, false, ErrWriteFailed
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return PrivacyRequest{}, true, ErrIdempotencyConflict
	}
	if resourceID == nil {
		return PrivacyRequest{}, true, ErrWriteFailed
	}
	request, scanError := scanPrivacyRequest(transaction.QueryRow(ctx, `SELECT `+privacyRequestProjection+` FROM privacy_requests WHERE id = $1`, *resourceID))
	if scanError != nil {
		return PrivacyRequest{}, true, ErrWriteFailed
	}
	return request, true, nil
}

func insertRequestIdempotency(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, digest [sha256.Size]byte, requestID string, createdAt time.Time) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO idempotency_records (actor_scope, action, idempotency_key, request_digest, response_code, response_body, resource_id, created_at, expires_at) VALUES ($1, 'privacy_request.create', $2, $3, 201, jsonb_build_object('id', $4::text), $4, $5::timestamptz, $5::timestamptz + interval '24 hours')`, actorID, idempotencyKey, digest[:], requestID, createdAt)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

func insertPrivacyRequest(ctx context.Context, transaction pgx.Tx, requestID string, input CreateRequestInput, actorID string, createdAt time.Time) (PrivacyRequest, error) {
	row := transaction.QueryRow(ctx, `INSERT INTO privacy_requests (id, student_id, request_type, received_by_account_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5) RETURNING `+privacyRequestProjection, requestID, input.StudentID, input.RequestType, actorID, createdAt)
	request, scanError := scanPrivacyRequest(row)
	if scanError != nil {
		return PrivacyRequest{}, ErrWriteFailed
	}
	return request, nil
}

func completePrivacyRequest(ctx context.Context, transaction pgx.Tx, requestID string, input completion, completedAt time.Time) (PrivacyRequest, error) {
	var category, note *string
	if input.decision == "refused" {
		category, note = &input.reasonCategory, &input.note
	}
	row := transaction.QueryRow(ctx, `UPDATE privacy_requests SET status = $2, resolution_reason_category = $3, resolution_note = $4, completed_at = $5, version = version + 1, updated_at = $5 WHERE id = $1 AND version = $6 AND status NOT IN ('completed', 'refused') RETURNING `+privacyRequestProjection, requestID, input.decision, category, note, completedAt, input.version)
	request, scanError := scanPrivacyRequest(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		var exists bool
		if queryError := transaction.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM privacy_requests WHERE id = $1)`, requestID).Scan(&exists); queryError != nil {
			return PrivacyRequest{}, ErrWriteFailed
		}
		if !exists {
			return PrivacyRequest{}, ErrNotFound
		}
		return PrivacyRequest{}, ErrVersionConflict
	}
	if scanError != nil {
		return PrivacyRequest{}, ErrWriteFailed
	}
	return request, nil
}

func insertRequestAudit(ctx context.Context, transaction pgx.Tx, auditID string, actorID string, action string, objectID string, requestID string, requestType string, reasonCategory string, occurredAt time.Time) error {
	query := `INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at) VALUES ($1, 'account', $2, $3, 'privacy_request', $4, 'success', $5, jsonb_build_object('request_type', $6::text), $7)`
	arguments := []any{auditID, actorID, action, objectID, requestID, requestType, occurredAt}
	if reasonCategory != "" {
		query = `INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at) VALUES ($1, 'account', $2, $3, 'privacy_request', $4, 'success', $5, jsonb_build_object('request_type', $6::text, 'reason_category', $7::text), $8)`
		arguments = []any{auditID, actorID, action, objectID, requestID, requestType, reasonCategory, occurredAt}
	}
	_, writeError := transaction.Exec(ctx, query, arguments...)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

type currentOperator struct {
	id             string
	role           string
	staffProfileID *string
}

func loadOperator(ctx context.Context, transaction pgx.Tx, accountID string) (currentOperator, error) {
	current := currentOperator{}
	var state string
	var mustChange bool
	queryError := transaction.QueryRow(ctx, `SELECT id, role, staff_profile_id, state, must_change_password FROM accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&current.id, &current.role, &current.staffProfileID, &state, &mustChange)
	if queryError != nil || state != "active" || mustChange || (current.role != "owner" && current.role != "staff") {
		return currentOperator{}, ErrForbidden
	}
	return current, nil
}

func requireStudentScope(ctx context.Context, transaction pgx.Tx, actor currentOperator, studentID string) error {
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM students WHERE id = $1)`
	arguments := []any{studentID}
	if actor.role == "staff" {
		query = `SELECT EXISTS (SELECT 1 FROM students AS student WHERE student.id = $1 AND (EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $2 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $2 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id))))`
		arguments = append(arguments, actor.staffProfileID)
	}
	if queryError := transaction.QueryRow(ctx, query, arguments...).Scan(&exists); queryError != nil {
		return ErrWriteFailed
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func scanPrivacyRequest(row pgx.Row) (PrivacyRequest, error) {
	request := PrivacyRequest{}
	error := row.Scan(&request.ID, &request.StudentID, &request.RequestType, &request.Status, &request.ReceivedByAccountID, &request.ReasonCategory, &request.Note, &request.CompletedAt, &request.Version, &request.CreatedAt, &request.UpdatedAt)
	return request, error
}

func eligibleOperator(actor auth.Account) bool {
	return actor.ID != "" && actor.State == "active" && !actor.MustChangePassword && (actor.Role == "owner" || actor.Role == "staff")
}

func validRequestType(value string) bool {
	return value == "access" || value == "correction" || value == "deletion" || value == "consent_withdrawal"
}

func validReasonCategory(value string) bool {
	return value == "identity_not_verified" || value == "request_invalid" || value == "legal_retention_required" || value == "unresolved_workflow"
}

func validRequestID(value string) bool { return validText(value, 8, 100) }
func validStudentID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "S-")
}
func validPrivacyRequestID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "PR-")
}
func validAuditID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "AU-")
}
func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}
