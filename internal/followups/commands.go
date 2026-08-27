/*
跟进业务指令：把学生对象范围、跟进版本和学生派生下一步封装成一个事务深模块。
调用方只提交当前账号与跟进意图；正文只进入业务表，事件和审计只保存最小引用事实。
*/
package followups

import (
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

var ErrInvalidDependencies = errors.New("follow-up dependencies are invalid")
var ErrForbidden = errors.New("follow-up access is forbidden")
var ErrInvalidInput = errors.New("follow-up input is invalid")
var ErrNotFound = errors.New("follow-up was not found")
var ErrVersionConflict = errors.New("follow-up version conflicts")
var ErrIdempotencyConflict = errors.New("follow-up idempotency conflicts")
var ErrWriteFailed = errors.New("follow-up write failed")

// FollowUp 是通过学生范围门禁后返回的完整跟进事实。
type FollowUp struct {
	ID                 string     `json:"id"`
	StudentID          string     `json:"student_id"`
	ContactedAt        time.Time  `json:"contacted_at"`
	Channel            string     `json:"channel"`
	Content            *string    `json:"content"` // 历史记录可空；新记录由命令强制必填。
	ValidContact       bool       `json:"valid_contact"`
	ReplyRequired      bool       `json:"reply_required"`
	ReplyThreadID      *string    `json:"reply_thread_id"`
	StudentRepliedAt   *time.Time `json:"student_replied_at"`
	OverdueOccurrence  bool       `json:"overdue_occurrence"`
	NextAction         *string    `json:"next_action"`
	NextFollowUpAt     *time.Time `json:"next_follow_up_at"`
	NextStaffID        *string    `json:"next_staff_id"`
	NextStaffName      *string    `json:"next_staff_name"`
	CreatedByAccountID string     `json:"created_by_account_id"`
	CreatedByName      string     `json:"created_by_name"`
	Version            int64      `json:"version"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// CreateInput 是一次完整跟进意图；缺省可选字段会持久化为 null。
type CreateInput struct {
	ContactedAt       time.Time
	Channel           string
	Content           string
	ValidContact      bool
	ReplyRequired     bool
	ReplyThreadID     *string
	StudentRepliedAt  *time.Time
	OverdueOccurrence bool
	NextAction        *string
	NextFollowUpAt    *time.Time
	NextStaffID       *string
}

// UpdateInput 是跟进当前完整快照，Version 防止覆盖并发修改。
type UpdateInput struct {
	ContactedAt       time.Time
	Channel           string
	Content           string
	ValidContact      bool
	ReplyRequired     bool
	ReplyThreadID     *string
	StudentRepliedAt  *time.Time
	OverdueOccurrence bool
	NextAction        *string
	NextFollowUpAt    *time.Time
	NextStaffID       *string
	Version           int64
}

// Commands 隐藏范围 SQL、派生重建、事件和审计格式。
type Commands struct {
	data        *store
	now         func() time.Time
	newIdentity func(string) (string, error)
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error)
}

type preparedFollowUp struct {
	contactedAt       time.Time
	channel           string
	content           string
	validContact      bool
	replyRequired     bool
	replyThreadID     *string
	studentRepliedAt  *time.Time
	overdueOccurrence bool
	nextAction        *string
	nextFollowUpAt    *time.Time
	nextStaffID       *string
	version           int64
}

// NewCommands 只在数据库、时钟和身份生成能力完整时装配模块。
func NewCommands(database transactionSource, now func() time.Time, newIdentity func(string) (string, error)) (*Commands, error) {
	if database == nil || now == nil || newIdentity == nil {
		return nil, ErrInvalidDependencies
	}
	return &Commands{data: &store{database: database}, now: now, newIdentity: newIdentity}, nil
}

// List 按学生范围稳定倒序返回跟进，不让空列表泄露其他学生存在性。
func (commands *Commands) List(ctx context.Context, actor auth.Account, studentID string) ([]FollowUp, error) {
	if !actorEligible(actor) {
		return nil, ErrForbidden
	}
	if !validStudentID(studentID) {
		return nil, ErrNotFound
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return nil, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return nil, actorError
	}
	if _, scopeError := commands.data.getScopedStudent(ctx, transaction, currentActor, studentID, false); scopeError != nil {
		return nil, scopeError
	}
	items, listError := commands.data.list(ctx, transaction, studentID)
	if listError != nil {
		return nil, listError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return nil, ErrWriteFailed
	}
	return items, nil
}

// Create 幂等写入跟进，并在同一事务重建学生派生下一步。
func (commands *Commands) Create(ctx context.Context, actor auth.Account, requestID string, idempotencyKey string, studentID string, input CreateInput) (FollowUp, error) {
	if !actorEligible(actor) {
		return FollowUp{}, ErrForbidden
	}
	prepared, prepareError := prepareInput(requestID, input, 0)
	if prepareError != nil || !validStudentID(studentID) || !validText(idempotencyKey, 16, 128) {
		return FollowUp{}, ErrInvalidInput
	}
	digest, digestError := createDigest(studentID, prepared)
	if digestError != nil {
		return FollowUp{}, ErrWriteFailed
	}
	followUpID, eventID, auditID, identityError := commands.identities()
	if identityError != nil {
		return FollowUp{}, identityError
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return FollowUp{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return FollowUp{}, actorError
	}
	if _, scopeError := commands.data.getScopedStudent(ctx, transaction, currentActor, studentID, true); scopeError != nil {
		return FollowUp{}, scopeError
	}
	if prepared.nextStaffID != nil {
		if nextStaffError := commands.data.requireActiveStudentStaff(ctx, transaction, studentID, *prepared.nextStaffID); nextStaffError != nil {
			return FollowUp{}, nextStaffError
		}
	}
	if replay, found, replayError := commands.data.findCreateReplay(ctx, transaction, currentActor, idempotencyKey, digest); replayError != nil || found {
		return replay, replayError
	}
	created, insertError := commands.data.insert(ctx, transaction, currentActor.id, followUpID, studentID, prepared)
	if insertError != nil {
		return FollowUp{}, insertError
	}
	created, insertError = commands.data.getScoped(ctx, transaction, currentActor, created.ID, false)
	if insertError != nil {
		return FollowUp{}, insertError
	}
	studentVersion, deriveError := commands.data.rebuildStudentDerivation(ctx, transaction, currentActor.id, studentID)
	if deriveError != nil {
		return FollowUp{}, deriveError
	}
	if eventError := commands.data.insertEvent(ctx, transaction, eventID, currentActor.id, "follow_up.created", created, commands.now().UTC()); eventError != nil {
		return FollowUp{}, eventError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, currentActor.id, "follow_up.created", created.ID, requestID, created.Version, studentVersion); auditError != nil {
		return FollowUp{}, auditError
	}
	if idempotencyError := commands.data.insertCreateIdempotency(ctx, transaction, currentActor.id, idempotencyKey, digest, created.ID); idempotencyError != nil {
		return FollowUp{}, idempotencyError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return FollowUp{}, ErrWriteFailed
	}
	return created, nil
}

// Update 版本化替换一条跟进，并重新选择联系时间最新的派生来源。
func (commands *Commands) Update(ctx context.Context, actor auth.Account, requestID string, followUpID string, input UpdateInput) (FollowUp, error) {
	if !actorEligible(actor) {
		return FollowUp{}, ErrForbidden
	}
	prepared, prepareError := prepareInput(requestID, CreateInput{
		ContactedAt: input.ContactedAt, Channel: input.Channel, Content: input.Content, ValidContact: input.ValidContact,
		ReplyRequired: input.ReplyRequired, ReplyThreadID: input.ReplyThreadID,
		StudentRepliedAt: input.StudentRepliedAt, OverdueOccurrence: input.OverdueOccurrence,
		NextAction: input.NextAction, NextFollowUpAt: input.NextFollowUpAt, NextStaffID: input.NextStaffID,
	}, input.Version)
	if prepareError != nil || !validFollowUpID(followUpID) || input.Version < 1 {
		return FollowUp{}, ErrInvalidInput
	}
	eventID, eventIdentityError := commands.newIdentity("EV")
	auditID, auditIdentityError := commands.newIdentity("AU")
	if eventIdentityError != nil || auditIdentityError != nil || eventID == "" || auditID == "" {
		return FollowUp{}, ErrWriteFailed
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return FollowUp{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return FollowUp{}, actorError
	}
	current, currentError := commands.data.getScoped(ctx, transaction, currentActor, followUpID, true)
	if currentError != nil {
		return FollowUp{}, currentError
	}
	if current.Version != input.Version {
		return FollowUp{}, ErrVersionConflict
	}
	if prepared.nextStaffID != nil {
		if nextStaffError := commands.data.requireActiveStudentStaff(ctx, transaction, current.StudentID, *prepared.nextStaffID); nextStaffError != nil {
			return FollowUp{}, nextStaffError
		}
	}
	updated, updateError := commands.data.update(ctx, transaction, currentActor.id, followUpID, prepared)
	if updateError != nil {
		return FollowUp{}, updateError
	}
	studentVersion, deriveError := commands.data.rebuildStudentDerivation(ctx, transaction, currentActor.id, current.StudentID)
	if deriveError != nil {
		return FollowUp{}, deriveError
	}
	if eventError := commands.data.insertEvent(ctx, transaction, eventID, currentActor.id, "follow_up.updated", updated, commands.now().UTC()); eventError != nil {
		return FollowUp{}, eventError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, currentActor.id, "follow_up.updated", updated.ID, requestID, updated.Version, studentVersion); auditError != nil {
		return FollowUp{}, auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return FollowUp{}, ErrWriteFailed
	}
	return updated, nil
}

// Delete 只删除调用方读取的版本，并在同一事务回退学生派生来源。
func (commands *Commands) Delete(ctx context.Context, actor auth.Account, requestID string, followUpID string, version int64) error {
	if !actorEligible(actor) {
		return ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validFollowUpID(followUpID) || version < 1 {
		return ErrInvalidInput
	}
	eventID, eventIdentityError := commands.newIdentity("EV")
	auditID, auditIdentityError := commands.newIdentity("AU")
	if eventIdentityError != nil || auditIdentityError != nil || eventID == "" || auditID == "" {
		return ErrWriteFailed
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return actorError
	}
	current, currentError := commands.data.getScoped(ctx, transaction, currentActor, followUpID, true)
	if currentError != nil {
		return currentError
	}
	if current.Version != version {
		return ErrVersionConflict
	}
	if deleteError := commands.data.delete(ctx, transaction, followUpID, version); deleteError != nil {
		return deleteError
	}
	studentVersion, deriveError := commands.data.rebuildStudentDerivation(ctx, transaction, currentActor.id, current.StudentID)
	if deriveError != nil {
		return deriveError
	}
	if eventError := commands.data.insertEvent(ctx, transaction, eventID, currentActor.id, "follow_up.deleted", current, commands.now().UTC()); eventError != nil {
		return eventError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, currentActor.id, "follow_up.deleted", current.ID, requestID, current.Version, studentVersion); auditError != nil {
		return auditError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return ErrWriteFailed
	}
	return nil
}

// identities 在开启事务前准备创建需要的三个相互独立身份。
func (commands *Commands) identities() (string, string, string, error) {
	followUpID, followUpError := commands.newIdentity("FU")
	eventID, eventError := commands.newIdentity("EV")
	auditID, auditError := commands.newIdentity("AU")
	if followUpError != nil || eventError != nil || auditError != nil || followUpID == "" || eventID == "" || auditID == "" {
		return "", "", "", ErrWriteFailed
	}
	return followUpID, eventID, auditID, nil
}

// prepareInput 统一正文、时间和跨字段不变量，避免事务内出现格式分支。
func prepareInput(requestID string, input CreateInput, version int64) (preparedFollowUp, error) {
	channel := norm.NFKC.String(strings.TrimSpace(input.Channel))
	content := norm.NFKC.String(strings.TrimSpace(input.Content))
	replyThreadID := normalizeOptional(input.ReplyThreadID)
	nextAction := normalizeOptional(input.NextAction)
	nextStaffID := normalizeOptional(input.NextStaffID)
	if !validText(requestID, 8, 100) || input.ContactedAt.IsZero() || !validText(channel, 1, 40) || !validText(content, 1, 4000) || !validOptionalText(nextAction, 500) || (nextStaffID != nil && !validStaffID(*nextStaffID)) {
		return preparedFollowUp{}, ErrInvalidInput
	}
	if replyThreadID != nil && !validReplyThreadID(*replyThreadID) || input.ReplyRequired && replyThreadID == nil || input.StudentRepliedAt != nil && replyThreadID == nil || version < 0 {
		return preparedFollowUp{}, ErrInvalidInput
	}
	studentRepliedAt := utcTime(input.StudentRepliedAt)
	nextFollowUpAt := utcTime(input.NextFollowUpAt)
	return preparedFollowUp{
		contactedAt: input.ContactedAt.UTC(), channel: channel, content: content, validContact: input.ValidContact,
		replyRequired: input.ReplyRequired, replyThreadID: replyThreadID, studentRepliedAt: studentRepliedAt,
		overdueOccurrence: input.OverdueOccurrence, nextAction: nextAction, nextFollowUpAt: nextFollowUpAt, nextStaffID: nextStaffID, version: version,
	}, nil
}

func createDigest(studentID string, input preparedFollowUp) ([sha256.Size]byte, error) {
	body, marshalError := json.Marshal(struct {
		StudentID         string     `json:"student_id"`
		ContactedAt       time.Time  `json:"contacted_at"`
		Channel           string     `json:"channel"`
		Content           string     `json:"content"`
		ValidContact      bool       `json:"valid_contact"`
		ReplyRequired     bool       `json:"reply_required"`
		ReplyThreadID     *string    `json:"reply_thread_id"`
		StudentRepliedAt  *time.Time `json:"student_replied_at"`
		OverdueOccurrence bool       `json:"overdue_occurrence"`
		NextAction        *string    `json:"next_action"`
		NextFollowUpAt    *time.Time `json:"next_follow_up_at"`
		NextStaffID       *string    `json:"next_staff_id"`
	}{studentID, input.contactedAt, input.channel, input.content, input.validContact, input.replyRequired, input.replyThreadID, input.studentRepliedAt, input.overdueOccurrence, input.nextAction, input.nextFollowUpAt, input.nextStaffID})
	if marshalError != nil {
		return [sha256.Size]byte{}, marshalError
	}
	return sha256.Sum256(body), nil
}

func actorEligible(actor auth.Account) bool {
	return actor.ID != "" && actor.State == "active" && !actor.MustChangePassword && (actor.Role == "owner" || actor.Role == "staff")
}

func validStudentID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "S-")
}
func validFollowUpID(value string) bool {
	return len(value) >= 16 && len(value) <= 84 && strings.HasPrefix(value, "FU-")
}
func validReplyThreadID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "RT-")
}
func validStaffID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "T-")
}
func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}
func normalizeOptional(value *string) *string {
	if value == nil {
		return nil
	}
	normalized := norm.NFKC.String(strings.TrimSpace(*value))
	if normalized == "" {
		return nil
	}
	return &normalized
}
func validOptionalText(value *string, maximum int) bool {
	return value == nil || validText(*value, 1, maximum)
}
func utcTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}
