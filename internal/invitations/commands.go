/*
邀请业务指令：把后台对象范围、一次秘密、生命周期和受限会话封装成一个事务深模块。
调用方只能取得本次新生成的原始秘密；数据库、事件和审计始终只接收摘要或最小引用事实。
*/
package invitations

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
)

var ErrInvalidDependencies = errors.New("invitation dependencies are invalid")
var ErrForbidden = errors.New("invitation access is forbidden")
var ErrInvalidInput = errors.New("invitation input is invalid")
var ErrNotFound = errors.New("invitation was not found")
var ErrInvalidInvitation = errors.New("invitation is invalid")
var ErrInvalidCapability = errors.New("invitation capability is invalid")
var ErrIdempotencyConflict = errors.New("invitation idempotency conflicts")
var ErrWriteFailed = errors.New("invitation write failed")

const restrictedSessionLifetime = 2 * time.Hour // 受限会话短于常见邀请期限，且仍受原邀请终点约束。
const maximumInvitationLifetimeHours = 72       // 生产计划冻结三天绝对上限，避免长期暴露一次邀请能力。

// IssueInput 只允许后台选择固定问卷版本和有界小时数。
type IssueInput struct {
	AssessmentVersion string // AssessmentVersion 必须是数据库当前活动的固定问卷。
	ExpiresInHours    int    // ExpiresInHours 限定为 1..72，与生产隐私批准的绝对期限一致。
}

// Invitation 是签发成功后的一次性反馈；Secret 不可从数据库恢复或再次返回。
type Invitation struct {
	ID                string    `json:"id"`                 // ID 是后续撤销和审计使用的稳定对象身份。
	StudentID         string    `json:"student_id"`         // StudentID 保留本次已通过的单学生范围。
	AssessmentVersion string    `json:"assessment_version"` // AssessmentVersion 固定学生稍后读取的问卷。
	Secret            string    `json:"secret"`             // Secret 只存在于本次成功反馈，不进入持久化。
	ExpiresAt         time.Time `json:"expires_at"`         // ExpiresAt 是半开有效区间的 UTC 终点。
}

// CapabilitySession 是邀请首次兑换后建立的独立短期秘密。
type CapabilitySession struct {
	ID                string    `json:"id"`                 // ID 与原邀请身份分离并作为受限主体引用。
	Secret            string    `json:"secret"`             // Secret 只反馈本次兑换生成的 Cookie 材料。
	StudentID         string    `json:"student_id"`         // StudentID 是能力唯一可访问的业务对象。
	AssessmentVersion string    `json:"assessment_version"` // AssessmentVersion 不能由学生改写。
	ExpiresAt         time.Time `json:"expires_at"`         // ExpiresAt 永不晚于原邀请终点。
}

// CapabilityScope 是学生自助命令可见的全部授权面，不携带后台账号权限。
type CapabilityScope struct {
	StudentID         string `json:"student_id"`         // StudentID 是后续资料写入的唯一目标。
	AssessmentVersion string `json:"assessment_version"` // AssessmentVersion 固定合法题目与评分定义。
	InvitationID      string `json:"invitation_id"`      // InvitationID 连接完成状态、事件和审计。
}

// Commands 隐藏账号重验、摘要轮换、对象范围和证据写入格式。
type Commands struct {
	data        *store
	now         func() time.Time
	newIdentity func(string) (string, error)
	newSecret   func() (string, error)
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error)
}

// NewCommands 只有在数据库、可信时钟、身份和秘密能力齐全时才装配模块。
func NewCommands(database transactionSource, now func() time.Time, newIdentity func(string) (string, error), newSecret func() (string, error)) (*Commands, error) {
	if database == nil || now == nil || newIdentity == nil || newSecret == nil {
		return nil, ErrInvalidDependencies
	}
	return &Commands{data: &store{database: database}, now: now, newIdentity: newIdentity, newSecret: newSecret}, nil
}

// Issue 签发或补发邀请，并把旧的可用能力、事件、审计和幂等事实放进同一事务。
func (commands *Commands) Issue(ctx context.Context, actor auth.Account, requestID string, idempotencyKey string, studentID string, input IssueInput) (Invitation, error) {
	if !actorEligible(actor) {
		return Invitation{}, ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validText(idempotencyKey, 16, 128) || !validStudentID(studentID) || !validAssessmentVersion(input.AssessmentVersion) || input.ExpiresInHours < 1 || input.ExpiresInHours > maximumInvitationLifetimeHours {
		return Invitation{}, ErrInvalidInput
	}
	requestDigest, digestError := issueDigest(studentID, input)
	if digestError != nil {
		return Invitation{}, ErrWriteFailed
	}
	invitationID, eventID, auditID, identityError := commands.issueIdentities()
	if identityError != nil {
		return Invitation{}, identityError
	}
	secret, secretError := commands.newSecret()
	if secretError != nil || !validSecret(secret) {
		return Invitation{}, ErrWriteFailed
	}

	now := commands.now().UTC()
	expiresAt := now.Add(time.Duration(input.ExpiresInHours) * time.Hour)
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Invitation{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return Invitation{}, actorError
	}
	studentVersion, scopeError := commands.data.getScopedStudent(ctx, transaction, currentActor, studentID)
	if scopeError != nil {
		return Invitation{}, scopeError
	}
	if questionnaireError := commands.data.requireActiveQuestionnaire(ctx, transaction, input.AssessmentVersion); questionnaireError != nil {
		return Invitation{}, questionnaireError
	}
	if idempotencyError := commands.data.requireUnusedIssueKey(ctx, transaction, currentActor.id, idempotencyKey); idempotencyError != nil {
		return Invitation{}, idempotencyError
	}
	if replaceError := commands.data.replaceLive(ctx, transaction, studentID, now); replaceError != nil {
		return Invitation{}, replaceError
	}
	invitationDigest := sha256.Sum256([]byte(secret))
	if insertError := commands.data.insertInvitation(ctx, transaction, invitationID, studentID, currentActor.id, input.AssessmentVersion, studentVersion, invitationDigest, expiresAt, now); insertError != nil {
		return Invitation{}, insertError
	}
	if eventError := commands.data.insertAccountEvent(ctx, transaction, eventID, studentID, currentActor.id, "invitation.issued", invitationID, input.AssessmentVersion, "", now); eventError != nil {
		return Invitation{}, eventError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, "account", currentActor.id, "invitation.issued", invitationID, requestID, input.AssessmentVersion, ""); auditError != nil {
		return Invitation{}, auditError
	}
	if idempotencyError := commands.data.insertIssueIdempotency(ctx, transaction, currentActor.id, idempotencyKey, requestDigest, invitationID, now); idempotencyError != nil {
		return Invitation{}, idempotencyError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Invitation{}, ErrWriteFailed
	}
	return Invitation{ID: invitationID, StudentID: studentID, AssessmentVersion: input.AssessmentVersion, Secret: secret, ExpiresAt: expiresAt}, nil
}

// Revoke 对未知与越权对象统一返回不存在，并在成功时销毁链接和会话摘要。
func (commands *Commands) Revoke(ctx context.Context, actor auth.Account, requestID string, invitationID string) error {
	if !actorEligible(actor) {
		return ErrForbidden
	}
	if !validText(requestID, 8, 100) {
		return ErrInvalidInput
	}
	if !validInvitationID(invitationID) {
		return ErrNotFound
	}
	eventID, eventError := commands.newIdentity("EV")
	auditID, auditError := commands.newIdentity("AU")
	if eventError != nil || auditError != nil || !validIdentity(eventID, "EV") || !validIdentity(auditID, "AU") {
		return ErrWriteFailed
	}

	now := commands.now().UTC()
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return actorError
	}
	current, findError := commands.data.getScopedLiveInvitation(ctx, transaction, currentActor, invitationID)
	if findError != nil {
		return findError
	}
	if revokeError := commands.data.revoke(ctx, transaction, current.ID, now); revokeError != nil {
		return revokeError
	}
	if evidenceError := commands.data.insertAccountEvent(ctx, transaction, eventID, current.StudentID, currentActor.id, "invitation.revoked", current.ID, current.AssessmentVersion, "manual", now); evidenceError != nil {
		return evidenceError
	}
	if evidenceError := commands.data.insertAudit(ctx, transaction, auditID, "account", currentActor.id, "invitation.revoked", current.ID, requestID, current.AssessmentVersion, "manual"); evidenceError != nil {
		return evidenceError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return ErrWriteFailed
	}
	return nil
}

// Exchange 以原邀请秘密换取更窄会话；所有不可用原因共享同一公开失败。
func (commands *Commands) Exchange(ctx context.Context, requestID string, secret string) (CapabilitySession, error) {
	if !validText(requestID, 8, 100) || !validSecret(secret) {
		return CapabilitySession{}, ErrInvalidInvitation
	}
	sessionID, eventID, auditID, identityError := commands.exchangeIdentities()
	if identityError != nil {
		return CapabilitySession{}, identityError
	}
	sessionSecret, secretError := commands.newSecret()
	if secretError != nil || !validSecret(sessionSecret) {
		return CapabilitySession{}, ErrWriteFailed
	}

	now := commands.now().UTC()
	invitationDigest := sha256.Sum256([]byte(secret))
	sessionDigest := sha256.Sum256([]byte(sessionSecret))
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return CapabilitySession{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, findError := commands.data.getExchangeable(ctx, transaction, invitationDigest, now)
	if findError != nil {
		return CapabilitySession{}, findError
	}
	sessionExpiresAt := now.Add(restrictedSessionLifetime)
	if current.ExpiresAt.Before(sessionExpiresAt) {
		sessionExpiresAt = current.ExpiresAt
	}
	if exchangeError := commands.data.exchange(ctx, transaction, current.ID, sessionID, sessionDigest, sessionExpiresAt, now); exchangeError != nil {
		return CapabilitySession{}, exchangeError
	}
	if evidenceError := commands.data.insertInvitationEvent(ctx, transaction, eventID, current.StudentID, sessionID, "invitation.exchanged", current.ID, current.AssessmentVersion, now); evidenceError != nil {
		return CapabilitySession{}, evidenceError
	}
	if evidenceError := commands.data.insertAudit(ctx, transaction, auditID, "invitation", sessionID, "invitation.exchanged", current.ID, requestID, current.AssessmentVersion, ""); evidenceError != nil {
		return CapabilitySession{}, evidenceError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return CapabilitySession{}, ErrWriteFailed
	}
	return CapabilitySession{ID: sessionID, Secret: sessionSecret, StudentID: current.StudentID, AssessmentVersion: current.AssessmentVersion, ExpiresAt: sessionExpiresAt}, nil
}

// Resolve 每次使用都动态复核签发账号、当前负责人和精确过期边界。
func (commands *Commands) Resolve(ctx context.Context, sessionID string, secret string) (CapabilityScope, error) {
	if !validSessionID(sessionID) || !validSecret(secret) {
		return CapabilityScope{}, ErrInvalidCapability
	}
	digest := sha256.Sum256([]byte(secret))
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return CapabilityScope{}, ErrInvalidCapability
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	scope, resolveError := commands.data.resolve(ctx, transaction, sessionID, digest, commands.now().UTC())
	if resolveError != nil {
		return CapabilityScope{}, resolveError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return CapabilityScope{}, ErrInvalidCapability
	}
	return scope, nil
}

func (commands *Commands) issueIdentities() (string, string, string, error) {
	invitationID, invitationError := commands.newIdentity("IV")
	eventID, eventError := commands.newIdentity("EV")
	auditID, auditError := commands.newIdentity("AU")
	if invitationError != nil || eventError != nil || auditError != nil || !validIdentity(invitationID, "IV") || !validIdentity(eventID, "EV") || !validIdentity(auditID, "AU") {
		return "", "", "", ErrWriteFailed
	}
	return invitationID, eventID, auditID, nil
}

func (commands *Commands) exchangeIdentities() (string, string, string, error) {
	sessionID, sessionError := commands.newIdentity("IS")
	eventID, eventError := commands.newIdentity("EV")
	auditID, auditError := commands.newIdentity("AU")
	if sessionError != nil || eventError != nil || auditError != nil || !validIdentity(sessionID, "IS") || !validIdentity(eventID, "EV") || !validIdentity(auditID, "AU") {
		return "", "", "", ErrWriteFailed
	}
	return sessionID, eventID, auditID, nil
}

func issueDigest(studentID string, input IssueInput) ([sha256.Size]byte, error) {
	body, marshalError := json.Marshal(struct {
		StudentID         string `json:"student_id"`
		AssessmentVersion string `json:"assessment_version"`
		ExpiresInHours    int    `json:"expires_in_hours"`
	}{studentID, input.AssessmentVersion, input.ExpiresInHours})
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

func validInvitationID(value string) bool { return validIdentity(value, "IV") }
func validSessionID(value string) bool    { return validIdentity(value, "IS") }

func validIdentity(value string, prefix string) bool {
	return len(value) >= len(prefix)+13 && len(value) <= len(prefix)+81 && strings.HasPrefix(value, prefix+"-")
}

func validAssessmentVersion(value string) bool {
	if !strings.HasPrefix(value, "assessment-") || len(value) < len("assessment-1") || len(value) > 40 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "assessment-") {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validSecret(value string) bool { return validText(value, 32, 256) }

func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}
