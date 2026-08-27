/*
跟进 HTTP 入口：把浏览器触发映射到连续跟进记录事务。
本文件只解析公开合同、恢复当前账号和映射稳定反馈；范围、版本和审计仍由命令层决定。
*/
package followups

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
)

var ErrInvalidHTTPDependencies = errors.New("follow-up HTTP dependencies are invalid")

type currentAccount func(*gin.Context) (auth.Account, error)

type HTTP struct {
	commands *Commands
	current  currentAccount
}

type createHTTPInput struct {
	ContactedAt       time.Time                 `json:"contacted_at"`
	Channel           string                    `json:"channel"`
	Content           string                    `json:"content"`
	ValidContact      httpx.OptionalField[bool] `json:"valid_contact"`
	ReplyRequired     httpx.OptionalField[bool] `json:"reply_required"`
	ReplyThreadID     *string                   `json:"reply_thread_id,omitempty"`
	StudentRepliedAt  *time.Time                `json:"student_replied_at"`
	OverdueOccurrence bool                      `json:"overdue_occurrence,omitempty"`
	NextAction        *string                   `json:"next_action"`
	NextFollowUpAt    *time.Time                `json:"next_follow_up_at"`
	NextStaffID       *string                   `json:"next_staff_id"`
}

type responseMeta struct {
	RequestID string `json:"request_id"`
}

func NewHTTP(commands *Commands, current currentAccount) (*HTTP, error) {
	if commands == nil || current == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current}, nil
}

func (entry *HTTP) Register(api *gin.RouterGroup) {
	api.GET("/students/:studentId/follow-ups", entry.list)
	api.POST("/students/:studentId/follow-ups", httpx.RequireIdempotencyKey(), entry.create)
}

func (entry *HTTP) list(context *gin.Context) {
	actor, ok := entry.authorize(context)
	if !ok {
		return
	}
	items, commandError := entry.commands.List(context.Request.Context(), actor, context.Param("studentId"))
	if commandError != nil {
		writeProblem(context, commandError)
		return
	}
	context.JSON(http.StatusOK, gin.H{"data": items, "meta": responseMeta{RequestID: httpx.RequestID(context)}})
}

func (entry *HTTP) create(context *gin.Context) {
	actor, ok := entry.authorize(context)
	if !ok {
		return
	}
	input := createHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 8192); decodeError != nil || !input.ValidContact.Set || !input.ReplyRequired.Set {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Follow-up input is invalid.")
		return
	}
	created, commandError := entry.commands.Create(context.Request.Context(), actor, httpx.RequestID(context), httpx.IdempotencyKey(context), context.Param("studentId"), CreateInput{
		ContactedAt: input.ContactedAt, Channel: input.Channel, Content: input.Content, ValidContact: input.ValidContact.Value,
		ReplyRequired: input.ReplyRequired.Value, ReplyThreadID: input.ReplyThreadID,
		StudentRepliedAt: input.StudentRepliedAt, OverdueOccurrence: input.OverdueOccurrence,
		NextAction: input.NextAction, NextFollowUpAt: input.NextFollowUpAt, NextStaffID: input.NextStaffID,
	})
	if commandError != nil {
		writeProblem(context, commandError)
		return
	}
	context.JSON(http.StatusCreated, gin.H{"data": created, "meta": responseMeta{RequestID: httpx.RequestID(context)}})
}

func (entry *HTTP) authorize(context *gin.Context) (auth.Account, bool) {
	actor, authenticationError := entry.current(context)
	if authenticationError != nil {
		httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return auth.Account{}, false
	}
	if actor.MustChangePassword {
		httpx.AbortProblem(context, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Password change is required.")
		return auth.Account{}, false
	}
	if actor.State != "active" || (actor.Role != "owner" && actor.Role != "staff") {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Follow-up access is forbidden.")
		return auth.Account{}, false
	}
	return actor, true
}

func writeProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Follow-up access is forbidden.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Follow-up input is invalid.")
	case errors.Is(commandError, ErrNotFound):
		httpx.AbortProblem(context, http.StatusNotFound, "NOT_FOUND", "Student or follow-up was not found.")
	case errors.Is(commandError, ErrVersionConflict):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Follow-up state changed.")
	case errors.Is(commandError, ErrIdempotencyConflict):
		httpx.AbortProblem(context, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with another request.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Follow-up service is temporarily unavailable.")
	}
}
