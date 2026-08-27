/* 隐私请求 HTTP：把已认证账号触发映射到登记、老板队列和版本化终态命令。 */
package privacy

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
)

var ErrInvalidHTTPDependencies = errors.New("privacy HTTP dependencies are invalid")

type currentAccount func(*gin.Context) (auth.Account, error)

type HTTP struct {
	commands *RequestCommands
	current  currentAccount
}

type createRequestHTTPInput struct {
	StudentID   string `json:"student_id"`
	RequestType string `json:"request_type"`
}

type completeRequestHTTPInput struct {
	Decision       string `json:"decision"`
	ReasonCategory string `json:"reason_category"`
	Note           string `json:"note"`
	Version        int64  `json:"version"`
}

func NewHTTP(commands *RequestCommands, current currentAccount) (*HTTP, error) {
	if commands == nil || current == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current}, nil
}

func (entry *HTTP) Register(api *gin.RouterGroup) {
	api.POST("/privacy-requests", httpx.RequireIdempotencyKey(), entry.create)
	api.GET("/privacy-requests", entry.list)
	api.POST("/privacy-requests/:privacyRequestId/complete", entry.complete)
}

func (entry *HTTP) create(context *gin.Context) {
	actor, authorized := entry.authorize(context)
	if !authorized {
		return
	}
	input := createRequestHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Privacy request input is invalid.")
		return
	}
	created, createError := entry.commands.Create(context.Request.Context(), actor, httpx.RequestID(context), httpx.IdempotencyKey(context), CreateRequestInput{StudentID: input.StudentID, RequestType: input.RequestType})
	if createError != nil {
		writePrivacyProblem(context, createError)
		return
	}
	context.JSON(http.StatusCreated, gin.H{"data": created, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) list(context *gin.Context) {
	actor, authorized := entry.authorize(context)
	if !authorized {
		return
	}
	requests, listError := entry.commands.List(context.Request.Context(), actor)
	if listError != nil {
		writePrivacyProblem(context, listError)
		return
	}
	context.JSON(http.StatusOK, gin.H{"data": requests, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) complete(context *gin.Context) {
	actor, authorized := entry.authorize(context)
	if !authorized {
		return
	}
	input := completeRequestHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Privacy request decision is invalid.")
		return
	}
	completed, completeError := entry.commands.Complete(context.Request.Context(), actor, httpx.RequestID(context), context.Param("privacyRequestId"), CompleteRequestInput{
		Decision: input.Decision, ReasonCategory: input.ReasonCategory, Note: input.Note, Version: input.Version,
	})
	if completeError != nil {
		writePrivacyProblem(context, completeError)
		return
	}
	context.JSON(http.StatusOK, gin.H{"data": completed, "meta": gin.H{"request_id": httpx.RequestID(context)}})
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
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Privacy request access is forbidden.")
		return auth.Account{}, false
	}
	return actor, true
}

func writePrivacyProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Privacy request access is forbidden.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Privacy request input is invalid.")
	case errors.Is(commandError, ErrNotFound):
		httpx.AbortProblem(context, http.StatusNotFound, "NOT_FOUND", "Privacy request was not found.")
	case errors.Is(commandError, ErrVersionConflict):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Privacy request state changed.")
	case errors.Is(commandError, ErrIdempotencyConflict):
		httpx.AbortProblem(context, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with another privacy request.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Privacy request service is temporarily unavailable.")
	}
}
