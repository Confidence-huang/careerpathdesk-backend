/* 老板关注 HTTP 入口：只投影最小证据 ID，并把人工结论交给现有原子命令。 */
package attention

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
)

var ErrInvalidHTTPDependencies = errors.New("attention HTTP dependencies are invalid")

type currentAccount func(*gin.Context) (auth.Account, error)

type HTTP struct {
	commands *Commands
	current  currentAccount
}

type conclusionHTTPInput struct {
	ConclusionCode string `json:"conclusion_code"`
	Reason         string `json:"reason"`
	Version        int64  `json:"version"`
}

type httpCase struct {
	ID               string    `json:"id"`
	StudentID        string    `json:"student_id"`
	RuleCode         string    `json:"rule_code"`
	Status           string    `json:"status"`
	EvidenceIDs      []string  `json:"evidence_ids"`
	ConclusionCode   *string   `json:"conclusion_code"`
	ConclusionReason *string   `json:"conclusion_reason"`
	Version          int64     `json:"version"`
	FirstTriggeredAt time.Time `json:"first_triggered_at"`
}

type httpReminder struct {
	StudentID          string    `json:"student_id"`
	LastValidContactAt time.Time `json:"last_valid_contact_at"`
	DueAt              time.Time `json:"due_at"`
}

func NewHTTP(commands *Commands, current currentAccount) (*HTTP, error) {
	if commands == nil || current == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current}, nil
}

func (entry *HTTP) Register(api *gin.RouterGroup) {
	api.GET("/attention-cases", entry.list)
	api.GET("/attention-reminders", entry.reminders)
	api.POST("/attention-evaluations", entry.evaluateAll)
	api.POST("/students/:studentId/complaints", httpx.RequireIdempotencyKey(), entry.confirmComplaint)
	api.PUT("/attention-cases/:caseId/conclusion", entry.conclude)
}

func (entry *HTTP) reminders(context *gin.Context) {
	actor, ok := entry.authorizeRole(context, "staff")
	if !ok {
		return
	}
	reminders, commandError := entry.commands.ListStaffReminders(context.Request.Context(), actor)
	if commandError != nil {
		writeHTTPProblem(context, commandError)
		return
	}
	data := make([]httpReminder, 0, len(reminders))
	for _, reminder := range reminders {
		data = append(data, httpReminder{StudentID: reminder.StudentID, LastValidContactAt: reminder.LastValidContactAt, DueAt: reminder.DueAt})
	}
	context.JSON(http.StatusOK, gin.H{"data": data, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) evaluateAll(context *gin.Context) {
	actor, ok := entry.authorizeOwner(context)
	if !ok {
		return
	}
	cases, commandError := entry.commands.EvaluateAll(context.Request.Context(), actor)
	if commandError != nil {
		writeHTTPProblem(context, commandError)
		return
	}
	data := make([]httpCase, 0, len(cases))
	for _, item := range cases {
		data = append(data, projectCase(item))
	}
	context.JSON(http.StatusOK, gin.H{"data": data, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) confirmComplaint(context *gin.Context) {
	actor, ok := entry.authorizeOperator(context)
	if !ok {
		return
	}
	_, commandError := entry.commands.ConfirmComplaint(context.Request.Context(), actor, httpx.RequestID(context), httpx.IdempotencyKey(context), context.Param("studentId"))
	if commandError != nil {
		writeHTTPProblem(context, commandError)
		return
	}
	context.JSON(http.StatusCreated, gin.H{"data": gin.H{"confirmed": true}, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) list(context *gin.Context) {
	actor, ok := entry.authorizeOwner(context)
	if !ok {
		return
	}
	cases, commandError := entry.commands.ListCases(context.Request.Context(), actor)
	if commandError != nil {
		writeHTTPProblem(context, commandError)
		return
	}
	data := make([]httpCase, 0, len(cases))
	for _, item := range cases {
		data = append(data, projectCase(item))
	}
	context.JSON(http.StatusOK, gin.H{"data": data, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) conclude(context *gin.Context) {
	actor, ok := entry.authorizeOwner(context)
	if !ok {
		return
	}
	input := conclusionHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Attention conclusion input is invalid.")
		return
	}
	updated, commandError := entry.commands.Conclude(context.Request.Context(), actor, httpx.RequestID(context), context.Param("caseId"), ConclusionInput{
		ConclusionCode: input.ConclusionCode, Reason: input.Reason, Version: input.Version,
	})
	if commandError != nil {
		writeHTTPProblem(context, commandError)
		return
	}
	context.JSON(http.StatusOK, gin.H{"data": projectCase(updated), "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) authorizeOwner(context *gin.Context) (auth.Account, bool) {
	return entry.authorizeRole(context, "owner")
}

func (entry *HTTP) authorizeRole(context *gin.Context, requiredRole string) (auth.Account, bool) {
	actor, authenticationError := entry.current(context)
	if authenticationError != nil {
		httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return auth.Account{}, false
	}
	if actor.MustChangePassword {
		httpx.AbortProblem(context, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Password change is required.")
		return auth.Account{}, false
	}
	if actor.State != "active" || actor.Role != requiredRole {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Attention access is forbidden.")
		return auth.Account{}, false
	}
	return actor, true
}

func (entry *HTTP) authorizeOperator(context *gin.Context) (auth.Account, bool) {
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
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Attention access is forbidden.")
		return auth.Account{}, false
	}
	return actor, true
}

func projectCase(item Case) httpCase {
	evidenceIDs := make([]string, 0, len(item.Evidence))
	for _, evidence := range item.Evidence {
		evidenceIDs = append(evidenceIDs, evidence.ObjectID)
	}
	return httpCase{
		ID: item.ID, StudentID: item.StudentID, RuleCode: item.RuleCode, Status: item.Status,
		EvidenceIDs: evidenceIDs, ConclusionCode: item.ConclusionCode, ConclusionReason: item.ConclusionReason,
		Version: item.Version, FirstTriggeredAt: item.FirstTriggeredAt,
	}
}

func writeHTTPProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Attention conclusion input is invalid.")
	case errors.Is(commandError, ErrNotFound):
		httpx.AbortProblem(context, http.StatusNotFound, "NOT_FOUND", "Attention case was not found.")
	case errors.Is(commandError, ErrVersionConflict):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Attention case state changed.")
	case errors.Is(commandError, ErrIdempotencyConflict):
		httpx.AbortProblem(context, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with another request.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Attention service is temporarily unavailable.")
	}
}
