/* 运营 HTTP 入口：把统计、最小审计和当前会话绑定的一次导出映射到同一 Commands 深模块。 */
package operations

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
)

var ErrInvalidHTTPDependencies = errors.New("operations HTTP dependencies are invalid")

type currentPrincipal func(*gin.Context) (auth.Account, string, error)

type HTTP struct {
	commands *Commands
	current  currentPrincipal
}

type exportConfirmationHTTPInput struct {
	ExportType string `json:"export_type"`
}

func NewHTTP(commands *Commands, current currentPrincipal) (*HTTP, error) {
	if commands == nil || current == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current}, nil
}

func (entry *HTTP) Register(api *gin.RouterGroup) {
	api.GET("/audit-events", entry.listAudit)
	api.GET("/statistics/overview", entry.statistics)
	api.POST("/exports/confirmations", entry.createConfirmation)
	api.POST("/exports/:exportType", entry.runExport)
}

func (entry *HTTP) listAudit(context *gin.Context) {
	actor, _, ok := entry.authorize(context)
	if !ok {
		return
	}
	if actor.Role != "owner" {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
		return
	}
	limit := 30
	if raw := context.Query("limit"); raw != "" {
		parsed, parseError := strconv.Atoi(raw)
		if parseError != nil {
			httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Audit query is invalid.")
			return
		}
		limit = parsed
	}
	page, commandError := entry.commands.ListAuditEvents(context.Request.Context(), actor, AuditQuery{
		Action: context.Query("action"), ObjectType: context.Query("object_type"), Cursor: context.Query("cursor"), Limit: limit,
	})
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	noStore(context)
	context.JSON(http.StatusOK, gin.H{"data": page.Events, "meta": gin.H{"request_id": httpx.RequestID(context), "next_cursor": page.NextCursor}})
}

func (entry *HTTP) statistics(context *gin.Context) {
	actor, _, ok := entry.authorize(context)
	if !ok {
		return
	}
	statistics, commandError := entry.commands.Overview(context.Request.Context(), actor)
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	noStore(context)
	context.JSON(http.StatusOK, gin.H{"data": statistics, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) createConfirmation(context *gin.Context) {
	actor, sessionID, ok := entry.authorize(context)
	if !ok {
		return
	}
	if actor.Role != "owner" {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
		return
	}
	input := exportConfirmationHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Export confirmation input is invalid.")
		return
	}
	confirmation, commandError := entry.commands.CreateExportConfirmation(context.Request.Context(), actor, ExportConfirmationInput{SessionID: sessionID, ExportType: input.ExportType})
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	noStore(context)
	context.JSON(http.StatusCreated, gin.H{
		"data": gin.H{"confirmation": confirmation.Confirmation, "expires_at": confirmation.ExpiresAt},
		"meta": gin.H{"request_id": httpx.RequestID(context)},
	})
}

func (entry *HTTP) runExport(context *gin.Context) {
	actor, sessionID, ok := entry.authorize(context)
	if !ok {
		return
	}
	if actor.Role != "owner" {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
		return
	}
	exportType := context.Param("exportType")
	artifact, commandError := entry.commands.RunExport(context.Request.Context(), actor, RunExportInput{
		SessionID: sessionID, ExportType: exportType, Confirmation: context.GetHeader("X-Export-Confirmation"), RequestID: httpx.RequestID(context),
	})
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	noStore(context)
	context.Header("Content-Type", artifact.MediaType)
	context.Header("Content-Disposition", `attachment; filename="careerpathdesk-`+exportType+`-export.xlsx"`)
	context.Data(http.StatusOK, artifact.MediaType, artifact.Body)
}

func (entry *HTTP) authorize(context *gin.Context) (auth.Account, string, bool) {
	actor, sessionID, authenticationError := entry.current(context)
	if authenticationError != nil {
		httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return auth.Account{}, "", false
	}
	if actor.MustChangePassword {
		httpx.AbortProblem(context, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Password change is required.")
		return auth.Account{}, "", false
	}
	if actor.State != "active" || (actor.Role != "owner" && actor.Role != "staff") || sessionID == "" {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Operations access is forbidden.")
		return auth.Account{}, "", false
	}
	return actor, sessionID, true
}

func (entry *HTTP) writeProblem(context *gin.Context, commandError error) {
	noStore(context)
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Operations access is forbidden.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Operations input is invalid.")
	case errors.Is(commandError, ErrExportConfirmationUnavailable):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Export confirmation is unavailable.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Operations service is temporarily unavailable.")
	}
}

func noStore(context *gin.Context) {
	context.Header("Cache-Control", "no-store")
	context.Header("Pragma", "no-cache")
}
