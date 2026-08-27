/* 受邀测评 HTTP 入口：只相信路径受限能力 Cookie，并反馈空白表单或一个完成布尔值。 */
package assessments

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/invitations"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
)

const invitationCookieName = "__Secure-p17_invitation"
const invitationCookiePath = "/api/v2/public"

var ErrInvalidHTTPDependencies = errors.New("assessment HTTP dependencies are invalid")

type HTTP struct {
	capabilities *invitations.Commands
	commands     *Commands
}

type submitHTTPInput struct {
	AssessmentVersion string             `json:"assessment_version"`
	StudentFields     map[string]*string `json:"student_fields"`
	Answers           map[string]string  `json:"answers"`
}

func NewHTTP(capabilities *invitations.Commands, commands *Commands) (*HTTP, error) {
	if capabilities == nil || commands == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{capabilities: capabilities, commands: commands}, nil
}

func (entry *HTTP) Register(api *gin.RouterGroup) {
	api.GET("/public/assessment", entry.form)
	api.POST("/public/assessment", httpx.RequireIdempotencyKey(), entry.submit)
}

func (entry *HTTP) form(context *gin.Context) {
	capability, ok := entry.readCapability(context)
	if !ok {
		return
	}
	form, commandError := entry.commands.Form(context.Request.Context(), capability)
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	context.JSON(http.StatusOK, gin.H{"data": form, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) submit(context *gin.Context) {
	capability, ok := entry.readCapability(context)
	if !ok {
		return
	}
	input := submitHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 65536); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Assessment input is invalid.")
		return
	}
	receipt, commandError := entry.commands.Submit(context.Request.Context(), capability, httpx.RequestID(context), httpx.IdempotencyKey(context), SubmitInput{
		AssessmentVersion: input.AssessmentVersion, StudentFields: input.StudentFields, Answers: input.Answers,
	})
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	clearInvitationCookie(context)
	context.JSON(http.StatusOK, gin.H{"data": receipt, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

func (entry *HTTP) readCapability(context *gin.Context) (Capability, bool) {
	value, cookieError := context.Cookie(invitationCookieName)
	separator := strings.IndexByte(value, '.')
	if cookieError != nil || separator < 1 || separator == len(value)-1 || strings.Count(value, ".") != 1 {
		entry.writeProblem(context, ErrInvalidCapability)
		return Capability{}, false
	}
	capability := Capability{ID: value[:separator], Secret: value[separator+1:]}
	if _, resolveError := entry.capabilities.Resolve(context.Request.Context(), capability.ID, capability.Secret); resolveError != nil {
		entry.writeProblem(context, ErrInvalidCapability)
		return Capability{}, false
	}
	return capability, true
}

func (entry *HTTP) writeProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrInvalidCapability):
		clearInvitationCookie(context)
		httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Invitation session is unavailable.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Assessment input is invalid.")
	case errors.Is(commandError, ErrVersionConflict):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Student information changed.")
	case errors.Is(commandError, ErrIdempotencyConflict):
		httpx.AbortProblem(context, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with another request.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Assessment is temporarily unavailable.")
	}
}

func clearInvitationCookie(context *gin.Context) {
	http.SetCookie(context.Writer, &http.Cookie{
		Name: invitationCookieName, Value: "", Path: invitationCookiePath, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}
