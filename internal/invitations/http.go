/*
邀请 HTTP 入口：后台签发返回一次 fragment 链接，公开兑换把原始邀请换成路径受限 Cookie。
数据库和普通日志永远不接收链接；Cookie 与 CSRF 随机材料在提交兑换事务前准备。
*/
package invitations

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
)

const capabilityCookieName = "__Secure-p17_invitation"
const capabilityCookiePath = "/api/v2/public"

var ErrInvalidHTTPDependencies = errors.New("invitation HTTP dependencies are invalid")

type currentAccount func(*gin.Context) (auth.Account, error)

type HTTP struct {
	commands     *Commands
	current      currentAccount
	publicOrigin string
}

type issueHTTPInput struct {
	AssessmentVersion string `json:"assessment_version"`
	ExpiresInHours    int    `json:"expires_in_hours"`
}

type exchangeHTTPInput struct {
	Secret string `json:"secret"`
}

func NewHTTP(commands *Commands, current currentAccount, publicOrigin string) (*HTTP, error) {
	parsed, parseError := url.Parse(publicOrigin)
	if commands == nil || current == nil || parseError != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current, publicOrigin: strings.TrimRight(publicOrigin, "/")}, nil
}

func (entry *HTTP) Register(api *gin.RouterGroup) {
	api.POST("/students/:studentId/invitations", httpx.RequireIdempotencyKey(), entry.issue)
	api.POST("/invitations/:invitationId/revoke", entry.revoke)
	api.POST("/public/invitations/exchange", entry.exchange)
}

func (entry *HTTP) issue(context *gin.Context) {
	actor, ok := entry.authorize(context)
	if !ok {
		return
	}
	input := issueHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Invitation input is invalid.")
		return
	}
	created, commandError := entry.commands.Issue(context.Request.Context(), actor, httpx.RequestID(context), httpx.IdempotencyKey(context), context.Param("studentId"), IssueInput{
		AssessmentVersion: input.AssessmentVersion, ExpiresInHours: input.ExpiresInHours,
	})
	if commandError != nil {
		writeHTTPProblem(context, commandError)
		return
	}
	invitationURL := entry.publicOrigin + "/assessment#secret=" + url.QueryEscape(created.Secret)
	context.JSON(http.StatusCreated, gin.H{
		"data": gin.H{"invitation_id": created.ID, "invitation_url": invitationURL, "expires_at": created.ExpiresAt},
		"meta": gin.H{"request_id": httpx.RequestID(context)},
	})
}

func (entry *HTTP) revoke(context *gin.Context) {
	actor, ok := entry.authorize(context)
	if !ok {
		return
	}
	if commandError := entry.commands.Revoke(context.Request.Context(), actor, httpx.RequestID(context), context.Param("invitationId")); commandError != nil {
		writeHTTPProblem(context, commandError)
		return
	}
	clearCapabilityCookie(context)
	context.Status(http.StatusNoContent)
}

func (entry *HTTP) exchange(context *gin.Context) {
	input := exchangeHTTPInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		writeInvalidInvitation(context)
		return
	}
	csrfToken, randomError := newCSRFCapabilityToken()
	if randomError != nil {
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Invitation is temporarily unavailable.")
		return
	}
	capability, commandError := entry.commands.Exchange(context.Request.Context(), httpx.RequestID(context), input.Secret)
	if commandError != nil {
		writeInvalidInvitation(context)
		return
	}
	maxAge := int(time.Until(capability.ExpiresAt).Seconds())
	if maxAge < 1 || maxAge > int(restrictedSessionLifetime.Seconds()) {
		maxAge = int(restrictedSessionLifetime.Seconds())
	}
	http.SetCookie(context.Writer, &http.Cookie{
		Name: capabilityCookieName, Value: capability.ID + "." + capability.Secret, Path: capabilityCookiePath,
		MaxAge: maxAge, Expires: capability.ExpiresAt, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(context.Writer, &http.Cookie{
		Name: httpx.CSRFTokenCookieName, Value: csrfToken, Path: "/", MaxAge: maxAge, Expires: capability.ExpiresAt,
		HttpOnly: false, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	context.Status(http.StatusNoContent)
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
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Invitation access is forbidden.")
		return auth.Account{}, false
	}
	return actor, true
}

func writeHTTPProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Invitation access is forbidden.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Invitation input is invalid.")
	case errors.Is(commandError, ErrNotFound):
		httpx.AbortProblem(context, http.StatusNotFound, "NOT_FOUND", "Student or invitation was not found.")
	case errors.Is(commandError, ErrIdempotencyConflict):
		httpx.AbortProblem(context, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with another request.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Invitation service is temporarily unavailable.")
	}
}

func writeInvalidInvitation(context *gin.Context) {
	clearCapabilityCookie(context)
	httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Invitation cannot be used.")
}

func clearCapabilityCookie(context *gin.Context) {
	http.SetCookie(context.Writer, &http.Cookie{Name: capabilityCookieName, Value: "", Path: capabilityCookiePath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func newCSRFCapabilityToken() (string, error) {
	randomBytes := make([]byte, 32)
	if _, randomError := rand.Read(randomBytes); randomError != nil {
		return "", randomError
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
