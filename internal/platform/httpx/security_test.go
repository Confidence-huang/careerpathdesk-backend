/*
浏览器写请求安全测试：验证 Origin、Fetch Metadata、双提交 CSRF 和创建幂等键。
所有请求均为 httptest 合成流量，不启动端口、不使用账号或业务数据。
*/
package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

const syntheticOrigin = "https://careerpathdesk.test"

// --- 正确同源与 CSRF 证据允许受保护写请求 ---
func TestBrowserMutationSecurityAcceptsSameOriginCSRF(t *testing.T) {
	router := securityTestRouter()
	response := performMutation(router, "/api/v2/students", syntheticOrigin, "same-origin", "synthetic-csrf-value-1234567890123456", "synthetic-csrf-value-1234567890123456")
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected protected mutation 204, got %d body=%s", response.Code, response.Body.String())
	}
}

// --- 错误来源在业务 handler 前被拒绝 ---
func TestBrowserMutationSecurityRejectsWrongOrigin(t *testing.T) {
	router := securityTestRouter()
	response := performMutation(router, "/api/v2/students", "https://wrong.test", "same-origin", "synthetic-csrf-value-1234567890123456", "synthetic-csrf-value-1234567890123456")
	if response.Code != http.StatusForbidden || !bodyHasCode(response.Body.String(), "origin_rejected") {
		t.Fatalf("expected origin rejection, got status=%d body=%s", response.Code, response.Body.String())
	}
}

// --- Fetch Metadata 指示跨站时即使 Origin 正确也拒绝 ---
func TestBrowserMutationSecurityRejectsCrossSiteFetch(t *testing.T) {
	router := securityTestRouter()
	response := performMutation(router, "/api/v2/students", syntheticOrigin, "cross-site", "synthetic-csrf-value-1234567890123456", "synthetic-csrf-value-1234567890123456")
	if response.Code != http.StatusForbidden || !bodyHasCode(response.Body.String(), "origin_rejected") {
		t.Fatalf("expected cross-site rejection, got status=%d body=%s", response.Code, response.Body.String())
	}
}

// --- 受保护写请求缺失匹配 CSRF 时拒绝 ---
func TestBrowserMutationSecurityRejectsMissingCSRF(t *testing.T) {
	router := securityTestRouter()
	response := performMutation(router, "/api/v2/students", syntheticOrigin, "same-origin", "", "")
	if response.Code != http.StatusForbidden || !bodyHasCode(response.Body.String(), "csrf_rejected") {
		t.Fatalf("expected CSRF rejection, got status=%d body=%s", response.Code, response.Body.String())
	}
}

// --- 登录仅要求同源证据，因为成功前尚无 CSRF Cookie ---
func TestBrowserMutationSecurityAllowsLoginWithoutCSRF(t *testing.T) {
	router := securityTestRouter()
	response := performMutation(router, "/api/v2/auth/login", syntheticOrigin, "same-origin", "", "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected login mutation 204, got %d body=%s", response.Code, response.Body.String())
	}
}

// --- 三个 MFA 会话前端点只要求同源证据，不错误依赖尚未签发的 CSRF Cookie ---
func TestBrowserMutationSecurityAllowsPreSessionMFAWithoutCSRF(t *testing.T) {
	router := securityTestRouter()
	for _, path := range []string{
		"/api/v2/auth/mfa/enrollment",
		"/api/v2/auth/mfa/enrollment/confirm",
		"/api/v2/auth/mfa/verify",
	} {
		response := performMutation(router, path, syntheticOrigin, "same-origin", "", "")
		if response.Code != http.StatusNoContent {
			t.Fatalf("expected pre-session MFA mutation %s to pass, got %d body=%s", path, response.Code, response.Body.String())
		}
	}
}

// --- 创建入口拒绝缺失或过短幂等键并反馈已验证键 ---
func TestRequireIdempotencyKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Foundation(func() (string, error) { return "R-idempotencytest", nil }))
	router.POST("/create", RequireIdempotencyKey(), func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"key": IdempotencyKey(context)})
	})

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/create", nil))
	if missing.Code != http.StatusBadRequest || !bodyHasCode(missing.Body.String(), "idempotency_key_required") {
		t.Fatalf("expected missing key rejection, got status=%d body=%s", missing.Code, missing.Body.String())
	}

	acceptedRequest := httptest.NewRequest(http.MethodPost, "/create", nil)
	acceptedRequest.Header.Set("Idempotency-Key", "synthetic-key-1234567890")
	accepted := httptest.NewRecorder()
	router.ServeHTTP(accepted, acceptedRequest)
	if accepted.Code != http.StatusOK || accepted.Body.String() != "{\"key\":\"synthetic-key-1234567890\"}" {
		t.Fatalf("unexpected accepted idempotency response: status=%d body=%s", accepted.Code, accepted.Body.String())
	}
}

func securityTestRouter() http.Handler {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Foundation(func() (string, error) { return "R-securitytest", nil }))
	router.Use(BrowserMutationSecurity(SecurityConfig{PublicOrigin: syntheticOrigin}))
	router.POST("/api/v2/students", func(context *gin.Context) { context.Status(http.StatusNoContent) })
	router.POST("/api/v2/auth/login", func(context *gin.Context) { context.Status(http.StatusNoContent) })
	router.POST("/api/v2/auth/mfa/enrollment", func(context *gin.Context) { context.Status(http.StatusNoContent) })
	router.POST("/api/v2/auth/mfa/enrollment/confirm", func(context *gin.Context) { context.Status(http.StatusNoContent) })
	router.POST("/api/v2/auth/mfa/verify", func(context *gin.Context) { context.Status(http.StatusNoContent) })
	return router
}

func performMutation(router http.Handler, path string, origin string, fetchSite string, csrfCookie string, csrfHeader string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Origin", origin)
	request.Header.Set("Sec-Fetch-Site", fetchSite)
	if csrfCookie != "" {
		request.AddCookie(&http.Cookie{Name: CSRFTokenCookieName, Value: csrfCookie})
	}
	if csrfHeader != "" {
		request.Header.Set("X-CSRF-Token", csrfHeader)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func bodyHasCode(body string, code string) bool {
	return len(body) > 0 && contains(body, `"code":"`+code+`"`)
}

func contains(value string, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
