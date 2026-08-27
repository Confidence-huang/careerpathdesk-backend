/*
HTTP 基础反馈测试：通过真实 Gin 请求证明请求身份、安全头和固定错误 envelope。
测试只使用合成路径和固定错误码，不启动监听器或记录请求正文。
*/
package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// --- 每个响应携带同一个服务端请求身份和安全头 ---
func TestFoundationMiddlewareSetsRequestIdentityAndSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Foundation(func() (string, error) { return "R-syntheticrequest", nil }))
	router.GET("/probe", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"requestId": RequestID(context)})
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/probe", nil))

	if response.Code != http.StatusOK || response.Header().Get("X-Request-ID") != "R-syntheticrequest" {
		t.Fatalf("unexpected request identity response: status=%d id=%q", response.Code, response.Header().Get("X-Request-ID"))
	}
	expectedHeaders := map[string]string{
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
	}
	for name, expected := range expectedHeaders {
		if actual := response.Header().Get(name); actual != expected {
			t.Fatalf("header %s: expected %q, got %q", name, expected, actual)
		}
	}
	if response.Body.String() != "{\"requestId\":\"R-syntheticrequest\"}" {
		t.Fatalf("unexpected response body: %s", response.Body.String())
	}
}

// --- 业务失败只暴露稳定码、普通说明和请求身份 ---
func TestAbortProblemUsesFixedEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Foundation(func() (string, error) { return "R-problemrequest", nil }))
	router.GET("/probe", func(context *gin.Context) {
		AbortProblem(context, http.StatusConflict, "version_conflict", "The resource changed. Retry from the latest version.")
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/probe", nil))

	expected := "{\"error\":{\"code\":\"version_conflict\",\"message\":\"The resource changed. Retry from the latest version.\",\"request_id\":\"R-problemrequest\"}}"
	if response.Code != http.StatusConflict || response.Body.String() != expected {
		t.Fatalf("unexpected problem response: status=%d body=%s", response.Code, response.Body.String())
	}
}

// --- 请求身份生成失败时不进入业务 handler ---
func TestFoundationMiddlewareFailsClosedWithoutRequestIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(Foundation(func() (string, error) { return "", errors.New("synthetic identity failure") }))
	reachedHandler := false
	router.GET("/probe", func(context *gin.Context) { reachedHandler = true })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/probe", nil))

	if response.Code != http.StatusServiceUnavailable || reachedHandler {
		t.Fatalf("identity failure did not close request: status=%d reached=%v", response.Code, reachedHandler)
	}
}
