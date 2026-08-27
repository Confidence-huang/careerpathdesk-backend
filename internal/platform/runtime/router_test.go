/*
HTTP 运行入口行为测试：从公开路由验证进程存活反馈不会暴露配置或依赖细节。
测试使用标准 httptest 发起真实 HTTP 请求，不读取内部路由结构。
调用示例：go test ./internal/platform/runtime -count=1。
*/
package runtime

import (
	"context"           // 构造数据库就绪检查的真实请求上下文。
	"errors"            // 模拟不包含数据库细节的依赖失败。
	"net/http"          // 构造与生产入口一致的 GET 请求。
	"net/http/httptest" // 在内存中记录完整 HTTP 反馈。
	"testing"           // 运行 Go 标准行为测试。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx" // 提供固定合成浏览器来源。
)

// --- 存活入口只返回最小事实 ---
func TestLivenessReturnsMinimalOK(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v2/health/live", nil) // 模拟反向代理探测版本化 API 进程。
	response := httptest.NewRecorder()                                         // 捕获状态、头部和公开响应正文。

	NewRouter(BuildInfo{Version: "test"}, Readiness{}, testBrowserSecurity(), nil).ServeHTTP(response, request) // 从公开构造入口走完整 HTTP 路径。

	if response.Code != http.StatusOK { // 存活进程必须稳定反馈 200。
		t.Fatalf("expected status 200, got %d", response.Code)
	}
	if response.Body.String() != "{\"status\":\"ok\"}" { // 响应不得泄露版本、数据库或环境配置。
		t.Fatalf("unexpected liveness body: %s", response.Body.String())
	}
	if response.Header().Get("X-Request-ID") == "" || response.Header().Get("Cache-Control") != "no-store" { // 健康入口也遵守统一反馈边界。
		t.Fatal("liveness response is missing foundation headers")
	}
}

// --- 数据库不可用时就绪入口失败关闭 ---
func TestReadinessRejectsUnavailableDatabase(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v2/health/ready", nil)                           // 模拟反向代理决定是否转发业务流量。
	response := httptest.NewRecorder()                                                                    // 捕获公开状态与最小反馈。
	checks := Readiness{Database: func(context.Context) error { return errors.New("synthetic failure") }} // 模拟不泄露细节的数据库失败。

	NewRouter(BuildInfo{Version: "test"}, checks, testBrowserSecurity(), nil).ServeHTTP(response, request) // 从公开构造入口走完整就绪路径。

	if response.Code != http.StatusServiceUnavailable { // 未证明数据库可用时必须拒绝接收业务流量。
		t.Fatalf("expected status 503, got %d", response.Code)
	}
	if response.Body.String() != "{\"status\":\"unavailable\"}" { // 反馈不得包含数据库地址、错误或版本。
		t.Fatalf("unexpected readiness body: %s", response.Body.String())
	}
}

func testBrowserSecurity() httpx.SecurityConfig {
	return httpx.SecurityConfig{PublicOrigin: "https://careerpathdesk.test"} // 测试只提供固定合成来源。
}
