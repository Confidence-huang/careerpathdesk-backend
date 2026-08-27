/*
账号管理 HTTP 合同测试：从生产 Gin 组合入口验证老板旅程、角色先行和响应隐私。
全部登录、账号和数据库事实都是隔离 synthetic 数据；测试不启动监听器或公网服务。
*/
package accounts

import (
	"context"           // 提供生产路由就绪探针的合成成功上下文。
	"crypto/ed25519"    // 为当前测试进程生成短生命周期访问令牌密钥。
	"crypto/rand"       // 提供测试签名密钥的系统随机材料。
	"encoding/json"     // 只解码公开账号 envelope 以继续版本化旅程。
	"fmt"               // 用服务器返回的责任档案 ID 形成后续版本化请求。
	"net/http"          // 构造冻结账户管理方法和状态断言。
	"net/http/httptest" // 从真实路由捕获公开 HTTP 反馈。
	"strings"           // 构造严格 JSON 并扫描敏感字段泄漏。
	"testing"           // 组织可独立运行的账号 HTTP 行为。
	"time"              // 为会话和 JWT 注入同一个固定 UTC 时刻。

	"github.com/gin-gonic/gin" // 组合认证与账号路由到同一版本组。
	"github.com/jackc/pgx/v5"  // 反馈隔离 synthetic 数据连接供旅程准备档案。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"                                // 建立真实登录 Cookie 和数据库会话。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"                      // 复用生产同源、CSRF 和请求身份边界。
	applicationruntime "github.com/confidence-huang/careerpathdesk-backend/internal/platform/runtime" // 从生产路由入口执行端到端合同。
)

const syntheticOrigin = "https://careerpathdesk.test" // 与测试路由唯一允许的同源值一致。

// --- 老板可完成账号创建、列表、停用和密码重置且反馈不泄密 ---
func TestOwnerAccountHTTPJourneyAndPrivacy(t *testing.T) {
	router, connection := newAccountsHTTPTestSystem(t)
	accessCookie, csrfCookie := loginAccountsActor(t, router, "synthetic-owner")

	createResponse := performAccountMutation(router, http.MethodPost, "/api/v2/accounts", `{
		"username":"synthetic-http-staff","display_name":"Synthetic HTTP Staff","role":"staff",
		"initial_password":"CareerPathDesk-Synthetic-HTTP-2026!"
	}`, accessCookie, csrfCookie, "synthetic-key-http-create-01")
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("unexpected account create response: status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	createdEnvelope := struct {
		Data Account `json:"data"`
	}{}
	if decodeError := json.Unmarshal(createResponse.Body.Bytes(), &createdEnvelope); decodeError != nil || createdEnvelope.Data.ID == "" || createdEnvelope.Data.StaffProfileID == nil || !validStaffProfileID(createdEnvelope.Data.StaffProfileID) || createdEnvelope.Data.Version != 1 {
		t.Fatalf("account create envelope is invalid: %#v %v", createdEnvelope, decodeError)
	}
	assertNoAccountSecrets(t, createResponse.Body.String())
	var profileState string
	if queryError := connection.QueryRow(t.Context(), `SELECT state FROM staff_profiles WHERE id = $1 AND display_name = 'Synthetic HTTP Staff'`, *createdEnvelope.Data.StaffProfileID).Scan(&profileState); queryError != nil || profileState != "active" {
		t.Fatalf("HTTP account creation omitted its active staff profile: state=%q error=%v", profileState, queryError)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v2/accounts", nil)
	listRequest.AddCookie(accessCookie)
	listResponse := httptest.NewRecorder()
	router.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), createdEnvelope.Data.ID) {
		t.Fatalf("created account missing from list: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	assertNoAccountSecrets(t, listResponse.Body.String())

	updateBody := fmt.Sprintf(`{"state":"disabled","staff_profile_id":%q,"version":1}`, *createdEnvelope.Data.StaffProfileID)
	updateResponse := performAccountMutation(router, http.MethodPatch, "/api/v2/accounts/"+createdEnvelope.Data.ID, updateBody, accessCookie, csrfCookie, "")
	if updateResponse.Code != http.StatusOK || !strings.Contains(updateResponse.Body.String(), `"state":"disabled"`) || !strings.Contains(updateResponse.Body.String(), `"version":2`) {
		t.Fatalf("unexpected account disable response: status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
	assertNoAccountSecrets(t, updateResponse.Body.String())

	resetResponse := performAccountMutation(router, http.MethodPost, "/api/v2/accounts/"+createdEnvelope.Data.ID+"/reset-password", `{"initial_password":"CareerPathDesk-Synthetic-Reset-HTTP-2026!"}`, accessCookie, csrfCookie, "")
	if resetResponse.Code != http.StatusNoContent || resetResponse.Body.Len() != 0 {
		t.Fatalf("unexpected reset response: status=%d body=%s", resetResponse.Code, resetResponse.Body.String())
	}
}

// --- 老师只修改本人显示名称，登录用户名与当前会话保持有效 ---
func TestStaffCanRenameOwnDisplayNameThroughPublicHTTP(t *testing.T) {
	router, connection := newAccountsHTTPTestSystem(t)
	accessCookie, csrfCookie := loginAccountsActor(t, router, "synthetic-staff-one")

	renameResponse := performAccountMutation(router, http.MethodPatch, "/api/v2/accounts/me", `{"display_name":"  Ｌ老师  "}`, accessCookie, csrfCookie, "")
	if renameResponse.Code != http.StatusOK || !strings.Contains(renameResponse.Body.String(), `"display_name":"L老师"`) || !strings.Contains(renameResponse.Body.String(), `"username":"synthetic-staff-one"`) {
		t.Fatalf("staff self rename failed: status=%d body=%s", renameResponse.Code, renameResponse.Body.String())
	}
	assertNoAccountSecrets(t, renameResponse.Body.String())

	meRequest := httptest.NewRequest(http.MethodGet, "/api/v2/auth/me", nil)
	meRequest.AddCookie(accessCookie)
	meResponse := httptest.NewRecorder()
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusOK || !strings.Contains(meResponse.Body.String(), `"display_name":"L老师"`) || !strings.Contains(meResponse.Body.String(), `"username":"synthetic-staff-one"`) {
		t.Fatalf("renamed staff was not visible through current session: status=%d body=%s", meResponse.Code, meResponse.Body.String())
	}
	var synchronizedFacts int
	if queryError := connection.QueryRow(t.Context(), `
		SELECT count(*) FROM accounts AS a
		JOIN staff_profiles AS s ON s.id = a.staff_profile_id
		WHERE a.id = 'A-syntheticstaff01' AND a.display_name = 'L老师' AND s.display_name = 'L老师'
	`).Scan(&synchronizedFacts); queryError != nil || synchronizedFacts != 1 {
		t.Fatalf("staff account and responsibility profile names diverged: count=%d error=%v", synchronizedFacts, queryError)
	}
	var auditCount int
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE actor_id = 'A-syntheticstaff01' AND action = 'account.display_name_changed' AND object_id = 'A-syntheticstaff01'`).Scan(&auditCount); queryError != nil || auditCount != 1 {
		t.Fatalf("staff self rename audit is incomplete: count=%d error=%v", auditCount, queryError)
	}
}

// --- 老板与老师共用同一本人改名合同 ---
func TestOwnerCanRenameOwnDisplayNameThroughPublicHTTP(t *testing.T) {
	router, _ := newAccountsHTTPTestSystem(t)
	accessCookie, csrfCookie := loginAccountsActor(t, router, "synthetic-owner")

	renameResponse := performAccountMutation(router, http.MethodPatch, "/api/v2/accounts/me", `{"display_name":"合成新负责人"}`, accessCookie, csrfCookie, "")
	if renameResponse.Code != http.StatusOK || !strings.Contains(renameResponse.Body.String(), `"display_name":"合成新负责人"`) || !strings.Contains(renameResponse.Body.String(), `"username":"synthetic-owner"`) {
		t.Fatalf("owner self rename failed: status=%d body=%s", renameResponse.Code, renameResponse.Body.String())
	}
	assertNoAccountSecrets(t, renameResponse.Body.String())
}

// --- 员工在非法正文或未知目标被读取前得到同一老板专属拒绝 ---
func TestStaffAccountHTTPAuthorizationRunsBeforeBodyAndTargetParsing(t *testing.T) {
	router, _ := newAccountsHTTPTestSystem(t)
	accessCookie, csrfCookie := loginAccountsActor(t, router, "synthetic-staff-one")

	createResponse := performAccountMutation(router, http.MethodPost, "/api/v2/accounts", `{not-json`, accessCookie, csrfCookie, "synthetic-key-staff-http-01")
	if createResponse.Code != http.StatusForbidden || !strings.Contains(createResponse.Body.String(), `"code":"FORBIDDEN"`) {
		t.Fatalf("staff create was not rejected role-first: status=%d body=%s", createResponse.Code, createResponse.Body.String())
	}
	updateResponse := performAccountMutation(router, http.MethodPatch, "/api/v2/accounts/A-does-not-exist", `{not-json`, accessCookie, csrfCookie, "")
	if updateResponse.Code != http.StatusForbidden || !strings.Contains(updateResponse.Body.String(), `"code":"FORBIDDEN"`) {
		t.Fatalf("staff update was not rejected role-first: status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}
}

// --- 装配共享真实 PostgreSQL 的认证和账号 HTTP 模块 ---
func newAccountsHTTPTestSystem(t *testing.T) (http.Handler, *pgx.Conn) {
	t.Helper()
	connection := openAccountsTestDatabase(t)
	if _, updateError := connection.Exec(t.Context(), `UPDATE accounts SET must_change_password = false WHERE id IN ('A-syntheticowner01', 'A-syntheticstaff01')`); updateError != nil {
		t.Fatal("synthetic account activation failed")
	}
	fixedNow := time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC)
	sessions, sessionError := auth.NewSessionCommands(connection, func() time.Time { return fixedNow })
	if sessionError != nil {
		t.Fatalf("synthetic sessions failed to initialize: %v", sessionError)
	}
	publicKey, privateKey, keyError := ed25519.GenerateKey(rand.Reader)
	if keyError != nil {
		t.Fatal("synthetic access token keys unavailable")
	}
	tokens, tokenError := auth.NewAccessTokens(
		auth.AccessTokenKeys{Private: privateKey, Public: publicKey},
		func() time.Time { return fixedNow },
		func() (string, error) { return "JTI-syntheticaccounts01", nil },
	)
	if tokenError != nil {
		t.Fatalf("synthetic access tokens failed to initialize: %v", tokenError)
	}
	authentication, authenticationError := auth.NewHTTP(sessions, tokens)
	if authenticationError != nil {
		t.Fatalf("synthetic authentication HTTP failed to initialize: %v", authenticationError)
	}
	commands := newAccountsTestCommands(t, connection)
	management, managementError := NewHTTP(commands, authentication.CurrentAccount)
	if managementError != nil {
		t.Fatalf("synthetic account HTTP failed to initialize: %v", managementError)
	}
	router := applicationruntime.NewRouter(
		applicationruntime.BuildInfo{Version: "test"},
		applicationruntime.Readiness{Database: func(_ context.Context) error { return nil }},
		httpx.SecurityConfig{PublicOrigin: syntheticOrigin},
		func(versionedAPI *gin.RouterGroup) {
			authentication.Register(versionedAPI)
			management.Register(versionedAPI)
		},
	)
	return router, connection
}

// --- 使用公开登录入口取得后续账号管理所需 Cookie ---
func loginAccountsActor(t *testing.T, router http.Handler, username string) (*http.Cookie, *http.Cookie) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(`{"username":"`+username+`","password":"`+syntheticInitialPassword+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", syntheticOrigin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("synthetic actor login failed: status=%d body=%s", response.Code, response.Body.String())
	}
	accessCookie := findAccountCookie(response.Result().Cookies(), "__Host-p17_access")
	csrfCookie := findAccountCookie(response.Result().Cookies(), httpx.CSRFTokenCookieName)
	if accessCookie == nil || csrfCookie == nil {
		t.Fatal("synthetic actor login omitted required cookies")
	}
	return accessCookie, csrfCookie
}

// --- 执行一条已登录、同源且通过 CSRF 的账号写请求 ---
func performAccountMutation(router http.Handler, method string, path string, body string, accessCookie *http.Cookie, csrfCookie *http.Cookie, idempotencyKey string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", syntheticOrigin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	request.AddCookie(accessCookie)
	request.AddCookie(csrfCookie)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// --- 账号公开反馈不得包含密码、内部比较键或会话秘密 ---
func assertNoAccountSecrets(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{"initial_password", "password_hash", "username_normalized", "refresh_token", "CareerPathDesk-Synthetic"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("account response exposed forbidden material %q", forbidden)
		}
	}
}

// --- 按固定 Cookie 名称读取浏览器反馈 ---
func findAccountCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
