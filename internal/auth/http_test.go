/*
认证 HTTP 行为测试：从真实 Gin 路由和隔离 PostgreSQL 验证浏览器登录反馈、Cookie 安全属性与响应隐私。
测试只使用公开 synthetic 账号；响应断言不输出访问令牌、刷新秘密、密码 hash 或数据库行。
*/
package auth

import (
	"context"           // 为生产路由注入成功的合成 readiness 检查。
	"crypto/ed25519"    // 为本测试生成独立 Ed25519 访问令牌密钥。
	"crypto/rand"       // 只向 Ed25519 系统边界提供密码学随机源。
	"encoding/json"     // 解码公开登录 envelope，不读取内部命令结构。
	"errors"            // 构造不含秘密的合成依赖失败。
	"net/http"          // 构造与浏览器一致的登录请求和 Cookie 断言。
	"net/http/httptest" // 捕获完整 Gin HTTP 状态、头、Cookie 和 JSON 反馈。
	"strings"           // 构造固定 synthetic JSON 正文并执行敏感字段扫描。
	"testing"           // 运行 Go 标准 HTTP 集成测试。
	"time"              // 固定 JWT、会话和 Cookie 的可信 UTC 时间。

	"github.com/gin-gonic/gin" // 直接构造传输层上下文验证密码长度合同。
	"github.com/jackc/pgx/v5"  // 实现只记录事务触达的测试数据库边界。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"                      // 建立请求身份和同源写请求门禁。
	applicationruntime "github.com/confidence-huang/careerpathdesk-backend/internal/platform/runtime" // 通过生产组合入口注册认证路由。
)

// --- 登录和改密传输层共享六至一百二十八字符边界 ---
func TestSixRunePasswordInputsPassHTTPValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	loginContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	loginContext.Request = httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(`{"username":"synthetic-owner","password":"六六六六六六"}`))
	loginContext.Request.Header.Set("Content-Type", "application/json")
	if _, inputError := readLoginInput(loginContext); inputError != nil {
		t.Fatal("six-rune login password was rejected by HTTP validation")
	}

	changeContext, _ := gin.CreateTestContext(httptest.NewRecorder())
	changeContext.Request = httptest.NewRequest(http.MethodPut, "/api/v2/auth/password", strings.NewReader(`{"current_password":"旧旧旧旧旧旧","new_password":"新新新新新新"}`))
	changeContext.Request.Header.Set("Content-Type", "application/json")
	if _, inputError := readChangePasswordInput(changeContext); inputError != nil {
		t.Fatal("six-rune password change was rejected by HTTP validation")
	}
}

// --- 正确逐人凭据返回最小账号状态并设置三个安全 Cookie ---
func TestLoginReturnsAccountAndSecureCookies(t *testing.T) {
	authentication, tokens := newAuthenticationTestHTTP(t) // 装配本测试独享的真实数据库和签名边界。
	router := newAuthenticationTestRouter(authentication)  // 通过公开路由入口测试，不直接调用 handler。

	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(`{"username":"synthetic-owner","password":"CareerPathDesk-Test-Only!"}`)) // 登录只使用本测试 seed 凭据。
	request.Header.Set("Content-Type", "application/json")                                                                                                       // 登录只接受明确 JSON。
	request.Header.Set("Origin", "https://careerpathdesk.test")                                                                                                  // 模拟 Caddy 同源 HTTPS 页面。
	request.Header.Set("Sec-Fetch-Site", "same-origin")                                                                                                          // 提供浏览器 Fetch Metadata 证据。
	request.Header.Set("User-Agent", "Synthetic Browser Test/1.0")                                                                                               // 只保存非敏感设备摘要。
	response := httptest.NewRecorder()                                                                                                                           // 捕获公开效果反馈。
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK { // 正确凭据必须建立浏览器会话。
		t.Fatalf("expected login status 200, got %d", response.Code)
	}
	var envelope struct {
		Data struct {
			Account struct {
				ID                 string  `json:"id"`                   // ID 是后续权限命令使用的账号身份。
				Username           string  `json:"username"`             // Username 只返回合法显示形式。
				Role               string  `json:"role"`                 // Role 供客户端展示入口，不替代服务端授权。
				State              string  `json:"state"`                // State 必须是当前数据库事实。
				CredentialVersion  int64   `json:"credential_version"`   // CredentialVersion 绑定新 JWT 和会话。
				MustChangePassword bool    `json:"must_change_password"` // 合成初始账号只能进入改密旅程。
				StaffProfileID     *string `json:"staff_profile_id"`     // 老板账号没有员工责任档案。
			} `json:"account"`
		} `json:"data"`
		Meta struct {
			RequestID string `json:"request_id"` // Meta 关联本次服务端请求身份。
		} `json:"meta"`
	}
	if decodeError := json.Unmarshal(response.Body.Bytes(), &envelope); decodeError != nil {
		t.Fatal("login response is not valid JSON")
	}
	if envelope.Data.Account.ID != "A-syntheticowner01" || envelope.Data.Account.Username != "synthetic-owner" || envelope.Data.Account.Role != "owner" || envelope.Data.Account.State != "active" { // 响应只能投影当前合成账号事实。
		t.Fatalf("unexpected synthetic account projection: id=%q role=%q state=%q", envelope.Data.Account.ID, envelope.Data.Account.Role, envelope.Data.Account.State)
	}
	if envelope.Data.Account.CredentialVersion != 1 || !envelope.Data.Account.MustChangePassword || envelope.Data.Account.StaffProfileID != nil || envelope.Meta.RequestID == "" { // 首次登录和请求身份合同必须完整。
		t.Fatal("login response omitted credential, first-change, staff-scope, or request identity facts")
	}
	if strings.Contains(response.Body.String(), "password_hash") || strings.Contains(response.Body.String(), "CareerPathDesk-Synthetic") || strings.Contains(response.Body.String(), "refresh_token") || strings.Contains(response.Body.String(), "access_token") { // JSON 正文不得复制任何认证材料。
		t.Fatal("login response body exposed authentication material")
	}

	cookies := response.Result().Cookies() // 只读取浏览器会收到的公开 Cookie 属性。
	accessCookie := findCookie(cookies, "__Host-p17_access")
	refreshCookie := findCookie(cookies, "__Secure-p17_refresh")
	csrfCookie := findCookie(cookies, httpx.CSRFTokenCookieName)
	if accessCookie == nil || refreshCookie == nil || csrfCookie == nil {
		t.Fatal("login response omitted an authentication cookie")
	}
	if !accessCookie.Secure || !accessCookie.HttpOnly || accessCookie.SameSite != http.SameSiteLaxMode || accessCookie.Path != "/" { // 访问 JWT 只能由同源 HTTPS 请求自动携带。
		t.Fatal("access cookie security attributes are incomplete")
	}
	if !refreshCookie.Secure || !refreshCookie.HttpOnly || refreshCookie.SameSite != http.SameSiteLaxMode || refreshCookie.Path != "/api/v2/auth" { // 刷新秘密只发送给认证路由。
		t.Fatal("refresh cookie security attributes are incomplete")
	}
	if !csrfCookie.Secure || csrfCookie.HttpOnly || csrfCookie.SameSite != http.SameSiteLaxMode || csrfCookie.Path != "/" || len(csrfCookie.Value) < 32 { // CSRF 值必须可由同源前端读取并回送。
		t.Fatal("csrf cookie security attributes are incomplete")
	}
	claims, verifyError := tokens.Verify(accessCookie.Value)
	if verifyError != nil || claims.AccountID != "A-syntheticowner01" || claims.CredentialVersion != 1 { // Cookie 中必须是已签名且绑定新会话的五分钟 JWT。
		t.Fatal("access cookie does not contain the expected signed session")
	}
}

// --- 生产登录只返回无秘密的 202 下一步，并把 challenge 收敛到五分钟 Strict Cookie ---
func TestLoginRequiresMFAHTTPChallengeBeforeSessionCookies(t *testing.T) {
	authentication := newMFAAuthenticationTestHTTP(t)
	response := performSyntheticLogin(newAuthenticationTestRouter(authentication))
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"code":"MFA_ENROLLMENT_REQUIRED"`) {
		t.Fatalf("expected MFA enrollment response, got status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "CareerPathDesk-Test-Only") || strings.Contains(response.Body.String(), "challenge") {
		t.Fatal("MFA login response exposed password or raw challenge")
	}
	cookies := response.Result().Cookies()
	challengeCookie := findCookie(cookies, mfaChallengeCookieName)
	if challengeCookie == nil || challengeCookie.Value == "" || !challengeCookie.HttpOnly || !challengeCookie.Secure || challengeCookie.SameSite != http.SameSiteStrictMode || challengeCookie.Path != "/api/v2/auth/mfa" || challengeCookie.MaxAge != 300 {
		t.Fatal("MFA challenge cookie security attributes are incomplete")
	}
	if findCookie(cookies, accessCookieName) != nil || findCookie(cookies, refreshCookieName) != nil || findCookie(cookies, httpx.CSRFTokenCookieName) != nil {
		t.Fatal("password-only MFA response issued normal session cookies")
	}
}

// --- MFA 注册端点在会话前凭同源 challenge Cookie 返回无持久会话的注册材料 ---
func TestMFAEnrollmentHTTPUsesPreSessionChallengeCookie(t *testing.T) {
	authentication := newMFAAuthenticationTestHTTP(t)
	router := newAuthenticationTestRouter(authentication)
	loginResponse := performSyntheticLogin(router)
	challengeCookie := findCookie(loginResponse.Result().Cookies(), mfaChallengeCookieName)
	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/mfa/enrollment", nil)
	request.Header.Set("Origin", "https://careerpathdesk.test")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(challengeCookie)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"otpauth_uri":"otpauth://totp/`) || !strings.Contains(response.Body.String(), `"manual_key":`) {
		t.Fatalf("expected MFA enrollment material, got status=%d body=%s", response.Code, response.Body.String())
	}
	if findCookie(response.Result().Cookies(), accessCookieName) != nil || findCookie(response.Result().Cookies(), refreshCookieName) != nil {
		t.Fatal("enrollment material endpoint issued a normal session")
	}
}

// --- 注册确认成功后才签发正常会话，恢复码只在该响应出现一次 ---
func TestMFAEnrollmentConfirmationHTTPReturnsSessionAndRecoveryCodesOnce(t *testing.T) {
	authentication := newMFAAuthenticationTestHTTP(t)
	router := newAuthenticationTestRouter(authentication)
	loginResponse := performSyntheticLogin(router)
	challengeCookie := findCookie(loginResponse.Result().Cookies(), mfaChallengeCookieName)
	enrollmentRequest := httptest.NewRequest(http.MethodPost, "/api/v2/auth/mfa/enrollment", nil)
	enrollmentRequest.Header.Set("Origin", "https://careerpathdesk.test")
	enrollmentRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	enrollmentRequest.AddCookie(challengeCookie)
	enrollmentResponse := httptest.NewRecorder()
	router.ServeHTTP(enrollmentResponse, enrollmentRequest)
	var enrollmentEnvelope struct {
		Data Enrollment `json:"data"`
	}
	if decodeError := json.Unmarshal(enrollmentResponse.Body.Bytes(), &enrollmentEnvelope); decodeError != nil {
		t.Fatal("MFA enrollment response was invalid")
	}
	code := testTOTPCode(t, enrollmentEnvelope.Data.ManualKey, time.Date(2026, time.August, 8, 16, 0, 0, 0, time.UTC).Unix()/30)
	confirmRequest := httptest.NewRequest(http.MethodPost, "/api/v2/auth/mfa/enrollment/confirm", strings.NewReader(`{"code":"`+code+`"}`))
	confirmRequest.Header.Set("Content-Type", "application/json")
	confirmRequest.Header.Set("Origin", "https://careerpathdesk.test")
	confirmRequest.Header.Set("Sec-Fetch-Site", "same-origin")
	confirmRequest.AddCookie(challengeCookie)
	confirmResponse := httptest.NewRecorder()
	router.ServeHTTP(confirmResponse, confirmRequest)
	if confirmResponse.Code != http.StatusOK || !strings.Contains(confirmResponse.Body.String(), `"recovery_codes":[`) {
		t.Fatalf("expected MFA confirmation session, got status=%d body=%s", confirmResponse.Code, confirmResponse.Body.String())
	}
	if strings.Contains(confirmResponse.Body.String(), code) || strings.Contains(confirmResponse.Body.String(), challengeCookie.Value) {
		t.Fatal("MFA confirmation response exposed OTP or challenge")
	}
	if findCookie(confirmResponse.Result().Cookies(), accessCookieName) == nil || findCookie(confirmResponse.Result().Cookies(), refreshCookieName) == nil || findCookie(confirmResponse.Result().Cookies(), httpx.CSRFTokenCookieName) == nil {
		t.Fatal("confirmed MFA did not issue normal session cookies")
	}
	clearedChallenge := findCookie(confirmResponse.Result().Cookies(), mfaChallengeCookieName)
	if clearedChallenge == nil || clearedChallenge.MaxAge >= 0 {
		t.Fatal("confirmed MFA did not clear the challenge cookie")
	}
}

// --- 已注册账号验证端点接受一次性恢复码，但不再返回恢复码集合 ---
func TestMFAVerifyHTTPConsumesRecoveryCodeWithoutExposingIt(t *testing.T) {
	authentication := newMFAAuthenticationTestHTTP(t)
	router := newAuthenticationTestRouter(authentication)
	firstLogin := performSyntheticLogin(router)
	enrollCookie := findCookie(firstLogin.Result().Cookies(), mfaChallengeCookieName)
	enrollmentRequest := newPreSessionMFARequest(http.MethodPost, "/api/v2/auth/mfa/enrollment", nil, enrollCookie)
	enrollmentResponse := httptest.NewRecorder()
	router.ServeHTTP(enrollmentResponse, enrollmentRequest)
	var enrollmentEnvelope struct {
		Data Enrollment `json:"data"`
	}
	_ = json.Unmarshal(enrollmentResponse.Body.Bytes(), &enrollmentEnvelope)
	code := testTOTPCode(t, enrollmentEnvelope.Data.ManualKey, time.Date(2026, time.August, 8, 16, 0, 0, 0, time.UTC).Unix()/30)
	confirmRequest := newPreSessionMFARequest(http.MethodPost, "/api/v2/auth/mfa/enrollment/confirm", strings.NewReader(`{"code":"`+code+`"}`), enrollCookie)
	confirmRequest.Header.Set("Content-Type", "application/json")
	confirmResponse := httptest.NewRecorder()
	router.ServeHTTP(confirmResponse, confirmRequest)
	var confirmation struct {
		Data struct {
			RecoveryCodes RecoveryCodes `json:"recovery_codes"`
		} `json:"data"`
	}
	if decodeError := json.Unmarshal(confirmResponse.Body.Bytes(), &confirmation); decodeError != nil || len(confirmation.Data.RecoveryCodes) == 0 {
		t.Fatal("MFA confirmation did not return recovery codes")
	}

	secondLogin := performSyntheticLogin(router)
	verifyCookie := findCookie(secondLogin.Result().Cookies(), mfaChallengeCookieName)
	recoveryCode := confirmation.Data.RecoveryCodes[0]
	verifyRequest := newPreSessionMFARequest(http.MethodPost, "/api/v2/auth/mfa/verify", strings.NewReader(`{"code":"`+recoveryCode+`"}`), verifyCookie)
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyResponse := httptest.NewRecorder()
	router.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK || findCookie(verifyResponse.Result().Cookies(), accessCookieName) == nil {
		t.Fatalf("expected MFA verification session, got status=%d body=%s", verifyResponse.Code, verifyResponse.Body.String())
	}
	if strings.Contains(verifyResponse.Body.String(), recoveryCode) || strings.Contains(verifyResponse.Body.String(), "recovery_codes") {
		t.Fatal("MFA verification response exposed recovery material")
	}
}

func newPreSessionMFARequest(method string, path string, body *strings.Reader, challengeCookie *http.Cookie) *http.Request {
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, body)
	}
	request.Header.Set("Origin", "https://careerpathdesk.test")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("User-Agent", "Synthetic Browser Test/1.0")
	request.AddCookie(challengeCookie)
	return request
}

// --- 未知账号和错误密码返回同一个无 Cookie 失败合同 ---
func TestLoginHidesWhetherTheUsernameExists(t *testing.T) {
	authentication, _ := newAuthenticationTestHTTP(t) // 两次失败共享同一隔离账号 schema。
	router := newAuthenticationTestRouter(authentication)
	testCases := []struct {
		name string // name 只描述合成失败路径，不包含凭据。
		body string // body 使用固定 synthetic 输入，不进入失败输出。
	}{
		{name: "known username", body: `{"username":"synthetic-owner","password":"Wrong-Synthetic-Password-2026!"}`},
		{name: "unknown username", body: `{"username":"unknown-synthetic-account","password":"Wrong-Synthetic-Password-2026!"}`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(testCase.body))
			request.Header.Set("Content-Type", "application/json")      // 登录入口只接受明确 JSON。
			request.Header.Set("Origin", "https://careerpathdesk.test") // 两条失败都通过同源前置门禁。
			request.Header.Set("Sec-Fetch-Site", "same-origin")         // 模拟浏览器 Fetch Metadata。
			response := httptest.NewRecorder()                          // 只观察公开状态、JSON 和 Cookie。
			router.ServeHTTP(response, request)

			var problem struct {
				Error struct {
					Code      string `json:"code"`       // Code 必须固定为不可枚举分类。
					Message   string `json:"message"`    // Message 不区分账号是否存在。
					RequestID string `json:"request_id"` // 每次失败仍可用服务端身份排查。
				} `json:"error"`
			}
			if decodeError := json.Unmarshal(response.Body.Bytes(), &problem); decodeError != nil {
				t.Fatal("login failure is not valid JSON")
			}
			if response.Code != http.StatusUnauthorized || problem.Error.Code != "INVALID_CREDENTIALS" || problem.Error.Message != "Username or password is invalid." || problem.Error.RequestID == "" { // 账号存在性不能改变公开反馈。
				t.Fatalf("unexpected generic login rejection: status=%d code=%q", response.Code, problem.Error.Code)
			}
			if len(response.Result().Cookies()) != 0 { // 失败登录不能留下部分访问、刷新或 CSRF 状态。
				t.Fatal("failed login set an authentication cookie")
			}
		})
	}
}

// --- 刷新请求轮换会话并重新签发全部浏览器 Cookie ---
func TestRefreshRotatesAllSessionCookies(t *testing.T) {
	authentication, tokens := newAuthenticationTestHTTP(t) // 使用一个真实 PostgreSQL 会话 family 完成登录再刷新。
	router := newAuthenticationTestRouter(authentication)
	loginResponse := performSyntheticLogin(router) // 先通过公开登录入口取得浏览器现有 Cookie。
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("synthetic login setup failed with status %d", loginResponse.Code)
	}
	oldAccessCookie := findCookie(loginResponse.Result().Cookies(), accessCookieName)
	oldRefreshCookie := findCookie(loginResponse.Result().Cookies(), refreshCookieName)
	oldCSRFCookie := findCookie(loginResponse.Result().Cookies(), httpx.CSRFTokenCookieName)
	if oldAccessCookie == nil || oldRefreshCookie == nil || oldCSRFCookie == nil { // 刷新测试必须从真实登录反馈开始。
		t.Fatal("synthetic login omitted a session cookie")
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/refresh", nil)
	request.Header.Set("Origin", "https://careerpathdesk.test") // 刷新是状态改变请求，必须来自配置同源。
	request.Header.Set("Sec-Fetch-Site", "same-origin")         // Fetch Metadata 证明不是跨站提交。
	request.Header.Set("X-CSRF-Token", oldCSRFCookie.Value)     // Header 与可读 Cookie 形成双提交证据。
	request.AddCookie(oldRefreshCookie)                         // 刷新入口不依赖可能已过期的访问 JWT。
	request.AddCookie(oldCSRFCookie)                            // 中间件在业务命令前验证 CSRF。
	response := httptest.NewRecorder()                          // 捕获新账号反馈和轮换 Cookie。
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK { // 有效刷新必须恢复当前账号会话。
		t.Fatalf("expected refresh status 200, got %d", response.Code)
	}
	newAccessCookie := findCookie(response.Result().Cookies(), accessCookieName)
	newRefreshCookie := findCookie(response.Result().Cookies(), refreshCookieName)
	newCSRFCookie := findCookie(response.Result().Cookies(), httpx.CSRFTokenCookieName)
	if newAccessCookie == nil || newRefreshCookie == nil || newCSRFCookie == nil { // 每次轮换都替换完整浏览器认证状态。
		t.Fatal("refresh response omitted a rotated session cookie")
	}
	if newAccessCookie.Value == oldAccessCookie.Value || newRefreshCookie.Value == oldRefreshCookie.Value || newCSRFCookie.Value == oldCSRFCookie.Value { // 三种凭据都必须变化。
		t.Fatal("refresh reused an existing browser credential")
	}
	claims, verifyError := tokens.Verify(newAccessCookie.Value)
	if verifyError != nil || claims.AccountID != "A-syntheticowner01" { // 新访问 JWT 仍绑定同一逐人账号。
		t.Fatal("refresh access cookie is not a valid current-account token")
	}
}

// --- 旧刷新 Cookie 重放会撤销完整轮换 family ---
func TestRefreshReplayRevokesTheRotatedBrowserSession(t *testing.T) {
	authentication, _ := newAuthenticationTestHTTP(t) // 登录、轮换和重放共享同一真实 token family。
	router := newAuthenticationTestRouter(authentication)
	loginResponse := performSyntheticLogin(router)
	oldRefreshCookie := findCookie(loginResponse.Result().Cookies(), refreshCookieName)
	oldCSRFCookie := findCookie(loginResponse.Result().Cookies(), httpx.CSRFTokenCookieName)
	if loginResponse.Code != http.StatusOK || oldRefreshCookie == nil || oldCSRFCookie == nil {
		t.Fatal("synthetic login did not establish replay prerequisites")
	}

	firstRefresh := performSyntheticRefresh(router, oldRefreshCookie, oldCSRFCookie) // 第一次提交合法轮换到新会话。
	newRefreshCookie := findCookie(firstRefresh.Result().Cookies(), refreshCookieName)
	newCSRFCookie := findCookie(firstRefresh.Result().Cookies(), httpx.CSRFTokenCookieName)
	if firstRefresh.Code != http.StatusOK || newRefreshCookie == nil || newCSRFCookie == nil {
		t.Fatal("synthetic refresh did not rotate replay prerequisites")
	}

	replayResponse := performSyntheticRefresh(router, oldRefreshCookie, oldCSRFCookie)                                                // 重放旧秘密必须触发 family 终态。
	if replayResponse.Code != http.StatusUnauthorized || !strings.Contains(replayResponse.Body.String(), `"code":"TOKEN_REPLAYED"`) { // 客户端得到明确停止恢复信号。
		t.Fatalf("refresh replay was not classified: status=%d", replayResponse.Code)
	}
	currentResponse := performSyntheticRefresh(router, newRefreshCookie, newCSRFCookie)                                                // 最新秘密也应因 family 撤销失效。
	if currentResponse.Code != http.StatusUnauthorized || !strings.Contains(currentResponse.Body.String(), `"code":"AUTH_REQUIRED"`) { // 已撤销 family 不能继续轮换。
		t.Fatalf("replayed family remained active: status=%d", currentResponse.Code)
	}
}

// --- 当前账号入口只接受仍绑定活动数据库会话的访问 JWT ---
func TestMeReturnsCurrentAccountOnlyForLiveAccessSession(t *testing.T) {
	authentication, _ := newAuthenticationTestHTTP(t) // 登录和当前账号读取共享同一隔离会话表。
	router := newAuthenticationTestRouter(authentication)
	loginResponse := performSyntheticLogin(router)
	accessCookie := findCookie(loginResponse.Result().Cookies(), accessCookieName)
	if loginResponse.Code != http.StatusOK || accessCookie == nil {
		t.Fatal("synthetic login did not establish an access session")
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v2/auth/me", nil)
	request.AddCookie(accessCookie)    // GET 只需脚本不可见的访问 JWT，不要求 CSRF。
	response := httptest.NewRecorder() // 捕获当前账号最小投影。
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"A-syntheticowner01"`) || !strings.Contains(response.Body.String(), `"request_id":"`) { // 有效会话必须恢复同一账号和请求身份。
		t.Fatalf("unexpected current-account response: status=%d body=%s", response.Code, response.Body.String())
	}

	tamperedRequest := httptest.NewRequest(http.MethodGet, "/api/v2/auth/me", nil)
	tamperedCookie := *accessCookie            // 保留所有浏览器属性，只修改签名正文。
	tamperedCookie.Value += "tampered"         // JWT 签名必须因此失效。
	tamperedRequest.AddCookie(&tamperedCookie) // 提交外部不可相信的 Cookie。
	tamperedResponse := httptest.NewRecorder() // 只观察稳定拒绝合同。
	router.ServeHTTP(tamperedResponse, tamperedRequest)
	if tamperedResponse.Code != http.StatusUnauthorized || !strings.Contains(tamperedResponse.Body.String(), `"code":"AUTH_REQUIRED"`) { // 不泄露 JWT 失败细节。
		t.Fatalf("tampered access token was not rejected: status=%d", tamperedResponse.Code)
	}
}

// --- 退出登录撤销当前数据库会话并清除全部 Cookie ---
func TestLogoutRevokesCurrentSessionAndClearsCookies(t *testing.T) {
	authentication, _ := newAuthenticationTestHTTP(t) // 登录、退出和失效验证共享同一隔离会话表。
	router := newAuthenticationTestRouter(authentication)
	loginResponse := performSyntheticLogin(router)
	accessCookie := findCookie(loginResponse.Result().Cookies(), accessCookieName)
	csrfCookie := findCookie(loginResponse.Result().Cookies(), httpx.CSRFTokenCookieName)
	if loginResponse.Code != http.StatusOK || accessCookie == nil || csrfCookie == nil {
		t.Fatal("synthetic login did not establish logout prerequisites")
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/logout", nil)
	request.Header.Set("Origin", "https://careerpathdesk.test") // 退出改变数据库状态，必须来自同源页面。
	request.Header.Set("Sec-Fetch-Site", "same-origin")         // Fetch Metadata 拒绝跨站触发退出。
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)        // 双提交值保护当前会话动作。
	request.AddCookie(accessCookie)                             // 访问 JWT 识别当前逐人会话。
	request.AddCookie(csrfCookie)                               // Cookie 与 Header 必须恒定时间匹配。
	response := httptest.NewRecorder()                          // 捕获 204 和 Cookie 清理反馈。
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 { // 成功退出不返回账号或业务正文。
		t.Fatalf("unexpected logout response: status=%d body=%s", response.Code, response.Body.String())
	}
	for _, cookieName := range []string{accessCookieName, refreshCookieName, httpx.CSRFTokenCookieName} {
		clearedCookie := findCookie(response.Result().Cookies(), cookieName)
		if clearedCookie == nil || clearedCookie.MaxAge >= 0 { // 浏览器必须收到明确过期指令。
			t.Fatalf("logout did not clear cookie %s", cookieName)
		}
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/api/v2/auth/me", nil)
	meRequest.AddCookie(accessCookie)    // 重放退出前的短期 JWT。
	meResponse := httptest.NewRecorder() // 数据库撤销必须立即覆盖 JWT 剩余期限。
	router.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusUnauthorized { // 旧访问令牌不能在退出后继续读取账号。
		t.Fatalf("logged-out access token remained active: status=%d", meResponse.Code)
	}
}

// --- 本人改密撤销全部会话并要求使用新密码重新登录 ---
func TestPasswordChangeClearsSessionAndActivatesOnlyNewPassword(t *testing.T) {
	authentication, _ := newAuthenticationTestHTTP(t) // 改密和重新登录共享同一隔离账号事实。
	router := newAuthenticationTestRouter(authentication)
	loginResponse := performSyntheticLogin(router)
	accessCookie := findCookie(loginResponse.Result().Cookies(), accessCookieName)
	csrfCookie := findCookie(loginResponse.Result().Cookies(), httpx.CSRFTokenCookieName)
	if loginResponse.Code != http.StatusOK || accessCookie == nil || csrfCookie == nil {
		t.Fatal("synthetic login did not establish password-change prerequisites")
	}

	requestBody := `{"current_password":"CareerPathDesk-Test-Only!","new_password":"CareerPathDesk-Synthetic-Changed-2026!"}` // 当前密码不对应任何部署环境。
	request := httptest.NewRequest(http.MethodPut, "/api/v2/auth/password", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")      // 改密只接受冻结 JSON 白名单。
	request.Header.Set("Origin", "https://careerpathdesk.test") // 安全状态改变必须来自配置同源。
	request.Header.Set("Sec-Fetch-Site", "same-origin")         // Fetch Metadata 阻止跨站提交。
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)        // 双提交值绑定当前浏览器会话。
	request.AddCookie(accessCookie)                             // JWT 识别要修改的本人账号。
	request.AddCookie(csrfCookie)                               // Cookie 与 Header 共同通过中间件。
	response := httptest.NewRecorder()                          // 捕获 204 与 Cookie 清理反馈。
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 { // 成功改密不返回账号或密码材料。
		t.Fatalf("unexpected password-change response: status=%d body=%s", response.Code, response.Body.String())
	}
	for _, cookieName := range []string{accessCookieName, refreshCookieName, httpx.CSRFTokenCookieName} {
		clearedCookie := findCookie(response.Result().Cookies(), cookieName)
		if clearedCookie == nil || clearedCookie.MaxAge >= 0 { // 所有旧设备凭据都必须从当前浏览器移除。
			t.Fatalf("password change did not clear cookie %s", cookieName)
		}
	}

	newLoginRequest := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(`{"username":"synthetic-owner","password":"CareerPathDesk-Synthetic-Changed-2026!"}`))
	newLoginRequest.Header.Set("Content-Type", "application/json")      // 使用新密码走完整公开登录入口。
	newLoginRequest.Header.Set("Origin", "https://careerpathdesk.test") // 登录仍要求同源。
	newLoginRequest.Header.Set("Sec-Fetch-Site", "same-origin")         // 提供浏览器来源证据。
	newLoginResponse := httptest.NewRecorder()                          // 新密码应建立全新会话 family。
	router.ServeHTTP(newLoginResponse, newLoginRequest)
	if newLoginResponse.Code != http.StatusOK { // 新密码必须成为唯一有效凭据。
		t.Fatalf("new password could not establish a session: status=%d", newLoginResponse.Code)
	}
}

// --- 本人可以列出设备并撤销另一台活动会话 ---
func TestSessionsListAndRevokeStayWithinCurrentAccount(t *testing.T) {
	authentication, _ := newAuthenticationTestHTTP(t) // 两台合成浏览器共享一个账号但拥有独立会话 family。
	router := newAuthenticationTestRouter(authentication)
	firstLogin := performSyntheticLogin(router)
	secondLogin := performSyntheticLogin(router)
	firstAccess := findCookie(firstLogin.Result().Cookies(), accessCookieName)
	firstCSRF := findCookie(firstLogin.Result().Cookies(), httpx.CSRFTokenCookieName)
	secondAccess := findCookie(secondLogin.Result().Cookies(), accessCookieName)
	if firstLogin.Code != http.StatusOK || secondLogin.Code != http.StatusOK || firstAccess == nil || firstCSRF == nil || secondAccess == nil {
		t.Fatal("synthetic device sessions failed to initialize")
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v2/auth/sessions", nil)
	listRequest.AddCookie(firstAccess)     // 第一台设备只凭活动访问 JWT 查询本人列表。
	listResponse := httptest.NewRecorder() // 响应不得包含 refresh digest 或秘密。
	router.ServeHTTP(listResponse, listRequest)
	var envelope struct {
		Data []struct {
			ID      string `json:"id"`      // ID 是撤销路由唯一允许的目标。
			Current bool   `json:"current"` // Current 明确标识发起列表的设备。
			State   string `json:"state"`   // State 只暴露 active/revoked/expired。
		} `json:"data"`
	}
	if decodeError := json.Unmarshal(listResponse.Body.Bytes(), &envelope); decodeError != nil {
		t.Fatal("session list is not valid JSON")
	}
	if listResponse.Code != http.StatusOK || len(envelope.Data) != 2 || strings.Contains(listResponse.Body.String(), "refresh_digest") || strings.Contains(listResponse.Body.String(), "refresh_token") { // 两台设备只返回最小展示字段。
		t.Fatalf("unexpected session list: status=%d count=%d", listResponse.Code, len(envelope.Data))
	}
	targetSessionID := ""
	currentCount := 0
	for _, session := range envelope.Data {
		if session.Current {
			currentCount++ // 当前访问 JWT 只能匹配一个列表项。
		} else if session.State == "active" {
			targetSessionID = session.ID // 选择另一台活动设备作为本人撤销目标。
		}
	}
	if currentCount != 1 || targetSessionID == "" {
		t.Fatal("session list did not identify current and target devices")
	}

	revokeRequest := httptest.NewRequest(http.MethodPost, "/api/v2/auth/sessions/"+targetSessionID+"/revoke", nil)
	revokeRequest.Header.Set("Origin", "https://careerpathdesk.test") // 设备撤销必须来自同源页面。
	revokeRequest.Header.Set("Sec-Fetch-Site", "same-origin")         // Fetch Metadata 拒绝跨站提交。
	revokeRequest.Header.Set("X-CSRF-Token", firstCSRF.Value)         // 第一台设备的双提交值保护本人动作。
	revokeRequest.AddCookie(firstAccess)                              // JWT 提供账号和当前会话身份。
	revokeRequest.AddCookie(firstCSRF)                                // Cookie 与 Header 必须匹配。
	revokeResponse := httptest.NewRecorder()                          // 成功只反馈 204。
	router.ServeHTTP(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("expected session revoke 204, got %d", revokeResponse.Code)
	}

	secondMeRequest := httptest.NewRequest(http.MethodGet, "/api/v2/auth/me", nil)
	secondMeRequest.AddCookie(secondAccess)    // 重放被撤销设备的旧访问 JWT。
	secondMeResponse := httptest.NewRecorder() // 数据库终态应立即拒绝。
	router.ServeHTTP(secondMeResponse, secondMeRequest)
	if secondMeResponse.Code != http.StatusUnauthorized { // 目标设备无需等待 JWT 自然过期。
		t.Fatalf("revoked device remained active: status=%d", secondMeResponse.Code)
	}
}

// --- JWT 身份不可用时不创建无法交付的数据库会话 ---
func TestLoginRejectsUnavailableTokenIdentityBeforeDatabaseSession(t *testing.T) {
	database := &countingTransactionSource{} // 只记录登录是否越过安全依赖前置门禁。
	sessions, sessionError := NewSessionCommands(database, func() time.Time { return time.Date(2026, time.August, 5, 17, 0, 0, 0, time.UTC) })
	if sessionError != nil {
		t.Fatalf("session commands failed to initialize: %v", sessionError)
	}
	publicKey, privateKey, keyError := ed25519.GenerateKey(rand.Reader) // 密钥有效，只有 JTI 随机身份故意失败。
	if keyError != nil {
		t.Fatal("synthetic access token keys unavailable")
	}
	tokens, tokenError := NewAccessTokens(
		AccessTokenKeys{Private: privateKey, Public: publicKey},
		func() time.Time { return time.Date(2026, time.August, 5, 17, 0, 0, 0, time.UTC) },
		func() (string, error) { return "", errors.New("synthetic token identity failure") },
	)
	if tokenError != nil {
		t.Fatalf("access tokens failed to initialize: %v", tokenError)
	}
	authentication, httpError := NewHTTP(sessions, tokens)
	if httpError != nil {
		t.Fatalf("authentication HTTP failed to initialize: %v", httpError)
	}
	response := performSyntheticLogin(newAuthenticationTestRouter(authentication)) // 从生产路由提交真实登录形状。

	if response.Code != http.StatusServiceUnavailable || database.beginCount != 0 { // 不可交付 JWT 时必须在打开事务前停止。
		t.Fatalf("token identity failure crossed the session boundary: status=%d begins=%d", response.Code, database.beginCount)
	}
	if len(response.Result().Cookies()) != 0 { // 失败不得留下访问、刷新或 CSRF Cookie。
		t.Fatal("token identity failure set a browser cookie")
	}
}

// --- 装配认证 HTTP 测试使用的真实合成依赖 ---
func newAuthenticationTestHTTP(t *testing.T) (*HTTP, *AccessTokens) {
	t.Helper()                               // 装配失败应指向调用行为测试。
	connection := openSessionTestDatabase(t) // 每个调用方获得独立 Foundation 合成账号 schema。
	fixedNow := time.Date(2026, time.August, 5, 15, 0, 0, 0, time.UTC)
	sessions, sessionError := NewSessionCommands(connection, func() time.Time { return fixedNow })
	if sessionError != nil {
		t.Fatalf("session commands failed to initialize: %v", sessionError)
	}
	publicKey, privateKey, keyError := ed25519.GenerateKey(rand.Reader) // 测试密钥只在当前进程内存在。
	if keyError != nil {
		t.Fatal("synthetic access token keys unavailable")
	}
	tokens, tokenError := NewAccessTokens(
		AccessTokenKeys{Private: privateKey, Public: publicKey},
		func() time.Time { return fixedNow },
		func() (string, error) { return "JTI-syntheticlogin01", nil },
	)
	if tokenError != nil {
		t.Fatalf("access tokens failed to initialize: %v", tokenError)
	}
	authentication, httpError := NewHTTP(sessions, tokens)
	if httpError != nil {
		t.Fatalf("authentication HTTP failed to initialize: %v", httpError)
	}
	return authentication, tokens // 反馈完整 HTTP 模块和用于检查 Cookie 声明的令牌能力。
}

func newMFAAuthenticationTestHTTP(t *testing.T) *HTTP {
	t.Helper()
	connection := openSessionTestDatabase(t)
	fixedNow := time.Date(2026, time.August, 8, 16, 0, 0, 0, time.UTC)
	sessions, _ := NewSessionCommands(connection, func() time.Time { return fixedNow })
	mfa, _ := NewMFACommands(connection, sessions, func() time.Time { return fixedNow }, true, []byte(strings.Repeat("k", 32)))
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	tokens, _ := NewAccessTokens(AccessTokenKeys{Private: privateKey, Public: publicKey}, func() time.Time { return fixedNow }, func() (string, error) { return "JTI-syntheticmfa001", nil })
	authentication, httpError := NewHTTPWithMFA(sessions, tokens, mfa)
	if httpError != nil {
		t.Fatalf("MFA authentication HTTP failed to initialize: %v", httpError)
	}
	return authentication
}

// --- 通过公开路由执行一次固定合成登录 ---
func performSyntheticLogin(router http.Handler) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(`{"username":"synthetic-owner","password":"CareerPathDesk-Test-Only!"}`)) // 登录只使用本测试 seed 凭据。
	request.Header.Set("Content-Type", "application/json")                                                                                                       // 登录正文使用冻结媒体类型。
	request.Header.Set("Origin", "https://careerpathdesk.test")                                                                                                  // 登录仍需通过同源门禁。
	request.Header.Set("Sec-Fetch-Site", "same-origin")                                                                                                          // 模拟真实浏览器 Fetch Metadata。
	request.Header.Set("User-Agent", "Synthetic Browser Test/1.0")                                                                                               // 设备摘要只使用固定合成文字。
	response := httptest.NewRecorder()                                                                                                                           // 返回完整公开 HTTP 反馈供下一步旅程使用。
	router.ServeHTTP(response, request)
	return response
}

// --- 通过公开路由执行一次固定合成刷新 ---
func performSyntheticRefresh(router http.Handler, refreshCookie *http.Cookie, csrfCookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/refresh", nil)
	request.Header.Set("Origin", "https://careerpathdesk.test") // 刷新只允许配置同源页面。
	request.Header.Set("Sec-Fetch-Site", "same-origin")         // Fetch Metadata 证明浏览器请求不是跨站。
	request.Header.Set("X-CSRF-Token", csrfCookie.Value)        // Header 回送同一 CSRF 值。
	request.AddCookie(refreshCookie)                            // 轮换命令只消费路径受限刷新 Cookie。
	request.AddCookie(csrfCookie)                               // 中间件先验证双提交 Cookie。
	response := httptest.NewRecorder()                          // 返回完整公开刷新反馈供旅程继续。
	router.ServeHTTP(response, request)
	return response
}

// --- 装配认证测试路由的统一基础与同源边界 ---
func newAuthenticationTestRouter(authentication *HTTP) http.Handler {
	readiness := applicationruntime.Readiness{Database: func(context.Context) error { return nil }} // 合成数据库已由测试连接证明可用。
	return applicationruntime.NewRouter(
		applicationruntime.BuildInfo{Version: "test"},
		readiness,
		httpx.SecurityConfig{PublicOrigin: "https://careerpathdesk.test"},
		authentication.Register,
	) // 从与 API 进程相同的组合入口挂载认证模块。
}

// --- 按名称读取一个响应 Cookie ---
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies { // 浏览全部 Set-Cookie，不依赖框架输出顺序。
		if cookie.Name == name {
			return cookie // 找到精确名称后反馈其公开属性。
		}
	}
	return nil // 缺失由调用行为断言统一报告。
}

// countingTransactionSource 只证明安全依赖失败前是否触达数据库，不模拟任何业务查询。
type countingTransactionSource struct {
	beginCount int // beginCount 记录公开登录调用打开事务的次数。
}

// --- 记录一次意外事务触达 ---
func (database *countingTransactionSource) Begin(context.Context) (pgx.Tx, error) {
	database.beginCount++ // 任何调用都说明前置令牌门禁顺序错误。
	return nil, errors.New("synthetic database should not be reached")
}
