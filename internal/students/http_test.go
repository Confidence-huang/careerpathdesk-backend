/*
学生 HTTP 合同测试：从真实认证 Cookie 和生产 Gin 路由验证对象范围、局部更新与幂等创建。
全部数据位于随机 synthetic PostgreSQL schema；测试只调用公开 HTTP，不启动监听器。
*/
package students

import (
	"context"           // 为生产路由提供合成就绪检查。
	"crypto/ed25519"    // 生成当前测试进程专用访问令牌密钥。
	"crypto/rand"       // 提供测试签名密钥的随机材料。
	"encoding/json"     // 解码公开学生 envelope 以继续版本化旅程。
	"fmt"               // 生成满足领域前缀的唯一 synthetic 身份。
	"net/http"          // 构造冻结学生方法与状态断言。
	"net/http/httptest" // 捕获生产路由的公开反馈。
	"net/url"           // 将不透明学生游标安全放入下一页请求。
	"strings"           // 提供严格 JSON 请求正文和安全响应断言。
	"testing"           // 组织独立 HTTP 行为。
	"time"              // 为会话与 JWT 注入同一 UTC 时刻。

	"github.com/gin-gonic/gin" // 把认证和学生入口组合到同一版本组。
	"github.com/jackc/pgx/v5"  // 返回随机 schema 连接供测试装配。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"                                // 通过真实登录建立当前账号。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"                      // 使用生产请求身份、同源和 CSRF 门禁。
	applicationruntime "github.com/confidence-huang/careerpathdesk-backend/internal/platform/runtime" // 通过生产路由执行合同。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport"                         // 建立 Foundation synthetic schema。
)

const studentHTTPOrigin = "https://careerpathdesk.test" // 测试浏览器唯一允许的同源值。
const studentHTTPPassword = "CareerPathDesk-Test-Only!"      // 只对应本测试 seed，不对应任何已部署环境。

// --- 员工通过 HTTP 只能管理本人学生，且创建重试不重复事实 ---
func TestStaffStudentHTTPJourneyAndExistenceHiding(t *testing.T) {
	router, _ := newStudentsHTTPTestSystem(t)
	accessCookie, csrfCookie := loginStudentHTTPActor(t, router, "synthetic-staff-one")

	listResponse := performStudentRead(router, "/api/v2/students?limit=30", accessCookie)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "S-syntheticstudent01") || strings.Contains(listResponse.Body.String(), "S-syntheticstudent03") {
		t.Fatalf("staff student list escaped scope: status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	foreignResponse := performStudentRead(router, "/api/v2/students/S-syntheticstudent03", accessCookie)
	unknownResponse := performStudentRead(router, "/api/v2/students/S-syntheticunknown01", accessCookie)
	assertStudentNotFound(t, foreignResponse)
	assertStudentNotFound(t, unknownResponse)

	updateResponse := performStudentMutation(router, http.MethodPatch, "/api/v2/students/S-syntheticstudent01", `{"next_action":"Synthetic HTTP next action","version":1}`, accessCookie, csrfCookie, "")
	if updateResponse.Code != http.StatusOK || !strings.Contains(updateResponse.Body.String(), `"name":"Synthetic Student Alpha"`) || !strings.Contains(updateResponse.Body.String(), `"version":2`) {
		t.Fatalf("partial student update did not preserve current fields: status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}

	createBody := `{"name":"Synthetic HTTP Student","processing_basis":"service_contract","privacy_notice_version":"privacy-notice-v1","privacy_notice_delivered":true}`
	createdResponse := performStudentMutation(router, http.MethodPost, "/api/v2/students", createBody, accessCookie, csrfCookie, "synthetic-key-http-student-01")
	replayedResponse := performStudentMutation(router, http.MethodPost, "/api/v2/students", createBody, accessCookie, csrfCookie, "synthetic-key-http-student-01")
	if createdResponse.Code != http.StatusCreated || replayedResponse.Code != http.StatusCreated {
		t.Fatalf("student create or replay failed: first=%d second=%d", createdResponse.Code, replayedResponse.Code)
	}
	createdEnvelope := struct {
		Data Student `json:"data"`
	}{}
	replayedEnvelope := struct {
		Data Student `json:"data"`
	}{}
	if firstError := json.Unmarshal(createdResponse.Body.Bytes(), &createdEnvelope); firstError != nil {
		t.Fatal("student create envelope is invalid")
	}
	if replayError := json.Unmarshal(replayedResponse.Body.Bytes(), &replayedEnvelope); replayError != nil || createdEnvelope.Data.ID == "" || replayedEnvelope.Data.ID != createdEnvelope.Data.ID {
		t.Fatalf("student HTTP replay duplicated identity: first=%q second=%q", createdEnvelope.Data.ID, replayedEnvelope.Data.ID)
	}

	assignmentResponse := performStudentMutation(router, http.MethodPut, "/api/v2/students/S-syntheticstudent03/assignment", `{not-json`, accessCookie, csrfCookie, "")
	if assignmentResponse.Code != http.StatusForbidden || !strings.Contains(assignmentResponse.Body.String(), `"code":"FORBIDDEN"`) {
		t.Fatalf("staff assignment did not reject before target/body parsing: status=%d body=%s", assignmentResponse.Code, assignmentResponse.Body.String())
	}
}

// --- HTTP 创建合同拒绝任何缺失的隐私依据、通知版本或告知确认 ---
func TestStudentCreateHTTPRequiresPrivacyFacts(t *testing.T) {
	router, _ := newStudentsHTTPTestSystem(t)
	accessCookie, csrfCookie := loginStudentHTTPActor(t, router, "synthetic-staff-one")
	cases := []string{
		`{"name":"Synthetic Missing Basis","privacy_notice_version":"privacy-notice-v1","privacy_notice_delivered":true}`,
		`{"name":"Synthetic Wrong Notice","processing_basis":"service_contract","privacy_notice_version":"privacy-notice-v0","privacy_notice_delivered":true}`,
		`{"name":"Synthetic Missing Delivery","processing_basis":"student_consent","privacy_notice_version":"privacy-notice-v1"}`,
	}
	for index, body := range cases {
		response := performStudentMutation(router, http.MethodPost, "/api/v2/students", body, accessCookie, csrfCookie, fmt.Sprintf("synthetic-key-http-privacy-%02d", index))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"INVALID_INPUT"`) {
			t.Fatalf("privacy-invalid create case %d was accepted: status=%d body=%s", index, response.Code, response.Body.String())
		}
	}
}

// --- 老板分配成功可见，第十六名服务中学生同样按正常合同提交 ---
func TestOwnerStudentAssignmentHTTPNoCapacityLimitContract(t *testing.T) {
	router, connection := newStudentsHTTPTestSystem(t)
	accessCookie, csrfCookie := loginStudentHTTPActor(t, router, "synthetic-owner")
	targetStaffID := "T-syntheticcoach01"

	successResponse := performStudentMutation(router, http.MethodPut, "/api/v2/students/S-syntheticstudent04/assignment", `{"owner_staff_id":"T-syntheticcoach01","version":1}`, accessCookie, csrfCookie, "")
	if successResponse.Code != http.StatusOK || !strings.Contains(successResponse.Body.String(), `"owner_staff_id":"T-syntheticcoach01"`) || !strings.Contains(successResponse.Body.String(), `"version":2`) {
		t.Fatalf("owner assignment failed: status=%d body=%s", successResponse.Code, successResponse.Body.String())
	}
	for index := 0; index < 14; index++ { // Seed 已有一名服务中学生，再加入十四名形成十五人基线。
		studentID := fmt.Sprintf("S-synthetichttpcapacity%02d", index)
		if _, insertError := connection.Exec(t.Context(), `
			INSERT INTO students (id, name, service_stage, job_search_stage, owner_staff_id, source_kind, created_by, updated_by, processing_basis, privacy_notice_version, privacy_notice_delivered_at)
			VALUES ($1, 'Synthetic HTTP Capacity', '服务中', '未开始', $2, 'staff', 'A-syntheticowner01', 'A-syntheticowner01', 'service_contract', 'privacy-notice-v1', statement_timestamp())`, studentID, targetStaffID); insertError != nil {
			t.Fatal("synthetic HTTP capacity setup failed")
		}
	}
	sixteenthResponse := performStudentMutation(router, http.MethodPut, "/api/v2/students/S-syntheticstudent03/assignment", `{"owner_staff_id":"T-syntheticcoach01","version":1}`, accessCookie, csrfCookie, "")
	if sixteenthResponse.Code != http.StatusOK || !strings.Contains(sixteenthResponse.Body.String(), `"owner_staff_id":"T-syntheticcoach01"`) || !strings.Contains(sixteenthResponse.Body.String(), `"version":2`) {
		t.Fatalf("sixteenth assignment HTTP contract failed: status=%d body=%s", sixteenthResponse.Code, sixteenthResponse.Body.String())
	}
	currentResponse := performStudentRead(router, "/api/v2/students/S-syntheticstudent03", accessCookie)
	if currentResponse.Code != http.StatusOK || !strings.Contains(currentResponse.Body.String(), `"owner_staff_id":"T-syntheticcoach01"`) || !strings.Contains(currentResponse.Body.String(), `"version":2`) {
		t.Fatalf("sixteenth assignment was not persisted: status=%d body=%s", currentResponse.Code, currentResponse.Body.String())
	}

	unassignResponse := performStudentMutation(router, http.MethodPut, "/api/v2/students/S-syntheticstudent02/assignment", `{"owner_staff_id":null,"version":1}`, accessCookie, csrfCookie, "")
	if unassignResponse.Code != http.StatusOK || !strings.Contains(unassignResponse.Body.String(), `"owner_staff_id":null`) {
		t.Fatalf("owner could not intentionally clear primary assignment: status=%d body=%s", unassignResponse.Code, unassignResponse.Body.String())
	}
}

// --- 学生列表游标稳定推进且不会重复上一页对象 ---
func TestStudentHTTPListCursorAdvancesWithoutOverlap(t *testing.T) {
	router, _ := newStudentsHTTPTestSystem(t)
	accessCookie, _ := loginStudentHTTPActor(t, router, "synthetic-staff-one")

	firstResponse := performStudentRead(router, "/api/v2/students?limit=1", accessCookie)
	firstPage := struct {
		Data []Student `json:"data"`
		Meta struct {
			NextCursor *string `json:"next_cursor"`
		} `json:"meta"`
	}{}
	if decodeError := json.Unmarshal(firstResponse.Body.Bytes(), &firstPage); decodeError != nil || firstResponse.Code != http.StatusOK || len(firstPage.Data) != 1 || firstPage.Meta.NextCursor == nil {
		t.Fatalf("first student cursor page is invalid: status=%d page=%#v", firstResponse.Code, firstPage)
	}
	secondResponse := performStudentRead(router, "/api/v2/students?limit=1&cursor="+url.QueryEscape(*firstPage.Meta.NextCursor), accessCookie)
	secondPage := struct {
		Data []Student `json:"data"`
	}{}
	if decodeError := json.Unmarshal(secondResponse.Body.Bytes(), &secondPage); decodeError != nil || secondResponse.Code != http.StatusOK || len(secondPage.Data) != 1 || secondPage.Data[0].ID == firstPage.Data[0].ID {
		t.Fatalf("second student cursor page overlapped or failed: status=%d first=%#v second=%#v", secondResponse.Code, firstPage.Data, secondPage.Data)
	}
}

// --- 装配真实认证与学生 HTTP 模块 ---
func newStudentsHTTPTestSystem(t *testing.T) (http.Handler, *pgx.Conn) {
	t.Helper()
	connection := testsupport.OpenDatabase(t, "students_http")
	fixedNow := time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC)
	sessions, sessionError := auth.NewSessionCommands(connection, func() time.Time { return fixedNow })
	if sessionError != nil {
		t.Fatalf("synthetic sessions failed to initialize: %v", sessionError)
	}
	publicKey, privateKey, keyError := ed25519.GenerateKey(rand.Reader)
	if keyError != nil {
		t.Fatal("synthetic access token keys unavailable")
	}
	tokens, tokenError := auth.NewAccessTokens(auth.AccessTokenKeys{Private: privateKey, Public: publicKey}, func() time.Time { return fixedNow }, func() (string, error) { return "JTI-syntheticstudents01", nil })
	if tokenError != nil {
		t.Fatalf("synthetic access tokens failed to initialize: %v", tokenError)
	}
	authentication, authenticationError := auth.NewHTTP(sessions, tokens)
	if authenticationError != nil {
		t.Fatalf("synthetic authentication HTTP failed to initialize: %v", authenticationError)
	}
	identityCount := 0
	commands, commandError := NewCommands(connection, func() time.Time { return fixedNow }, func(prefix string) (string, error) {
		identityCount++
		return fmt.Sprintf("%s-synthetichttp%012d", prefix, identityCount), nil
	})
	if commandError != nil {
		t.Fatalf("synthetic student commands failed to initialize: %v", commandError)
	}
	studentHTTP, studentHTTPError := NewHTTP(commands, authentication.CurrentAccount)
	if studentHTTPError != nil {
		t.Fatalf("synthetic student HTTP failed to initialize: %v", studentHTTPError)
	}
	router := applicationruntime.NewRouter(
		applicationruntime.BuildInfo{Version: "test"},
		applicationruntime.Readiness{Database: func(_ context.Context) error { return nil }},
		httpx.SecurityConfig{PublicOrigin: studentHTTPOrigin},
		func(versionedAPI *gin.RouterGroup) {
			authentication.Register(versionedAPI)
			studentHTTP.Register(versionedAPI)
		},
	)
	return router, connection
}

// --- 使用公开登录入口取得学生请求 Cookie ---
func loginStudentHTTPActor(t *testing.T, router http.Handler, username string) (*http.Cookie, *http.Cookie) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(`{"username":"`+username+`","password":"`+studentHTTPPassword+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", studentHTTPOrigin)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("synthetic student actor login failed: status=%d body=%s", response.Code, response.Body.String())
	}
	accessCookie := findStudentCookie(response.Result().Cookies(), "__Host-p17_access")
	csrfCookie := findStudentCookie(response.Result().Cookies(), httpx.CSRFTokenCookieName)
	if accessCookie == nil || csrfCookie == nil {
		t.Fatal("synthetic student actor login omitted required cookies")
	}
	return accessCookie, csrfCookie
}

// --- 执行一条已登录学生读取请求 ---
func performStudentRead(router http.Handler, path string, accessCookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(accessCookie)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// --- 执行一条同源且通过 CSRF 的学生写请求 ---
func performStudentMutation(router http.Handler, method string, path string, body string, accessCookie *http.Cookie, csrfCookie *http.Cookie, idempotencyKey string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", studentHTTPOrigin)
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

// --- 断言未知与范围外学生共享最小不存在反馈 ---
func assertStudentNotFound(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"NOT_FOUND"`) {
		t.Fatalf("student existence was not hidden: status=%d body=%s", response.Code, response.Body.String())
	}
}

// --- 按固定名称读取测试浏览器 Cookie ---
func findStudentCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
