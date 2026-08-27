/*
隐私说明公开 HTTP 测试：从匿名 GET 入口核对 DRAFT/APPROVED 投影、统一请求身份和禁止缓存响应。
测试使用内存 Gin 路由与合成审批事实，不创建账号、会话、数据库或外部监听器。
调用示例：go test ./internal/privacy -run NoticeHTTP -count=1。
*/
package privacy

import (
	"bytes"             // 拒绝公开 JSON 后的任何额外值。
	"encoding/json"     // 解码公开 envelope 并核对精确字段集合。
	"net/http"          // 构造匿名 GET 请求并断言 200 状态。
	"net/http/httptest" // 在内存捕获完整 HTTP 反馈。
	"testing"           // 运行 Go 标准行为测试。
	"time"              // 固定 synthetic DRAFT 的加载时钟。

	"github.com/gin-gonic/gin" // 复用正式路由注册方式。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx" // 提供统一 request_id 与 no-store 基础边界。
)

// --- 匿名 synthetic 请求得到精确 DRAFT 公开投影 ---
func TestNoticeHTTPPublishesSyntheticDraftAnonymously(t *testing.T) {
	gin.SetMode(gin.TestMode)
	notice, loadError := LoadNotice("synthetic", "", "uat", time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC))
	if loadError != nil {
		t.Fatalf("synthetic notice failed to load: %v", loadError)
	}
	entry, constructionError := NewNoticeHTTP(notice)
	if constructionError != nil {
		t.Fatalf("public notice HTTP failed to initialize: %v", constructionError)
	}
	router := gin.New()
	router.Use(httpx.Foundation(func() (string, error) { return "R-syntheticnoticehttp01", nil }))
	entry.Register(router.Group("/api/v2"))

	request := httptest.NewRequest(http.MethodGet, "/api/v2/public/privacy-notice", nil) // 不提供任何账号或邀请凭据。
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous draft response diverged: status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}

	envelope := decodeExactNoticeHTTPEnvelope(t, response.Body.Bytes())
	if envelope.Meta.RequestID != "R-syntheticnoticehttp01" || len(envelope.Data) != 11 {
		t.Fatalf("public draft envelope diverged: %#v", envelope)
	}
	if envelope.Data["version"] != "privacy-notice-v1" || envelope.Data["status"] != "DRAFT" {
		t.Fatalf("public draft identity diverged: %#v", envelope.Data)
	}
	for _, nullableField := range []string{"operator_name", "public_contact", "approved_at", "publication_digest"} {
		if value, exists := envelope.Data[nullableField]; !exists || value != nil {
			t.Fatalf("draft field %s must be explicit null: %#v", nullableField, envelope.Data)
		}
	}
	for _, forbiddenField := range []string{"release_sha", "under_14_excluded", "approval_digest", "privacy_notice_file"} {
		if _, exposed := envelope.Data[forbiddenField]; exposed {
			t.Fatalf("public draft exposed internal field %s: %#v", forbiddenField, envelope.Data)
		}
	}
}

// --- production 匿名请求只得到 APPROVED 公开字段和 publication_digest ---
func TestNoticeHTTPPublishesApprovedProjectionWithoutInternalFacts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	releaseSHA := "0123456789abcdef0123456789abcdef01234567"
	document := approvedNoticeDocument(releaseSHA, "2026-08-09T07:30:00Z")
	path := writeNoticeDocument(t, document, 0o600)
	notice, loadError := LoadNotice("production", path, releaseSHA, time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC))
	if loadError != nil {
		t.Fatalf("approved notice failed to load: %v", loadError)
	}
	entry, constructionError := NewNoticeHTTP(notice)
	if constructionError != nil {
		t.Fatalf("approved notice HTTP failed to initialize: %v", constructionError)
	}
	router := gin.New()
	router.Use(httpx.Foundation(func() (string, error) { return "R-syntheticnoticehttp02", nil }))
	entry.Register(router.Group("/api/v2"))

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v2/public/privacy-notice", nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous approved response diverged: status=%d cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	envelope := decodeExactNoticeHTTPEnvelope(t, response.Body.Bytes())
	if len(envelope.Data) != 11 || envelope.Data["status"] != "APPROVED" || envelope.Data["operator_name"] != "合成测试经营主体" ||
		envelope.Data["public_contact"] != "业务微信：synthetic-career-desk" || envelope.Data["approved_at"] != "2026-08-09T07:30:00Z" ||
		envelope.Data["publication_digest"] != document["approval_digest"] {
		t.Fatalf("approved public projection diverged: %#v", envelope.Data)
	}
	for _, forbiddenField := range []string{"release_sha", "under_14_excluded", "approval_digest", "privacy_notice_file"} {
		if _, exposed := envelope.Data[forbiddenField]; exposed {
			t.Fatalf("public approved response exposed %s: %#v", forbiddenField, envelope.Data)
		}
	}
}

type noticeHTTPEnvelope struct {
	Data map[string]any `json:"data"` // Data 保留公开字段名称和值，便于检查 null 与字段数。
	Meta struct {
		RequestID string `json:"request_id"` // RequestID 必须来自统一 Foundation，而不是隐私文件。
	} `json:"meta"`
}

// --- 先锁定匿名 envelope 的全部键，再让强类型解码核对公开值 ---
func decodeExactNoticeHTTPEnvelope(t *testing.T, body []byte) noticeHTTPEnvelope {
	t.Helper()
	var rawEnvelope map[string]json.RawMessage
	if decodeError := json.Unmarshal(body, &rawEnvelope); decodeError != nil {
		t.Fatalf("public notice response failed to decode: %v", decodeError)
	}
	assertExactJSONKeys(t, rawEnvelope, []string{"data", "meta"})

	var rawData map[string]json.RawMessage
	if decodeError := json.Unmarshal(rawEnvelope["data"], &rawData); decodeError != nil {
		t.Fatalf("public notice data failed to decode: %v", decodeError)
	}
	assertExactJSONKeys(t, rawData, []string{
		"approved_at", "audit_retention_days", "backup_retention_days", "invitation_absolute_hours",
		"operator_name", "public_contact", "publication_digest", "session_absolute_days", "status",
		"student_closed_retention_days", "version",
	})

	var rawMeta map[string]json.RawMessage
	if decodeError := json.Unmarshal(rawEnvelope["meta"], &rawMeta); decodeError != nil {
		t.Fatalf("public notice meta failed to decode: %v", decodeError)
	}
	assertExactJSONKeys(t, rawMeta, []string{"request_id"})

	var envelope noticeHTTPEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(&envelope); decodeError != nil {
		t.Fatalf("public notice typed response failed to decode: %v", decodeError)
	}
	if decoder.Decode(&struct{}{}) == nil {
		t.Fatal("public notice response contains an extra JSON value")
	}
	return envelope
}

func assertExactJSONKeys(t *testing.T, values map[string]json.RawMessage, expected []string) {
	t.Helper()
	if len(values) != len(expected) {
		t.Fatalf("public notice JSON keys diverged: got=%v expected=%v", values, expected)
	}
	for _, key := range expected {
		if _, exists := values[key]; !exists {
			t.Fatalf("public notice JSON key %q is missing: %v", key, values)
		}
	}
}
