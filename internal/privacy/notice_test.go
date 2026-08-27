/*
隐私说明发布测试：通过公开 LoadNotice 证明 synthetic 只产生内存 DRAFT，production 只接受绑定发布的审批摘要。
测试文件全部位于 t.TempDir，使用合成身份和摘要，不读取宿主配置或任何真实业务输入。
调用示例：go test ./internal/privacy -run Notice -count=1。
*/
package privacy

import (
	"crypto/sha256" // 独立计算冻结的 NUL 顺序摘要，不复用被测实现。
	"encoding/json" // 生成净化 JSON fixture 并核对公开投影。
	"errors"        // 比较不泄露文件细节的稳定失败分类。
	"fmt"           // 把 SHA-256 编码成冻结的小写十六进制。
	"os"            // 以精确 0600 权限创建受控审批文件。
	"path/filepath" // 把 fixture 限制在测试临时目录。
	"strings"       // 用无尾随 NUL 的固定顺序连接摘要输入。
	"testing"       // 运行 Go 标准行为测试。
	"time"          // 固定审批与加载时间，避免测试依赖当前时钟。
)

// --- synthetic 只公开内存 DRAFT 和固定期限 ---
func TestLoadNoticeCreatesSyntheticDraftWithoutFile(t *testing.T) {
	now := time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC) // synthetic 不使用该时间，但公开入口仍接收明确时钟。
	notice, loadError := LoadNotice("synthetic", "", "uat", now) // UAT 构建身份无需伪造成正式 Git SHA。
	if loadError != nil {
		t.Fatalf("synthetic privacy notice failed to load: %v", loadError)
	}
	if notice.Version != "privacy-notice-v1" || notice.Status != "DRAFT" {
		t.Fatalf("unexpected synthetic notice identity: %#v", notice)
	}
	if notice.OperatorName != nil || notice.PublicContact != nil || notice.ApprovedAt != nil || notice.PublicationDigest != nil {
		t.Fatalf("synthetic draft invented approved public facts: %#v", notice)
	}
	if notice.StudentClosedRetentionDays != 180 || notice.AuditRetentionDays != 365 || notice.BackupRetentionDays != 30 ||
		notice.SessionAbsoluteDays != 30 || notice.InvitationAbsoluteHours != 72 {
		t.Fatalf("synthetic draft retention facts drifted: %#v", notice)
	}
}

// --- production 拒绝未批准、漂移、含糊或未绑定当前发布的审批摘要 ---
func TestLoadNoticeRejectsInvalidProductionApprovalFacts(t *testing.T) {
	releaseSHA := "0123456789abcdef0123456789abcdef01234567"
	now := time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown_field", mutate: func(document map[string]any) { document["unreviewed"] = true }},
		{name: "draft_status", mutate: func(document map[string]any) { document["status"] = "DRAFT" }},
		{name: "empty_operator", mutate: func(document map[string]any) { document["operator_name"] = "" }},
		{name: "publisher_rejected_operator", mutate: func(document map[string]any) { document["operator_name"] = "Project $17" }},
		{name: "empty_contact", mutate: func(document map[string]any) { document["public_contact"] = "" }},
		{name: "unsafe_contact", mutate: func(document map[string]any) { document["public_contact"] = "微信：synthetic;command" }},
		{name: "future_approval", mutate: func(document map[string]any) { document["approved_at"] = "2026-08-09T08:00:01Z" }},
		{name: "noncanonical_approval_time", mutate: func(document map[string]any) { document["approved_at"] = "2026-08-09T07:30:00.123Z" }},
		{name: "student_retention_drift", mutate: func(document map[string]any) { document["student_closed_retention_days"] = 181 }},
		{name: "audit_retention_drift", mutate: func(document map[string]any) { document["audit_retention_days"] = 364 }},
		{name: "backup_retention_drift", mutate: func(document map[string]any) { document["backup_retention_days"] = 31 }},
		{name: "session_lifetime_drift", mutate: func(document map[string]any) { document["session_absolute_days"] = 8 }},
		{name: "invitation_lifetime_drift", mutate: func(document map[string]any) { document["invitation_absolute_hours"] = 71 }},
		{name: "under_14_not_excluded", mutate: func(document map[string]any) { document["under_14_excluded"] = false }},
		{name: "release_mismatch", mutate: func(document map[string]any) { document["release_sha"] = "89abcdef0123456789abcdef0123456789abcdef" }},
		{name: "digest_mismatch", mutate: func(document map[string]any) { document["approval_digest"] = strings.Repeat("0", 64) }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			document := approvedNoticeDocument(releaseSHA, "2026-08-09T07:30:00Z") // 每例从独立有效审批事实开始。
			testCase.mutate(document)                                              // 只改变当前子例声明的一项生产事实。
			if testCase.name != "digest_mismatch" {                                // 除摘要破坏例外，都重算摘要以隔离真正拒绝原因。
				refreshApprovalDigest(document)
			}
			path := writeNoticeDocument(t, document, 0o600)
			if _, loadError := LoadNotice("production", path, releaseSHA, now); !errors.Is(loadError, ErrNoticeUnavailable) {
				t.Fatalf("expected invalid approval rejection, got %v", loadError)
			}
		})
	}
}

// --- production 文件必须是唯一、无歧义、精确 0600 的普通文件 ---
func TestLoadNoticeRejectsUnsafeApprovalFileShapes(t *testing.T) {
	releaseSHA := "0123456789abcdef0123456789abcdef01234567"
	now := time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC)
	document := approvedNoticeDocument(releaseSHA, "2026-08-09T07:30:00Z")

	broadPath := writeNoticeDocument(t, document, 0o644) // 组或其他用户可读时不得发布审批内容。
	assertNoticeUnavailable(t, broadPath, releaseSHA, now)

	targetPath := writeNoticeDocument(t, document, 0o600) // 即使链接目标本身安全，路径替换仍必须拒绝。
	linkPath := filepath.Join(t.TempDir(), "privacy-notice-link.json")
	if linkError := os.Symlink(targetPath, linkPath); linkError != nil {
		t.Fatalf("synthetic approval symlink failed: %v", linkError)
	}
	assertNoticeUnavailable(t, linkPath, releaseSHA, now)

	directoryPath := filepath.Join(t.TempDir(), "privacy-notice-directory.json") // 非普通目标必须在读取前失败。
	if directoryError := os.Mkdir(directoryPath, 0o600); directoryError != nil {
		t.Fatalf("synthetic approval directory failed: %v", directoryError)
	}
	assertNoticeUnavailable(t, directoryPath, releaseSHA, now)

	body, marshalError := json.Marshal(document)
	if marshalError != nil {
		t.Fatalf("synthetic approval document failed to encode: %v", marshalError)
	}
	duplicateStatus := append([]byte(`{"status":"DRAFT",`), body[1:]...) // 后一个合法值不得覆盖前一个冲突值。
	duplicatePath := writeRawNoticeDocument(t, duplicateStatus, 0o600)
	assertNoticeUnavailable(t, duplicatePath, releaseSHA, now)

	caseDriftBody := []byte(strings.Replace(string(body), `"version"`, `"Version"`, 1)) // Go 的大小写宽松匹配不能扩大精确发布合同。
	caseDriftPath := writeRawNoticeDocument(t, caseDriftBody, 0o600)
	assertNoticeUnavailable(t, caseDriftPath, releaseSHA, now)

	trailingPath := writeRawNoticeDocument(t, append(body, []byte(` {}`)...), 0o600) // 第二个 JSON 文档不得被忽略。
	assertNoticeUnavailable(t, trailingPath, releaseSHA, now)
}

// --- production 只装配与完整发布 SHA 绑定的 APPROVED 公开投影 ---
func TestLoadNoticeAcceptsProtectedApprovedProductionDocument(t *testing.T) {
	releaseSHA := "0123456789abcdef0123456789abcdef01234567"   // 使用完整 40 位小写合成发布身份。
	approvedAt := "2026-08-09T07:30:00Z"                       // 审批发生在固定加载时间之前。
	document := approvedNoticeDocument(releaseSHA, approvedAt) // 生成包含全部冻结内部字段的审批摘要。
	if document["status"] != "approved" || document["approval_digest"] != "9891d2ea77758f6bc8fbeaad1efa398766962f61349424a4895ad5b2489d2554" {
		t.Fatalf("publisher-shaped canonical approval diverged: %#v", document)
	}
	path := writeNoticeDocument(t, document, 0o600)                      // production 只接受精确 0600 普通文件。
	now := time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC)         // 固定未来时间判断边界。
	notice, loadError := LoadNotice("production", path, releaseSHA, now) // 从公开入口加载并净化成匿名投影。
	if loadError != nil {
		t.Fatalf("approved production notice failed to load: %v", loadError)
	}
	if notice.Status != "APPROVED" || notice.OperatorName == nil || *notice.OperatorName != "合成测试经营主体" ||
		notice.PublicContact == nil || *notice.PublicContact != "业务微信：synthetic-career-desk" || notice.ApprovedAt == nil || *notice.ApprovedAt != approvedAt {
		t.Fatalf("approved public facts diverged: %#v", notice)
	}
	if notice.PublicationDigest == nil || *notice.PublicationDigest != document["approval_digest"] {
		t.Fatalf("publication digest diverged: %#v", notice)
	}
	publicJSON, marshalError := json.Marshal(notice) // 序列化真实公开结构，检查内部文件事实不会被 tag 意外暴露。
	if marshalError != nil {
		t.Fatalf("public notice failed to serialize: %v", marshalError)
	}
	for _, forbidden := range []string{path, releaseSHA, "under_14_excluded", "approval_digest"} {
		if strings.Contains(string(publicJSON), forbidden) {
			t.Fatalf("public notice exposed internal approval material %q: %s", forbidden, publicJSON)
		}
	}
}

// --- production 可以发布微信等通用联系方式，且不再暴露电话专用字段 ---
func TestLoadNoticePublishesApprovedWechatContact(t *testing.T) {
	releaseSHA := "0123456789abcdef0123456789abcdef01234567"
	approvedAt := "2026-08-09T07:30:00Z"
	document := approvedNoticeDocument(releaseSHA, approvedAt)
	path := writeNoticeDocument(t, document, 0o600)

	notice, loadError := LoadNotice("production", path, releaseSHA, time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC))
	if loadError != nil {
		t.Fatalf("approved WeChat contact failed to load: %v", loadError)
	}
	publicJSON, marshalError := json.Marshal(notice)
	if marshalError != nil {
		t.Fatalf("approved WeChat notice failed to encode: %v", marshalError)
	}
	projection := map[string]any{}
	if decodeError := json.Unmarshal(publicJSON, &projection); decodeError != nil {
		t.Fatalf("approved WeChat projection failed to decode: %v", decodeError)
	}
	if projection["public_contact"] != "业务微信：synthetic-career-desk" {
		t.Fatalf("approved WeChat contact diverged: %#v", projection)
	}
	if _, exposedLegacyPhone := projection["public_phone"]; exposedLegacyPhone {
		t.Fatalf("approved WeChat projection retained phone-only field: %#v", projection)
	}
}

// --- production 公开运营名称，不把未经核验的展示名标成法定名称 ---
func TestLoadNoticePublishesApprovedOperatorNameWithoutLegalClaim(t *testing.T) {
	releaseSHA := "0123456789abcdef0123456789abcdef01234567"
	approvedAt := "2026-08-09T07:30:00Z"
	document := approvedNoticeDocument(releaseSHA, approvedAt)
	document["operator_name"] = "合成运营名称"
	refreshApprovalDigest(document)
	path := writeNoticeDocument(t, document, 0o600)

	notice, loadError := LoadNotice("production", path, releaseSHA, time.Date(2026, time.August, 9, 8, 0, 0, 0, time.UTC))
	if loadError != nil {
		t.Fatalf("approved operator name failed to load: %v", loadError)
	}
	publicJSON, marshalError := json.Marshal(notice)
	if marshalError != nil {
		t.Fatalf("approved operator name failed to encode: %v", marshalError)
	}
	projection := map[string]any{}
	if decodeError := json.Unmarshal(publicJSON, &projection); decodeError != nil {
		t.Fatalf("approved operator projection failed to decode: %v", decodeError)
	}
	if projection["operator_name"] != "合成运营名称" {
		t.Fatalf("approved operator name diverged: %#v", projection)
	}
	if _, exposedLegalClaim := projection["operator_legal_name"]; exposedLegalClaim {
		t.Fatalf("approved operator projection retained an unverified legal-name claim: %#v", projection)
	}
}

func approvedNoticeDocument(releaseSHA string, approvedAt string) map[string]any {
	document := map[string]any{
		"version": "privacy-notice-v1", "status": "approved",
		"operator_name": "合成测试经营主体", "public_contact": "业务微信：synthetic-career-desk", "approved_at": approvedAt,
		"student_closed_retention_days": 180, "audit_retention_days": 365, "backup_retention_days": 30,
		"session_absolute_days": 30, "invitation_absolute_hours": 72, "under_14_excluded": true,
		"release_sha": releaseSHA,
	}
	refreshApprovalDigest(document)
	return document
}

func refreshApprovalDigest(document map[string]any) {
	digestValues := []string{
		document["version"].(string), document["status"].(string), document["operator_name"].(string),
		document["public_contact"].(string), document["approved_at"].(string),
		fmt.Sprint(document["student_closed_retention_days"]), fmt.Sprint(document["audit_retention_days"]),
		fmt.Sprint(document["backup_retention_days"]), fmt.Sprint(document["session_absolute_days"]),
		fmt.Sprint(document["invitation_absolute_hours"]), "yes", document["release_sha"].(string),
	}
	digest := sha256.Sum256([]byte(strings.Join(digestValues, "\x00"))) // 独立冻结无尾随 NUL 的十二值顺序。
	document["approval_digest"] = fmt.Sprintf("%x", digest)
}

func writeNoticeDocument(t *testing.T, document map[string]any, permissions os.FileMode) string {
	t.Helper()
	body, marshalError := json.Marshal(document) // 编码器只产生一个 UTF-8 JSON 对象，不带额外文档。
	if marshalError != nil {
		t.Fatalf("synthetic approval document failed to encode: %v", marshalError)
	}
	path := filepath.Join(t.TempDir(), "privacy-notice.json")
	if writeError := os.WriteFile(path, body, permissions); writeError != nil {
		t.Fatalf("synthetic approval document failed to write: %v", writeError)
	}
	if chmodError := os.Chmod(path, permissions); chmodError != nil { // 消除测试进程 umask 对精确权限子例的影响。
		t.Fatalf("synthetic approval permissions failed: %v", chmodError)
	}
	return path
}

func writeRawNoticeDocument(t *testing.T, body []byte, permissions os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "privacy-notice.json")
	if writeError := os.WriteFile(path, body, permissions); writeError != nil {
		t.Fatalf("synthetic raw approval document failed to write: %v", writeError)
	}
	if chmodError := os.Chmod(path, permissions); chmodError != nil {
		t.Fatalf("synthetic raw approval permissions failed: %v", chmodError)
	}
	return path
}

func assertNoticeUnavailable(t *testing.T, path string, releaseSHA string, now time.Time) {
	t.Helper()
	if _, loadError := LoadNotice("production", path, releaseSHA, now); !errors.Is(loadError, ErrNoticeUnavailable) {
		t.Fatalf("expected unsafe approval file rejection, got %v", loadError)
	}
}
