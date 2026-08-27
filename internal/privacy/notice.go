/*
隐私说明发布边界：synthetic 生成不含审批身份的内存 DRAFT，production 从受保护文件装配公开投影。
Notice 只包含允许匿名发布的字段；文件路径、发布 SHA 与内部批准标志永不进入该结构。
调用示例：notice, loadError := privacy.LoadNotice(runtimeMode, noticeFile, releaseSHA, now)。
*/
package privacy

import (
	"bytes"         // 从受限内存缓冲区严格解码一个 JSON 文档。
	"crypto/sha256" // 复算与发布 SHA 绑定的审批摘要。
	"encoding/hex"  // 把审批摘要编码为固定小写十六进制。
	"encoding/json" // 严格拒绝未知字段和尾随 JSON 文档。
	"errors"        // 暴露不包含文件路径或审批内容的稳定加载失败分类。
	"io"            // 限制审批文件尺寸并验证 JSON 已到 EOF。
	"os"            // 把 nofollow 文件描述符转换为可读取的普通文件。
	"regexp"        // 验证完整发布 SHA、摘要与批准时间的固定字符边界。
	"strconv"       // 按十进制固定格式加入五个期限摘要值。
	"strings"       // 验证净化文本并用 NUL 连接摘要字段。
	"time"          // 拒绝未来批准时间。
	"unicode"       // 拒绝经营主体或公开联系方式中的控制字符。
	"unicode/utf8"  // 在 JSON 解码替换非法字节前拒绝非 UTF-8 文件。

	"golang.org/x/sys/unix" // 使用 Linux O_NOFOLLOW 消除检查后替换符号链接的窗口。
)

var ErrNoticeUnavailable = errors.New("privacy notice is unavailable") // 标识运行身份或审批摘要未通过完整门禁。

const noticeVersion = "privacy-notice-v1" // 学生建档当前唯一允许引用的隐私说明版本。
const approvedDocumentStatus = "approved" // 受保护发布文件与 publisher 统一使用小写批准状态参与摘要。
const approvedNoticeStatus = "APPROVED"   // 匿名公开合同把已批准事实映射成稳定大写状态。
const draftNoticeStatus = "DRAFT"         // synthetic 只生成不可冒充正式批准的草案状态。
const maximumNoticeBytes = 16 * 1024      // 审批摘要只有固定小字段，超限文件拒绝进入内存。

var releaseSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)     // 发布身份必须是完整 40 位小写 Git SHA。
var approvalDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`) // 审批摘要必须是完整小写 SHA-256。
var approvedAtPattern = regexp.MustCompile(
	`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$`,
) // 与 publisher 的秒级 RFC3339 文本完全一致。

// Notice 是匿名接口唯一允许公开的隐私说明投影。
type Notice struct {
	Version                    string  `json:"version"`                       // Version 绑定学生建档所引用的说明版本。
	Status                     string  `json:"status"`                        // Status 在 synthetic 为 DRAFT，在 production 为 APPROVED。
	OperatorName               *string `json:"operator_name"`                 // OperatorName 未批准时为 null，不把公开名称冒充法定实名。
	PublicContact              *string `json:"public_contact"`                // PublicContact 未批准时为 null，可发布电话、业务微信等获批渠道。
	ApprovedAt                 *string `json:"approved_at"`                   // ApprovedAt 保留审批摘要中的 RFC3339 公开时间。
	StudentClosedRetentionDays int     `json:"student_closed_retention_days"` // StudentClosedRetentionDays 固定为结案后 180 天。
	AuditRetentionDays         int     `json:"audit_retention_days"`          // AuditRetentionDays 固定为 365 天。
	BackupRetentionDays        int     `json:"backup_retention_days"`         // BackupRetentionDays 固定为 30 天。
	SessionAbsoluteDays        int     `json:"session_absolute_days"`         // SessionAbsoluteDays 固定为 30 天。
	InvitationAbsoluteHours    int     `json:"invitation_absolute_hours"`     // InvitationAbsoluteHours 固定为 72 小时。
	PublicationDigest          *string `json:"publication_digest"`            // PublicationDigest 公开审批摘要指纹而不是内部 release SHA。
}

// approvalDocument 保存受保护文件的完整内部审批事实；该类型永不直接序列化到 HTTP。
type approvalDocument struct {
	Version                    string `json:"version"`                       // Version 必须是当前学生建档说明版本。
	Status                     string `json:"status"`                        // Status 只接受 publisher 的小写 approved。
	OperatorName               string `json:"operator_name"`                 // OperatorName 是获批公开展示的运营名称。
	PublicContact              string `json:"public_contact"`                // PublicContact 是老板批准的公开请求渠道。
	ApprovedAt                 string `json:"approved_at"`                   // ApprovedAt 是参与摘要的秒级 RFC3339 文本。
	StudentClosedRetentionDays int    `json:"student_closed_retention_days"` // StudentClosedRetentionDays 必须为 180。
	AuditRetentionDays         int    `json:"audit_retention_days"`          // AuditRetentionDays 必须为 365。
	BackupRetentionDays        int    `json:"backup_retention_days"`         // BackupRetentionDays 必须为 30。
	SessionAbsoluteDays        int    `json:"session_absolute_days"`         // SessionAbsoluteDays 必须为 30。
	InvitationAbsoluteHours    int    `json:"invitation_absolute_hours"`     // InvitationAbsoluteHours 必须为 72。
	Under14Excluded            bool   `json:"under_14_excluded"`             // Under14Excluded 是不得对外投影的运营批准标志。
	ReleaseSHA                 string `json:"release_sha"`                   // ReleaseSHA 把审批绑定到唯一 production 构建。
	ApprovalDigest             string `json:"approval_digest"`               // ApprovalDigest 绑定以上固定顺序值，公开时改名 publication_digest。
}

// --- 按运行身份装配公开隐私说明 ---
func LoadNotice(runtimeMode string, noticeFile string, releaseSHA string, now time.Time) (Notice, error) {
	if runtimeMode == "synthetic" { // synthetic 明确走不接触文件的内存分支。
		if noticeFile != "" { // 即使调用方绕过 config，也不能把生产审批文件带入合成进程。
			return Notice{}, ErrNoticeUnavailable
		}
		return draftNotice(), nil
	}
	if runtimeMode != "production" || noticeFile == "" || now.IsZero() || !releaseSHAPattern.MatchString(releaseSHA) { // 未审查身份或缺失绑定事实一律失败关闭。
		return Notice{}, ErrNoticeUnavailable
	}
	document, readError := readApprovalDocument(noticeFile) // 通过同一个 nofollow 描述符完成权限检查和读取。
	if readError != nil || !validApprovalDocument(document, releaseSHA, now.UTC()) {
		return Notice{}, ErrNoticeUnavailable // 对外不区分路径、权限、字段或摘要错误，避免泄露部署细节。
	}
	operatorName := document.OperatorName // 复制公开字段，返回结构不再持有内部文档。
	publicContact := document.PublicContact
	approvedAt := document.ApprovedAt
	publicationDigest := document.ApprovalDigest
	return Notice{
		Version: document.Version, Status: approvedNoticeStatus,
		OperatorName: &operatorName, PublicContact: &publicContact, ApprovedAt: &approvedAt,
		StudentClosedRetentionDays: document.StudentClosedRetentionDays, AuditRetentionDays: document.AuditRetentionDays,
		BackupRetentionDays: document.BackupRetentionDays, SessionAbsoluteDays: document.SessionAbsoluteDays,
		InvitationAbsoluteHours: document.InvitationAbsoluteHours, PublicationDigest: &publicationDigest,
	}, nil // 只反馈冻结的十一个公开字段，不携带文件路径、release SHA 或内部年龄标志。
}

// --- 创建不包含任何虚构审批事实的合成草案 ---
func draftNotice() Notice {
	return Notice{
		Version: noticeVersion, Status: draftNoticeStatus,
		StudentClosedRetentionDays: 180, AuditRetentionDays: 365, BackupRetentionDays: 30,
		SessionAbsoluteDays: 30, InvitationAbsoluteHours: 72,
	}
}

// --- 从精确 0600 普通文件读取唯一 JSON 对象 ---
func readApprovalDocument(path string) (approvalDocument, error) {
	fileDescriptor, openError := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) // 非阻塞打开让 FIFO 等非普通目标也能立即失败。
	if openError != nil {
		return approvalDocument{}, ErrNoticeUnavailable
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	if file == nil { // 极端描述符包装失败时仍关闭原始资源。
		_ = unix.Close(fileDescriptor)
		return approvalDocument{}, ErrNoticeUnavailable
	}
	defer func() { _ = file.Close() }()
	information, statError := file.Stat() // 从已打开描述符核对真实目标而不是路径缓存。
	if statError != nil || !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 {
		return approvalDocument{}, ErrNoticeUnavailable
	}
	body, readError := io.ReadAll(io.LimitReader(file, maximumNoticeBytes+1)) // 多读一个字节以确定超限，而不分配无界内存。
	if readError != nil || len(body) == 0 || len(body) > maximumNoticeBytes || !utf8.Valid(body) {
		return approvalDocument{}, ErrNoticeUnavailable
	}
	if !hasExactApprovalFields(body) { // 大小写漂移或重复键会让不同解析器看到不同批准事实，必须先拒绝。
		return approvalDocument{}, ErrNoticeUnavailable
	}
	document := approvalDocument{}
	decoder := json.NewDecoder(bytes.NewReader(body)) // 严格结构避免拼写错误悄悄降级审批事实。
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(&document); decodeError != nil {
		return approvalDocument{}, ErrNoticeUnavailable
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) { // 只允许一个 JSON 对象，拒绝尾随值。
		return approvalDocument{}, ErrNoticeUnavailable
	}
	return document, nil
}

// --- 逐字锁定十三个根字段，消除大小写宽松匹配和“后值覆盖前值”歧义 ---
func hasExactApprovalFields(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, openingError := decoder.Token()
	if openingError != nil || opening != json.Delim('{') {
		return false // 审批摘要必须从一个 JSON 对象开始。
	}
	fieldNames := make(map[string]struct{}, 13) // 固定审批合同当前恰有十三个字段。
	for decoder.More() {
		fieldToken, fieldError := decoder.Token()
		fieldName, isFieldName := fieldToken.(string)
		if fieldError != nil || !isFieldName {
			return false
		}
		if !isApprovalDocumentField(fieldName) {
			return false // encoding/json 会忽略字段名大小写差异，此处先执行逐字 allowlist。
		}
		if _, repeated := fieldNames[fieldName]; repeated {
			return false // 同名字段不得依赖 JSON 实现的覆盖顺序。
		}
		fieldNames[fieldName] = struct{}{}
		value := json.RawMessage{}
		if valueError := decoder.Decode(&value); valueError != nil { // 消耗完整字段值后继续检查下一个根键。
			return false
		}
	}
	closing, closingError := decoder.Token()
	return closingError == nil && closing == json.Delim('}') && len(fieldNames) == 13 // 必须完整出现恰好十三个审批字段。
}

func isApprovalDocumentField(fieldName string) bool {
	switch fieldName {
	case "version", "status", "operator_name", "public_contact", "approved_at",
		"student_closed_retention_days", "audit_retention_days", "backup_retention_days",
		"session_absolute_days", "invitation_absolute_hours", "under_14_excluded", "release_sha", "approval_digest":
		return true
	default:
		return false
	}
}

// --- 验证审批身份、固定期限、时间和发布摘要 ---
func validApprovalDocument(document approvalDocument, releaseSHA string, now time.Time) bool {
	if document.Version != noticeVersion || document.Status != approvedDocumentStatus || document.ReleaseSHA != releaseSHA || !releaseSHAPattern.MatchString(document.ReleaseSHA) {
		return false // 版本、批准状态和运行中完整发布身份必须同时一致。
	}
	if !validPublishedText(document.OperatorName, 2, 128) || !validPublishedText(document.PublicContact, 2, 128) {
		return false // 运营名称和公开联系方式必须是净化后的真实非空公开文本。
	}
	approvedAt, parseError := time.Parse(time.RFC3339, document.ApprovedAt)
	if !approvedAtPattern.MatchString(document.ApprovedAt) || parseError != nil || approvedAt.After(now) {
		return false // 无效或未来审批时间不能授权当前进程发布。
	}
	if document.StudentClosedRetentionDays != 180 || document.AuditRetentionDays != 365 || document.BackupRetentionDays != 30 ||
		document.SessionAbsoluteDays != 30 || document.InvitationAbsoluteHours != 72 || !document.Under14Excluded {
		return false // 任一期限或内部运营年龄边界漂移都必须重新走发布审批。
	}
	expectedDigest := approvalDigest(document)
	return approvalDigestPattern.MatchString(document.ApprovalDigest) && document.ApprovalDigest == expectedDigest
}

// --- 校验经营主体等公开文本已经净化且没有控制字符 ---
func validPublishedText(value string, minimumRunes int, maximumRunes int) bool {
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "$`;|<>\\") {
		return false // 摘要绑定最终展示文本，并与 publisher 使用同一字符边界。
	}
	runeCount := utf8.RuneCountInString(value)
	if runeCount < minimumRunes || runeCount > maximumRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// --- 按冻结 NUL 顺序复算绑定 release SHA 的审批摘要 ---
func approvalDigest(document approvalDocument) string {
	values := []string{
		document.Version, document.Status, document.OperatorName, document.PublicContact, document.ApprovedAt,
		strconv.Itoa(document.StudentClosedRetentionDays), strconv.Itoa(document.AuditRetentionDays),
		strconv.Itoa(document.BackupRetentionDays), strconv.Itoa(document.SessionAbsoluteDays),
		strconv.Itoa(document.InvitationAbsoluteHours), "yes", document.ReleaseSHA,
	}
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00"))) // Join 在字段之间放 NUL，不产生尾随 NUL。
	return hex.EncodeToString(digest[:])
}
