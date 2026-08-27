/*
隐私说明公开入口：把启动时已验证的不可变 Notice 投影成匿名、禁止缓存的 HTTP envelope。
入口不读取文件、不访问数据库、不检查账号；所有内部审批字段已在 Notice 加载边界被移除。
调用示例：entry, entryError := privacy.NewNoticeHTTP(notice); entry.Register(api)。
*/
package privacy

import (
	"errors"   // 暴露不包含审批内容的稳定组合失败分类。
	"net/http" // 返回匿名 GET 的标准 200 状态。
	"time"     // 再次核对 APPROVED 公开时间使用 canonical RFC3339。

	"github.com/gin-gonic/gin" // 注册版本化公开路由并输出 JSON。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx" // 复用统一 request_id 反馈。
)

var ErrInvalidNoticeHTTPDependencies = errors.New("privacy notice HTTP dependencies are invalid") // 标识组合根传入了未经加载器验证的投影。

// NoticeHTTP 保存启动时冻结的公开投影；请求期间不再读取可变文件。
type NoticeHTTP struct {
	notice Notice
}

// --- 冻结一个可匿名发布的 Notice 副本 ---
func NewNoticeHTTP(notice Notice) (*NoticeHTTP, error) {
	if !validPublicNotice(notice) { // 防止绕过 LoadNotice 直接构造未批准或期限漂移的公开响应。
		return nil, ErrInvalidNoticeHTTPDependencies
	}
	return &NoticeHTTP{notice: cloneNotice(notice)}, nil // 深复制四个指针字段，避免调用方稍后改写公开事实。
}

// --- 注册无需账号或邀请能力的公开隐私说明路由 ---
func (entry *NoticeHTTP) Register(api *gin.RouterGroup) {
	api.GET("/public/privacy-notice", entry.get)
}

// --- 反馈固定公开投影并禁止浏览器或代理缓存 ---
func (entry *NoticeHTTP) get(context *gin.Context) {
	context.Header("Cache-Control", "no-store") // 审批版本切换后客户端必须立即读取当前进程投影。
	context.JSON(http.StatusOK, gin.H{
		"data": entry.notice,
		"meta": gin.H{"request_id": httpx.RequestID(context)},
	})
}

// --- 验证公开投影只有两种完整状态 ---
func validPublicNotice(notice Notice) bool {
	if notice.Version != noticeVersion || notice.StudentClosedRetentionDays != 180 || notice.AuditRetentionDays != 365 ||
		notice.BackupRetentionDays != 30 || notice.SessionAbsoluteDays != 30 || notice.InvitationAbsoluteHours != 72 {
		return false // 版本或任一期限漂移都不能绕过文件加载边界进入 HTTP。
	}
	if notice.Status == draftNoticeStatus {
		return notice.OperatorName == nil && notice.PublicContact == nil && notice.ApprovedAt == nil && notice.PublicationDigest == nil
	}
	if notice.Status != approvedNoticeStatus || notice.OperatorName == nil || notice.PublicContact == nil || notice.ApprovedAt == nil || notice.PublicationDigest == nil {
		return false // APPROVED 必须携带全部四个公开批准事实。
	}
	_, approvedAtError := time.Parse(time.RFC3339, *notice.ApprovedAt)
	return validPublishedText(*notice.OperatorName, 2, 128) && validPublishedText(*notice.PublicContact, 2, 128) &&
		approvedAtPattern.MatchString(*notice.ApprovedAt) && approvedAtError == nil && approvalDigestPattern.MatchString(*notice.PublicationDigest)
}

// --- 深复制公开字符串指针，保持 HTTP 生命周期内不可被调用方改写 ---
func cloneNotice(notice Notice) Notice {
	cloned := notice
	if notice.OperatorName != nil {
		value := *notice.OperatorName
		cloned.OperatorName = &value
	}
	if notice.PublicContact != nil {
		value := *notice.PublicContact
		cloned.PublicContact = &value
	}
	if notice.ApprovedAt != nil {
		value := *notice.ApprovedAt
		cloned.ApprovedAt = &value
	}
	if notice.PublicationDigest != nil {
		value := *notice.PublicationDigest
		cloned.PublicationDigest = &value
	}
	return cloned
}
