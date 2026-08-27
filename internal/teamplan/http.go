/*
团队计划 HTTP 入口：把已认证工作台触发映射为一个团队计划 Commands 动作和稳定 JSON 反馈。
本文件只负责认证、严格输入和错误映射；老板权限、正文规则、版本与事务留在命令层。
调用示例：teamPlanHTTP.Register(router.Group("/api/v2"))。
*/
package teamplan

import (
	"errors"   // 将认证和命令失败映射成稳定问题码。
	"net/http" // 使用明确 REST 状态码反馈结果。

	"github.com/gin-gonic/gin" // 注册版本化 API 路由。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"           // 接收认证模块恢复的当前账号。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx" // 复用严格 JSON 和请求身份。
)

var ErrInvalidHTTPDependencies = errors.New("team plan HTTP dependencies are invalid") // 命令或认证能力缺失。

type currentAccount func(*gin.Context) (auth.Account, error) // 只接收团队计划需要的认证投影。

// HTTP 将传输层触发收敛到 Commands 深模块。
type HTTP struct {
	commands *Commands      // commands 隐藏账号复核、正文规则、版本和事务。
	current  currentAccount // current 每次重新验证 JWT 与数据库会话。
}

type updateHTTPInput struct {
	Title   string `json:"title"`   // Title 是完整替换值。
	Summary string `json:"summary"` // Summary 是完整替换值。
	Content string `json:"content"` // Content 是保留真实换行的普通文本。
	Version int64  `json:"version"` // Version 绑定页面读取的旧计划。
}

// --- 装配团队计划 HTTP 入口 ---
func NewHTTP(commands *Commands, current currentAccount) (*HTTP, error) {
	if commands == nil || current == nil { // 缺少任一依赖时不建立半可用路由。
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current}, nil // 反馈可注册的窄 HTTP 入口。
}

// --- 注册工作台计划读取和保存路由 ---
func (entry *HTTP) Register(api *gin.RouterGroup) {
	api.GET("/team-plan", entry.read)     // 老板和老师读取同一计划。
	api.PATCH("/team-plan", entry.update) // 只有老板命令允许写入。
}

// --- 读取工作台团队计划 ---
func (entry *HTTP) read(context *gin.Context) {
	actor, authorized := entry.authorize(context) // 先恢复当前账号再访问业务命令。
	if !authorized {
		return
	}
	plan, commandError := entry.commands.Read(context.Request.Context(), actor) // 命令在事务中重验账号。
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	writeNoStore(context) // 团队计划属于当前账号动态事实，不进入浏览器缓存。
	context.JSON(http.StatusOK, gin.H{"data": plan, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

// --- 保存工作台团队计划 ---
func (entry *HTTP) update(context *gin.Context) {
	actor, authorized := entry.authorize(context) // HTTP 只恢复身份，老板权限由命令再次裁决。
	if !authorized {
		return
	}
	input := updateHTTPInput{}                                                            // 接收完整编辑快照。
	if decodeError := httpx.DecodeSingleJSON(context, &input, 8192); decodeError != nil { // 拒绝未知、重复或超长 JSON。
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Team plan input is invalid.")
		return
	}
	updated, commandError := entry.commands.Update(context.Request.Context(), actor, httpx.RequestID(context), UpdateInput{Title: input.Title, Summary: input.Summary, Content: input.Content, Version: input.Version})
	if commandError != nil {
		entry.writeProblem(context, commandError)
		return
	}
	writeNoStore(context) // 保存反馈同样禁止被共享缓存保存。
	context.JSON(http.StatusOK, gin.H{"data": updated, "meta": gin.H{"request_id": httpx.RequestID(context)}})
}

// --- 恢复当前后台团队账号并限制首次改密状态 ---
func (entry *HTTP) authorize(context *gin.Context) (auth.Account, bool) {
	actor, authenticationError := entry.current(context) // 使用认证模块统一会话恢复入口。
	if authenticationError != nil {
		httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return auth.Account{}, false
	}
	if actor.MustChangePassword {
		httpx.AbortProblem(context, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Password change is required.")
		return auth.Account{}, false
	}
	if actor.State != "active" || (actor.Role != "owner" && actor.Role != "staff") {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Team plan access is forbidden.")
		return auth.Account{}, false
	}
	return actor, true // 反馈可交给命令再次数据库复核的账号投影。
}

// --- 映射团队计划命令的稳定失败分类 ---
func (entry *HTTP) writeProblem(context *gin.Context, commandError error) {
	writeNoStore(context) // 所有问题响应都避免缓存旧权限或旧版本。
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Team plan access is forbidden.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Team plan input is invalid.")
	case errors.Is(commandError, ErrNotFound):
		httpx.AbortProblem(context, http.StatusNotFound, "NOT_FOUND", "Team plan was not found.")
	case errors.Is(commandError, ErrVersionConflict):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Team plan state changed.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Team plan is temporarily unavailable.")
	}
}

func writeNoStore(context *gin.Context) {
	context.Header("Cache-Control", "no-store") // 禁止缓存含当前账号范围的动态事实。
	context.Header("Pragma", "no-cache")        // 兼容仍读取旧缓存头的浏览器。
}
