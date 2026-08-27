/*
HTTP 路由装配：把外部 HTTP 触发连接到 CareerPathDesk 已交付的反馈入口。
健康入口始终由平台层注册；已经交付的业务模块通过一个显式函数挂到同一版本化 API 组。
调用示例：runtime.NewRouter(buildInfo, readiness, browserSecurity, authentication.Register)。
*/
package runtime

import (
	"context"  // 把请求取消传递到数据库就绪检查。
	"net/http" // 使用标准状态码表达最小健康反馈。

	"github.com/gin-gonic/gin" // 提供轻量 HTTP 路由和 JSON 反馈能力。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"    // 为所有响应建立请求身份和固定安全头。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/identity" // 使用不可推测的服务端请求 ID。
)

// BuildInfo 保存可注入的构建身份，但不会通过公开健康响应泄露。
type BuildInfo struct {
	Version string // Version 标识构建版本，供未来受控诊断使用。
}

// Readiness 收拢决定是否接收业务流量的外部依赖检查。
type Readiness struct {
	Database func(context.Context) error // Database 证明 PostgreSQL 当前可响应最小查询。
}

// --- 装配已交付 HTTP 入口 ---
func NewRouter(buildInfo BuildInfo, readiness Readiness, browserSecurity httpx.SecurityConfig, registerBusinessRoutes func(*gin.RouterGroup)) http.Handler {
	_ = buildInfo                                                                     // Foundation 只接收构建身份，不将其反馈给匿名健康请求。
	gin.SetMode(gin.ReleaseMode)                                                      // 禁止框架调试输出复制路由或未来请求细节。
	router := gin.New()                                                               // 创建无默认访问日志的路由器，避免意外记录敏感 URL。
	router.Use(httpx.Foundation(func() (string, error) { return identity.New("R") })) // 在路由前建立统一反馈边界。
	router.Use(httpx.BrowserMutationSecurity(browserSecurity))                        // 在未来写路由正文和业务读取前验证同源证据。
	versionedAPI := router.Group("/api/v2")                                           // 将所有应用合同集中到明确版本边界。
	versionedAPI.GET("/health/live", getLiveness)                                     // 注册不接触数据库的进程存活入口。
	versionedAPI.GET("/health/ready", getReadiness(readiness))                        // 注册只有依赖可用才成功的流量门禁。
	if registerBusinessRoutes != nil {                                                // Foundation 测试可省略业务模块，正式入口必须显式传入。
		registerBusinessRoutes(versionedAPI) // 业务模块只得到版本组，不接管平台中间件或健康入口。
	}

	return router // 将完整 HTTP 入口反馈给进程启动层和行为测试。
}

// --- 构造数据库就绪反馈 ---
func getReadiness(readiness Readiness) gin.HandlerFunc {
	return func(context *gin.Context) { // 在每次代理探测时读取最新依赖事实。
		if readiness.Database == nil || readiness.Database(context.Request.Context()) != nil { // 缺失检查或数据库失败都拒绝业务流量。
			context.JSON(http.StatusServiceUnavailable, gin.H{"status": "unavailable"})
			return
		}
		context.JSON(http.StatusOK, gin.H{"status": "ok"}) // 只有数据库明确成功才反馈 ready。
	}
}

// --- 反馈进程存活事实 ---
func getLiveness(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"status": "ok"}) // 只返回固定状态，不暴露版本、环境或依赖。
}
