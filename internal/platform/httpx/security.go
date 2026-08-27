/*
浏览器写请求门禁：在正文解析和业务查询前验证同源、Fetch Metadata 与双提交 CSRF。
创建型路由可叠加 RequireIdempotencyKey，把已验证键显式传给命令层。
*/
package httpx

import (
	"crypto/subtle" // 以固定时间比较 CSRF Cookie 与请求头。
	"net/http"      // 区分安全读取方法和状态改变方法。
	"regexp"        // 限定幂等键为无空白的安全标识字符。

	"github.com/gin-gonic/gin" // 在统一路由边界拒绝危险浏览器请求。
)

const CSRFTokenCookieName = "__Host-p17_csrf"                             // 同源 HTTPS 下由前端读取并回送的双提交 Cookie。
const idempotencyContextKey = "careerpathdesk.idempotency-key"            // 包私有上下文 key，避免业务 handler 自行解析头部。
var validIdempotencyKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`) // 可重试创建意图的固定安全格式。

// SecurityConfig 保存浏览器写请求唯一可信来源。
type SecurityConfig struct {
	PublicOrigin string // PublicOrigin 必须与配置层验证后的部署同源值精确相等。
}

// --- 在业务读取前验证状态改变请求 ---
func BrowserMutationSecurity(configuration SecurityConfig) gin.HandlerFunc {
	return func(context *gin.Context) {
		if isSafeMethod(context.Request.Method) { // GET/HEAD/OPTIONS 不改变状态，不要求 CSRF。
			context.Next()
			return
		}
		if context.GetHeader("Origin") != configuration.PublicOrigin || context.GetHeader("Sec-Fetch-Site") != "same-origin" {
			AbortProblem(context, http.StatusForbidden, "origin_rejected", "Request origin was rejected.")
			return
		}
		if isPreSessionMutation(context.Request.URL.Path) { // 登录和邀请兑换成功前尚不存在可信 CSRF Cookie。
			context.Next()
			return
		}
		csrfCookie, cookieError := context.Cookie(CSRFTokenCookieName)
		csrfHeader := context.GetHeader("X-CSRF-Token")
		if cookieError != nil || len(csrfCookie) < 32 || len(csrfCookie) > 256 || len(csrfHeader) != len(csrfCookie) || subtle.ConstantTimeCompare([]byte(csrfCookie), []byte(csrfHeader)) != 1 {
			AbortProblem(context, http.StatusForbidden, "csrf_rejected", "Request verification failed.")
			return
		}
		context.Next() // 同源和 CSRF 证据完成后才允许正文与业务读取。
	}
}

// --- 为创建型命令提取一个合规幂等键 ---
func RequireIdempotencyKey() gin.HandlerFunc {
	return func(context *gin.Context) {
		key := context.GetHeader("Idempotency-Key") // 只接受一个固定头，不从 query/body 猜测。
		if !validIdempotencyKey.MatchString(key) {
			AbortProblem(context, http.StatusBadRequest, "idempotency_key_required", "A valid Idempotency-Key is required.")
			return
		}
		context.Set(idempotencyContextKey, key) // 后续命令只消费已验证值。
		context.Next()
	}
}

// IdempotencyKey 反馈本路由已经验证的创建意图身份。
func IdempotencyKey(context *gin.Context) string {
	key, _ := context.Get(idempotencyContextKey)
	value, _ := key.(string)
	return value
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func isPreSessionMutation(path string) bool {
	return path == "/api/v2/auth/login" || path == "/api/v2/public/invitations/exchange" ||
		path == "/api/v2/auth/mfa/enrollment" || path == "/api/v2/auth/mfa/enrollment/confirm" || path == "/api/v2/auth/mfa/verify"
}
