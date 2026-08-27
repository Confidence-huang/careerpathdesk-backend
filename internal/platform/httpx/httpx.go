/*
HTTP 基础反馈：为每个请求建立服务端身份、固定安全响应头和统一错误 envelope。
该层不读取正文、不判断业务权限，也不记录 URL、Cookie 或响应内容。
调用示例：router.Use(httpx.Foundation(func() (string, error) { return identity.New("R") }))。
*/
package httpx

import (
	"net/http" // 使用标准服务不可用状态保护请求身份失败边界。

	"github.com/gin-gonic/gin" // 在 Gin 请求上下文传递单一请求身份。
)

const requestIDContextKey = "careerpathdesk.request-id" // 使用包私有 key，避免业务 handler 覆盖基础身份。

// ProblemEnvelope 是所有 API 业务错误的稳定顶层形状。
type ProblemEnvelope struct {
	Error Problem `json:"error"` // Error 集中固定码、普通说明和关联请求身份。
}

// Problem 不接收底层 error、SQL、配置或业务正文。
type Problem struct {
	Code      string `json:"code"`       // Code 是客户端可分支的固定机器码。
	Message   string `json:"message"`    // Message 是不含内部细节的用户可读说明。
	RequestID string `json:"request_id"` // RequestID 用于关联受控服务端元数据，并与冻结 OpenAPI 的 snake_case 一致。
}

// --- 建立每个 HTTP 请求的基础反馈边界 ---
func Foundation(newRequestID func() (string, error)) gin.HandlerFunc {
	return func(context *gin.Context) {
		setSecurityHeaders(context) // 即使后续身份生成失败，也保持不缓存和浏览器安全边界。
		requestID, createError := newRequestID()
		if createError != nil || requestID == "" { // 缺少可信身份时不进入任何业务 handler。
			context.AbortWithStatusJSON(http.StatusServiceUnavailable, ProblemEnvelope{Error: Problem{
				Code: "request_identity_unavailable", Message: "Request unavailable.", RequestID: "",
			}})
			return
		}
		context.Set(requestIDContextKey, requestID) // 将同一身份传给错误映射、日志与业务命令。
		context.Header("X-Request-ID", requestID)   // 让客户端可以报告对应失败，不接受客户端覆盖。
		context.Next()                              // 身份和响应边界完成后才进入下游。
	}
}

// --- 读取本请求已经建立的服务端身份 ---
func RequestID(context *gin.Context) string {
	requestID, _ := context.Get(requestIDContextKey) // Foundation 缺失时反馈空值，让调用方失败关闭。
	value, _ := requestID.(string)
	return value
}

// --- 用固定 envelope 停止当前请求 ---
func AbortProblem(context *gin.Context, status int, code string, message string) {
	context.AbortWithStatusJSON(status, ProblemEnvelope{Error: Problem{
		Code: code, Message: message, RequestID: RequestID(context),
	}})
}

// --- 设置 API 响应的统一浏览器边界 ---
func setSecurityHeaders(context *gin.Context) {
	context.Header("Cache-Control", "no-store")
	context.Header("X-Content-Type-Options", "nosniff")
	context.Header("X-Frame-Options", "DENY")
	context.Header("Referrer-Policy", "no-referrer")
	context.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}
