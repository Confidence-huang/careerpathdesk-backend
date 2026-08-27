/*
账号管理 HTTP 入口：先恢复可信逐人账号并执行老板门禁，再解析路径或严格 JSON。
本文件只映射传输合同；密码派生、事务、审计、幂等和会话撤销全部留在 Commands 深模块。
调用示例：management.Register(router.Group("/api/v2"))。
*/
package accounts

import (
	"errors"   // 将稳定命令失败分类映射为冻结问题码。
	"net/http" // 使用冻结账号路由的 HTTP 状态。

	"github.com/gin-gonic/gin" // 注册版本化老板账号管理路由。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"           // 接收认证模块反馈的可信当前账号。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx" // 复用请求身份、严格 JSON、幂等与问题 envelope。
)

var ErrInvalidHTTPDependencies = errors.New("account HTTP dependencies are invalid") // 命令或认证能力未装配。

type currentAccount func(*gin.Context) (auth.Account, error) // 只暴露账号模块实际需要的认证投影。

// HTTP 将账号管理触发映射到一个 Commands 接口。
type HTTP struct {
	commands *Commands      // commands 隐藏全部业务与 PostgreSQL 细节。
	current  currentAccount // current 由认证模块验证访问 JWT 和数据库会话。
}

type createInput struct {
	Username        string  `json:"username"`
	DisplayName     string  `json:"display_name"`
	Role            string  `json:"role"`
	StaffProfileID  *string `json:"staff_profile_id"`
	InitialPassword string  `json:"initial_password"`
}

type updateInput struct {
	State          string  `json:"state"`
	StaffProfileID *string `json:"staff_profile_id"`
	Version        int64   `json:"version"`
}

type renameSelfInput struct {
	DisplayName string `json:"display_name"`
}

type resetPasswordInput struct {
	InitialPassword string `json:"initial_password"`
}

type accountEnvelope struct {
	Data Account      `json:"data"`
	Meta responseMeta `json:"meta"`
}

type accountListEnvelope struct {
	Data []Account    `json:"data"`
	Meta responseMeta `json:"meta"`
}

type responseMeta struct {
	RequestID string `json:"request_id"`
}

// --- 装配老板账号管理 HTTP 入口 ---
func NewHTTP(commands *Commands, current currentAccount) (*HTTP, error) {
	if commands == nil || current == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current}, nil
}

// --- 注册冻结账号管理路由 ---
func (management *HTTP) Register(versionedAPI *gin.RouterGroup) {
	versionedAPI.GET("/accounts", management.list)
	versionedAPI.POST("/accounts", httpx.RequireIdempotencyKey(), management.create)
	versionedAPI.PATCH("/accounts/me", management.renameSelf)
	versionedAPI.PATCH("/accounts/:accountId", management.update)
	versionedAPI.POST("/accounts/:accountId/reset-password", management.resetPassword)
}

// --- 已登录老板或老师修改本人显示名称 ---
func (management *HTTP) renameSelf(context *gin.Context) {
	actor, authenticationError := management.current(context)
	if authenticationError != nil {
		if errors.Is(authenticationError, auth.ErrAuthenticationRequired) || errors.Is(authenticationError, auth.ErrAccountDisabled) {
			httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		} else {
			httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Account management is temporarily unavailable.")
		}
		return
	}
	if actor.MustChangePassword {
		httpx.AbortProblem(context, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Password change is required.")
		return
	}
	input := renameSelfInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Account input is invalid.")
		return
	}
	updated, updateError := management.commands.RenameSelf(context.Request.Context(), actor, httpx.RequestID(context), RenameSelfInput{DisplayName: input.DisplayName})
	if updateError != nil {
		writeSelfAccountProblem(context, updateError)
		return
	}
	context.JSON(http.StatusOK, accountEnvelope{Data: updated, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

func writeSelfAccountProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Account access is required.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Account input is invalid.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Account management is temporarily unavailable.")
	}
}

// --- 列出包括停用身份在内的全部账号 ---
func (management *HTTP) list(context *gin.Context) {
	actor, authorized := management.authorizeOwner(context)
	if !authorized {
		return
	}
	accounts, listError := management.commands.List(context.Request.Context(), actor)
	if listError != nil {
		writeAccountProblem(context, listError)
		return
	}
	context.JSON(http.StatusOK, accountListEnvelope{Data: accounts, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 创建一个逐人账号 ---
func (management *HTTP) create(context *gin.Context) {
	actor, authorized := management.authorizeOwner(context) // 老板门禁先于正文解码和密码派生。
	if !authorized {
		return
	}
	input := createInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Account input is invalid.")
		return
	}
	created, createError := management.commands.Create(context.Request.Context(), actor, httpx.RequestID(context), httpx.IdempotencyKey(context), CreateInput{
		Username: input.Username, DisplayName: input.DisplayName, Role: input.Role,
		StaffProfileID: input.StaffProfileID, InitialPassword: input.InitialPassword,
	})
	if createError != nil {
		writeAccountProblem(context, createError)
		return
	}
	context.JSON(http.StatusCreated, accountEnvelope{Data: created, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 版本化修改账号状态或责任关联 ---
func (management *HTTP) update(context *gin.Context) {
	actor, authorized := management.authorizeOwner(context) // 未授权时不读取目标 ID 或正文。
	if !authorized {
		return
	}
	input := updateInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Account input is invalid.")
		return
	}
	updated, updateError := management.commands.Update(context.Request.Context(), actor, httpx.RequestID(context), context.Param("accountId"), UpdateInput{
		State: input.State, StaffProfileID: input.StaffProfileID, Version: input.Version,
	})
	if updateError != nil {
		writeAccountProblem(context, updateError)
		return
	}
	context.JSON(http.StatusOK, accountEnvelope{Data: updated, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 设置目标账号的新临时密码 ---
func (management *HTTP) resetPassword(context *gin.Context) {
	actor, authorized := management.authorizeOwner(context) // 未授权时不读取目标 ID 或密码正文。
	if !authorized {
		return
	}
	input := resetPasswordInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Password input is invalid.")
		return
	}
	if _, resetError := management.commands.ResetPassword(context.Request.Context(), actor, httpx.RequestID(context), context.Param("accountId"), input.InitialPassword); resetError != nil {
		writeAccountProblem(context, resetError)
		return
	}
	context.Status(http.StatusNoContent)
}

// --- 恢复当前账号并执行老板专属门禁 ---
func (management *HTTP) authorizeOwner(context *gin.Context) (auth.Account, bool) {
	actor, authenticationError := management.current(context)
	if authenticationError != nil {
		if errors.Is(authenticationError, auth.ErrAuthenticationRequired) || errors.Is(authenticationError, auth.ErrAccountDisabled) {
			httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		} else {
			httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Account management is temporarily unavailable.")
		}
		return auth.Account{}, false
	}
	if actor.MustChangePassword {
		httpx.AbortProblem(context, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Password change is required.")
		return auth.Account{}, false
	}
	if actor.Role != "owner" || actor.State != "active" {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
		return auth.Account{}, false
	}
	return actor, true
}

// --- 映射账号命令的稳定失败分类 ---
func writeAccountProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Account input is invalid.")
	case errors.Is(commandError, ErrNotFound):
		httpx.AbortProblem(context, http.StatusNotFound, "NOT_FOUND", "Account was not found.")
	case errors.Is(commandError, ErrVersionConflict), errors.Is(commandError, ErrConflict):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Account state changed or conflicts with an existing identity.")
	case errors.Is(commandError, ErrIdempotencyConflict):
		httpx.AbortProblem(context, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with another request.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Account management is temporarily unavailable.")
	}
}
