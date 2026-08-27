/*
认证 HTTP 入口：校验浏览器 JSON，调用一个账号会话命令，并把一次性凭据收敛为安全 Cookie。
本文件不查询数据库、不验证密码、不决定账号状态；这些规则全部由 SessionCommands 承担。
调用示例：authentication.Register(router.Group("/api/v2"))。
*/
package auth

import (
	"crypto/rand"     // 为双提交 CSRF Cookie 生成独立随机值。
	"encoding/base64" // 将随机 CSRF 字节编码为 Cookie 安全文本。
	"errors"          // 区分稳定认证命令失败分类。
	"net/http"        // 设置状态码和浏览器 Cookie 安全属性。
	"strings"         // 严格拆分刷新 Cookie 中的会话 ID 与 opaque secret。
	"time"            // MFA challenge envelope 使用明确 UTC 期限。
	"unicode/utf8"    // 按用户可见字符执行 OpenAPI 长度合同。

	"github.com/gin-gonic/gin" // 注册版本化认证路由并反馈 JSON。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx" // 读取 Foundation 建立的服务端请求身份。
)

const accessCookieName = "__Host-p17_access"                // 五分钟访问 JWT 只由浏览器自动携带。
const refreshCookieName = "__Secure-p17_refresh"            // 子路径 Cookie 使用合规 Secure 前缀，只发送给认证路由。
const mfaChallengeCookieName = "__Secure-p17_mfa_challenge" // 密码后的短期 secret 只发送给 MFA 子路径。
const csrfTokenBytes = 32                                   // 256 位双提交值避免被跨站请求猜中。

var ErrInvalidHTTPDependencies = errors.New("authentication HTTP dependencies are invalid") // 标识会话或 JWT 能力未装配。

// HTTP 只负责认证触发与浏览器反馈，安全状态机留在命令模块。
type HTTP struct {
	sessions *SessionCommands // sessions 原子验证账号并创建数据库会话。
	tokens   *AccessTokens    // tokens 把可信会话投影签成五分钟访问 JWT。
	mfa      *MFACommands     // mfa 非空且启用时在正常会话前强制完成第二因素。
}

// loginInput 是登录路由唯一接受的 JSON 白名单。
type loginInput struct {
	Username string `json:"username"` // Username 是用户输入的逐人登录名。
	Password string `json:"password"` // Password 只在本次命令调用内存在。
}

// changePasswordInput 是本人改密唯一接受的 JSON 白名单。
type changePasswordInput struct {
	CurrentPassword string `json:"current_password"` // CurrentPassword 再次证明本人掌握现有凭据。
	NewPassword     string `json:"new_password"`     // NewPassword 由命令层生成新的 Argon2id hash。
}

// sessionEnvelope 是登录成功后不含秘密的固定公开反馈。
type sessionEnvelope struct {
	Data sessionData  `json:"data"` // Data 只包含当前账号投影。
	Meta responseMeta `json:"meta"` // Meta 关联服务端请求身份。
}

// sessionData 保存认证页面需要的最小账号状态。
type sessionData struct {
	Account Account `json:"account"` // Account 不含密码 hash、Cookie 或内部时间。
}

// responseMeta 保存跨请求问题排查所需的非敏感身份。
type responseMeta struct {
	RequestID string `json:"request_id"` // RequestID 来自 Foundation，不相信客户端输入。
}

// sessionListEnvelope 是本人设备页的固定列表反馈。
type sessionListEnvelope struct {
	Data []Session    `json:"data"` // Data 最多包含最近 50 条无秘密会话事实。
	Meta responseMeta `json:"meta"` // Meta 关联本次服务端请求身份。
}

type mfaChallengeEnvelope struct {
	Data struct {
		Code      string    `json:"code"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"data"`
	Meta responseMeta `json:"meta"`
}

type mfaEnrollmentEnvelope struct {
	Data Enrollment   `json:"data"`
	Meta responseMeta `json:"meta"`
}

type mfaCodeInput struct {
	Code string `json:"code"`
}

type mfaConfirmationEnvelope struct {
	Data struct {
		Account       Account       `json:"account"`
		RecoveryCodes RecoveryCodes `json:"recovery_codes"`
	} `json:"data"`
	Meta responseMeta `json:"meta"`
}

// --- 装配认证 HTTP 入口 ---
func NewHTTP(sessions *SessionCommands, tokens *AccessTokens) (*HTTP, error) {
	return NewHTTPWithMFA(sessions, tokens, nil)
}

// NewHTTPWithMFA 装配生产 MFA；nil 保留已有显式 UAT 登录行为。
func NewHTTPWithMFA(sessions *SessionCommands, tokens *AccessTokens, mfa *MFACommands) (*HTTP, error) {
	if sessions == nil || tokens == nil { // 缺少任一安全能力时不注册半可用登录路由。
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{sessions: sessions, tokens: tokens, mfa: mfa}, nil // 反馈只负责传输映射的认证入口。
}

// --- 在版本化 API 下注册认证路由 ---
func (authentication *HTTP) Register(versionedAPI *gin.RouterGroup) {
	versionedAPI.POST("/auth/login", authentication.login)                                 // 登录是成功前无需 CSRF Cookie 的同源写入口。
	versionedAPI.POST("/auth/mfa/enrollment", authentication.beginMFAEnrollment)           // challenge Cookie 换取 TOTP 注册材料。
	versionedAPI.POST("/auth/mfa/enrollment/confirm", authentication.confirmMFAEnrollment) // 有效 TOTP 后首次建立正常会话。
	versionedAPI.POST("/auth/mfa/verify", authentication.verifyMFA)                        // 已注册账号使用 TOTP 或恢复码建立会话。
	versionedAPI.POST("/auth/refresh", authentication.refresh)                             // 刷新只相信轮换 Cookie 与全局同源/CSRF 门禁。
	versionedAPI.POST("/auth/logout", authentication.logout)                               // 退出撤销当前数据库会话并清理浏览器状态。
	versionedAPI.GET("/auth/me", authentication.me)                                        // 当前账号同时验证 JWT 签名和数据库会话终态。
	versionedAPI.PUT("/auth/password", authentication.changePassword)                      // 改密原子撤销全部设备并清除当前 Cookie。
	versionedAPI.GET("/auth/sessions", authentication.listSessions)                        // 本人查看最小设备会话事实。
	versionedAPI.POST("/auth/sessions/:sessionId/revoke", authentication.revokeSession)    // 本人撤销明确目标设备。
}

// --- 为其他受保护业务模块反馈当前可信账号 ---
func (authentication *HTTP) CurrentAccount(context *gin.Context) (Account, error) {
	account, _, authenticationError := authentication.current(context) // JWT 和数据库会话仍由认证深模块共同核对。
	return account, authenticationError                                // 不向业务模块暴露访问声明或 Cookie。
}

// --- 为需要绑定当前设备的业务模块反馈账号与数据库已复核会话 ---
func (authentication *HTTP) CurrentAccountSession(context *gin.Context) (Account, string, error) {
	account, claims, authenticationError := authentication.current(context) // 与普通当前账号入口共享 JWT 和数据库终态复核。
	if authenticationError != nil {
		return Account{}, "", authenticationError
	}
	return account, claims.SessionID, nil // 只暴露不透明会话 ID，不暴露 JWT、Cookie 或刷新秘密。
}

// --- 接收逐人登录并建立安全浏览器会话 ---
func (authentication *HTTP) login(context *gin.Context) {
	input, inputError := readLoginInput(context)
	if inputError != nil { // JSON 形状或长度不符合冻结合同时，不调用密码和数据库命令。
		writeProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Login input is invalid.")
		return
	}
	if authentication.mfa != nil && authentication.mfa.requireMFA {
		challenge, beginError := authentication.mfa.BeginLogin(context.Request.Context(), input.Username, input.Password, context.GetHeader("User-Agent"))
		if beginError != nil {
			writeLoginProblem(context, beginError)
			return
		}
		setMFAChallengeCookie(context, challenge.Secret)
		code := "MFA_REQUIRED"
		if challenge.Purpose == MFAEnrollmentPurpose {
			code = "MFA_ENROLLMENT_REQUIRED"
		}
		envelope := mfaChallengeEnvelope{Meta: responseMeta{RequestID: httpx.RequestID(context)}}
		envelope.Data.Code = code
		envelope.Data.ExpiresAt = challenge.ExpiresAt
		context.JSON(http.StatusAccepted, envelope)
		return
	}

	accessTokenDraft, prepareError := authentication.tokens.Prepare() // 先取得 JTI，避免数据库提交后随机源失败留下无法交付的会话。
	if prepareError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	csrfToken, csrfError := newCSRFToken() // CSRF 随机源也必须在创建数据库会话前通过。
	if csrfError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}

	var accountSession AccountSession
	var loginError error
	if authentication.mfa != nil {
		challenge, beginError := authentication.mfa.BeginLogin(context.Request.Context(), input.Username, input.Password, context.GetHeader("User-Agent"))
		loginError = beginError
		if challenge.Session != nil {
			accountSession = *challenge.Session
		}
	} else {
		accountSession, loginError = authentication.sessions.Login(context.Request.Context(), input.Username, input.Password, context.GetHeader("User-Agent"))
	}
	if loginError != nil {
		writeLoginProblem(context, loginError) // 入口只把稳定命令分类映射为公开 HTTP 反馈。
		return
	}
	accessToken, issueError := accessTokenDraft.Issue(accountSession.Account.ID, accountSession.Credential.SessionID, accountSession.Credential.CredentialVersion)
	if issueError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}

	setSessionCookies(context, accountSession.Credential, accessToken, csrfToken) // 原始刷新秘密只进入 HttpOnly Cookie。
	context.JSON(http.StatusOK, sessionEnvelope{
		Data: sessionData{Account: accountSession.Account},
		Meta: responseMeta{RequestID: httpx.RequestID(context)},
	}) // 浏览器只收到可展示账号状态和请求身份。
}

func (authentication *HTTP) beginMFAEnrollment(context *gin.Context) {
	challengeSecret, challengeError := readMFAChallengeCookie(context)
	if challengeError != nil || authentication.mfa == nil {
		writeMFAProblem(context, ErrInvalidMFAChallenge)
		return
	}
	enrollment, enrollmentError := authentication.mfa.BeginEnrollment(context.Request.Context(), challengeSecret)
	if enrollmentError != nil {
		writeMFAProblem(context, enrollmentError)
		return
	}
	context.JSON(http.StatusOK, mfaEnrollmentEnvelope{Data: enrollment, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

func (authentication *HTTP) confirmMFAEnrollment(context *gin.Context) {
	challengeSecret, challengeError := readMFAChallengeCookie(context)
	input, inputError := readMFACodeInput(context)
	if challengeError != nil || authentication.mfa == nil {
		writeMFAProblem(context, ErrInvalidMFAChallenge)
		return
	}
	if inputError != nil {
		writeMFAProblem(context, ErrInvalidMFACode)
		return
	}
	accessTokenDraft, csrfToken, prepareError := authentication.prepareSessionDelivery()
	if prepareError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	accountSession, recoveryCodes, confirmError := authentication.mfa.ConfirmEnrollment(context.Request.Context(), challengeSecret, input.Code, context.GetHeader("User-Agent"))
	if confirmError != nil {
		writeMFAProblem(context, confirmError)
		return
	}
	accessToken, issueError := accessTokenDraft.Issue(accountSession.Account.ID, accountSession.Credential.SessionID, accountSession.Credential.CredentialVersion)
	if issueError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	setSessionCookies(context, accountSession.Credential, accessToken, csrfToken)
	clearMFAChallengeCookie(context)
	envelope := mfaConfirmationEnvelope{Meta: responseMeta{RequestID: httpx.RequestID(context)}}
	envelope.Data.Account = accountSession.Account
	envelope.Data.RecoveryCodes = recoveryCodes
	context.JSON(http.StatusOK, envelope)
}

func (authentication *HTTP) verifyMFA(context *gin.Context) {
	challengeSecret, challengeError := readMFAChallengeCookie(context)
	input, inputError := readMFACodeInput(context)
	if challengeError != nil || authentication.mfa == nil {
		writeMFAProblem(context, ErrInvalidMFAChallenge)
		return
	}
	if inputError != nil {
		writeMFAProblem(context, ErrInvalidMFACode)
		return
	}
	accessTokenDraft, csrfToken, prepareError := authentication.prepareSessionDelivery()
	if prepareError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	accountSession, verifyError := authentication.mfa.VerifyLogin(context.Request.Context(), challengeSecret, input.Code, context.GetHeader("User-Agent"))
	if verifyError != nil {
		writeMFAProblem(context, verifyError)
		return
	}
	accessToken, issueError := accessTokenDraft.Issue(accountSession.Account.ID, accountSession.Credential.SessionID, accountSession.Credential.CredentialVersion)
	if issueError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	setSessionCookies(context, accountSession.Credential, accessToken, csrfToken)
	clearMFAChallengeCookie(context)
	context.JSON(http.StatusOK, sessionEnvelope{Data: sessionData{Account: accountSession.Account}, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

func (authentication *HTTP) prepareSessionDelivery() (AccessTokenDraft, string, error) {
	draft, prepareError := authentication.tokens.Prepare()
	if prepareError != nil {
		return AccessTokenDraft{}, "", prepareError
	}
	csrfToken, csrfError := newCSRFToken()
	if csrfError != nil {
		return AccessTokenDraft{}, "", csrfError
	}
	return draft, csrfToken, nil
}

// --- 轮换刷新秘密并恢复浏览器会话 ---
func (authentication *HTTP) refresh(context *gin.Context) {
	sessionID, refreshToken, cookieError := readRefreshCookie(context) // Cookie 形状必须在进入数据库状态机前固定。
	if cookieError != nil {
		clearSessionCookies(context) // 浏览器不应持续重试已损坏的凭据。
		writeProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return
	}
	accessTokenDraft, prepareError := authentication.tokens.Prepare() // 在轮换数据库 family 前取得新 JWT 随机身份。
	if prepareError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	csrfToken, csrfError := newCSRFToken() // 新 CSRF 值同样在事务提交前准备。
	if csrfError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	accountSession, refreshError := authentication.sessions.Refresh(context.Request.Context(), sessionID, refreshToken) // 命令在一个事务中轮换并读取账号投影。
	if refreshError != nil {
		clearSessionCookies(context)               // 过期、撤销、重放和停用都移除浏览器旧状态。
		writeRefreshProblem(context, refreshError) // 只保留重放与普通失效的必要差异。
		return
	}
	accessToken, issueError := accessTokenDraft.Issue(accountSession.Account.ID, accountSession.Credential.SessionID, accountSession.Credential.CredentialVersion)
	if issueError != nil {
		clearSessionCookies(context) // 不允许只有刷新 Cookie 而没有匹配访问 JWT 的部分反馈。
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	setSessionCookies(context, accountSession.Credential, accessToken, csrfToken) // 三枚 Cookie 作为一个 HTTP 反馈共同替换。
	context.JSON(http.StatusOK, sessionEnvelope{
		Data: sessionData{Account: accountSession.Account},
		Meta: responseMeta{RequestID: httpx.RequestID(context)},
	}) // 刷新恢复与登录相同的最小账号 envelope。
}

// --- 反馈当前仍可信的逐人账号状态 ---
func (authentication *HTTP) me(context *gin.Context) {
	account, _, authenticationError := authentication.current(context) // 在反馈任何账号字段前核对 JWT 与数据库会话。
	if authenticationError != nil {
		writeCurrentProblem(context, authenticationError)
		return
	}
	context.JSON(http.StatusOK, sessionEnvelope{
		Data: sessionData{Account: account},
		Meta: responseMeta{RequestID: httpx.RequestID(context)},
	}) // GET 不轮换 Cookie，只反馈当前账号最小投影。
}

// --- 撤销当前会话并要求浏览器丢弃认证状态 ---
func (authentication *HTTP) logout(context *gin.Context) {
	_, claims, authenticationError := authentication.current(context) // 先证明 JWT 与数据库会话仍属于同一活动账号。
	if authenticationError != nil {
		writeCurrentProblem(context, authenticationError)
		return
	}
	logoutError := authentication.sessions.Logout(context.Request.Context(), claims.AccountID, claims.SessionID) // 命令用账号和会话双条件阻止越权撤销。
	if logoutError != nil {
		writeCurrentProblem(context, logoutError)
		return
	}
	clearSessionCookies(context)         // 数据库提交成功后才要求浏览器清除全部凭据。
	context.Status(http.StatusNoContent) // 退出成功只反馈 204，不返回账号或令牌正文。
}

// --- 修改本人密码并终止全部既有设备 ---
func (authentication *HTTP) changePassword(context *gin.Context) {
	account, _, authenticationError := authentication.current(context) // 在读取密码正文前证明当前逐人会话仍可信。
	if authenticationError != nil {
		writeCurrentProblem(context, authenticationError)
		return
	}
	input, inputError := readChangePasswordInput(context)
	if inputError != nil { // 非法长度、字段或正文不进入 Argon2id 命令。
		writeProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Password input is invalid.")
		return
	}
	changeError := authentication.sessions.ChangePassword(context.Request.Context(), account.ID, input.CurrentPassword, input.NewPassword)
	if changeError != nil {
		writePasswordProblem(context, changeError)
		return
	}
	clearSessionCookies(context)         // 数据库已经撤销全部设备，当前浏览器同步清除旧凭据。
	context.Status(http.StatusNoContent) // 新密码不回显；用户必须重新登录。
}

// --- 列出本人最近设备会话 ---
func (authentication *HTTP) listSessions(context *gin.Context) {
	_, claims, authenticationError := authentication.current(context) // 列表范围只来自可信访问 JWT 和数据库会话。
	if authenticationError != nil {
		writeCurrentProblem(context, authenticationError)
		return
	}
	sessions, listError := authentication.sessions.List(context.Request.Context(), claims.AccountID, claims.SessionID)
	if listError != nil {
		writeCurrentProblem(context, listError)
		return
	}
	context.JSON(http.StatusOK, sessionListEnvelope{
		Data: sessions,
		Meta: responseMeta{RequestID: httpx.RequestID(context)},
	}) // 列表不含 refresh digest、family、撤销原因或账号正文。
}

// --- 撤销本人一个明确设备会话 ---
func (authentication *HTTP) revokeSession(context *gin.Context) {
	_, claims, authenticationError := authentication.current(context) // 先锁定发起人的当前账号范围。
	if authenticationError != nil {
		writeCurrentProblem(context, authenticationError)
		return
	}
	targetSessionID := context.Param("sessionId")
	if !strings.HasPrefix(targetSessionID, "AS-") || len(targetSessionID) < 15 || len(targetSessionID) > 83 { // 无效目标形状不进入数据库查询。
		writeProblem(context, http.StatusNotFound, "NOT_FOUND", "Session was not found.")
		return
	}
	revokeError := authentication.sessions.Revoke(context.Request.Context(), claims.AccountID, targetSessionID)
	if errors.Is(revokeError, ErrSessionNotFound) { // 未知、他人和终态目标共享存在性隐藏反馈。
		writeProblem(context, http.StatusNotFound, "NOT_FOUND", "Session was not found.")
		return
	}
	if revokeError != nil {
		writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
		return
	}
	if targetSessionID == claims.SessionID {
		clearSessionCookies(context) // 撤销当前设备时同步清除本浏览器状态。
	}
	context.Status(http.StatusNoContent) // 其他设备撤销也只反馈 204。
}

// --- 验证访问 Cookie 并读取最新账号会话 ---
func (authentication *HTTP) current(context *gin.Context) (Account, AccessClaims, error) {
	rawAccessToken, cookieError := context.Cookie(accessCookieName) // 访问 JWT 只从 HttpOnly Cookie 读取。
	if cookieError != nil || rawAccessToken == "" {
		return Account{}, AccessClaims{}, ErrAuthenticationRequired
	}
	claims, verifyError := authentication.tokens.Verify(rawAccessToken) // 固定算法、用途、来源、期限和签名先通过。
	if verifyError != nil {
		return Account{}, AccessClaims{}, ErrAuthenticationRequired
	}
	account, currentError := authentication.sessions.Current(context.Request.Context(), claims.AccountID, claims.SessionID, claims.CredentialVersion) // 数据库终态使撤销与改密立即生效。
	if currentError != nil {
		return Account{}, AccessClaims{}, currentError
	}
	return account, claims, nil // 后续受保护命令可复用可信账号与会话身份。
}

// --- 严格读取一个登录 JSON 对象 ---
func readLoginInput(context *gin.Context) (loginInput, error) {
	input := loginInput{}
	if decodeError := decodeSingleJSON(context, &input); decodeError != nil { // 共用严格单对象、4 KiB 与字段白名单边界。
		return loginInput{}, decodeError
	}
	usernameLength := utf8.RuneCountInString(input.Username) // 长度按用户可见字符与 OpenAPI 对齐。
	passwordLength := utf8.RuneCountInString(input.Password)
	if !utf8.ValidString(input.Username) || !utf8.ValidString(input.Password) || usernameLength < 1 || usernameLength > 128 || passwordLength < minPasswordRunes || passwordLength > maxPasswordRunes { // 非法文本不进入 Argon2id。
		return loginInput{}, errors.New("invalid login field length")
	}
	return input, nil // 反馈只含冻结白名单字段的登录指令数据。
}

// --- 严格读取一个改密 JSON 对象 ---
func readChangePasswordInput(context *gin.Context) (changePasswordInput, error) {
	input := changePasswordInput{}
	if decodeError := decodeSingleJSON(context, &input); decodeError != nil { // 不接受额外字段、多个对象或非 JSON 媒体类型。
		return changePasswordInput{}, decodeError
	}
	currentLength := utf8.RuneCountInString(input.CurrentPassword) // 两个密码都按用户字符而不是字节计数。
	newLength := utf8.RuneCountInString(input.NewPassword)
	if !utf8.ValidString(input.CurrentPassword) || !utf8.ValidString(input.NewPassword) || currentLength < minPasswordRunes || currentLength > maxPasswordRunes || newLength < minPasswordRunes || newLength > maxPasswordRunes { // 无效文本不进入高成本验证。
		return changePasswordInput{}, ErrInvalidPasswordInput
	}
	return input, nil // 原始密码只在当前 HTTP 调用栈内传给命令。
}

// --- 解码一个严格且有上限的 JSON 对象 ---
func decodeSingleJSON(context *gin.Context, target any) error {
	return httpx.DecodeSingleJSON(context, target, 4096) // 认证字段校验继续由本模块承担。
}

// --- 将登录命令错误映射为稳定 HTTP 合同 ---
func writeLoginProblem(context *gin.Context, loginError error) {
	if errors.Is(loginError, ErrInvalidCredentials) { // 未知账号和错误密码保持不可区分。
		writeProblem(context, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Username or password is invalid.")
		return
	}
	if errors.Is(loginError, ErrAccountDisabled) { // 只有正确密码命中的停用账号得到锁定反馈。
		writeProblem(context, http.StatusLocked, "ACCOUNT_DISABLED", "This account is disabled.")
		return
	}
	writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.") // 未知数据库或随机源失败关闭。
}

// --- 将刷新命令错误映射为最小认证反馈 ---
func writeRefreshProblem(context *gin.Context, refreshError error) {
	if errors.Is(refreshError, ErrRefreshReplay) { // 明确重放需要客户端停止恢复并重新登录。
		writeProblem(context, http.StatusUnauthorized, "TOKEN_REPLAYED", "The session can no longer be refreshed.")
		return
	}
	if errors.Is(refreshError, ErrInvalidRefreshSession) || errors.Is(refreshError, ErrAccountDisabled) { // 不向客户端区分过期、撤销、停用或秘密错误。
		writeProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return
	}
	writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.") // 数据库或随机源失败保持可重试分类。
}

// --- 将访问会话错误映射为认证或依赖反馈 ---
func writeCurrentProblem(context *gin.Context, authenticationError error) {
	if errors.Is(authenticationError, ErrAuthenticationRequired) || errors.Is(authenticationError, ErrAccountDisabled) { // 外部凭据和账号终态不泄露差异。
		clearSessionCookies(context)
		writeProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return
	}
	writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.") // 数据库读取异常允许客户端稍后重试。
}

// --- 将本人改密错误映射为稳定 HTTP 合同 ---
func writePasswordProblem(context *gin.Context, changeError error) {
	if errors.Is(changeError, ErrInvalidPasswordInput) { // 新密码长度或随机 hash 输入不合规属于请求错误。
		writeProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Password input is invalid.")
		return
	}
	if errors.Is(changeError, ErrInvalidCredentials) { // 错误旧密码不改变账号或任何会话。
		writeProblem(context, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Current password is invalid.")
		return
	}
	if errors.Is(changeError, ErrAccountDisabled) || errors.Is(changeError, ErrAuthenticationRequired) { // 账号终态要求重新认证。
		clearSessionCookies(context)
		writeProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		return
	}
	writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.") // 数据库或随机源失败不泄露细节。
}

// --- 从刷新 Cookie 读取严格的会话凭据对 ---
func readRefreshCookie(context *gin.Context) (string, string, error) {
	value, cookieError := context.Cookie(refreshCookieName) // Cookie 是唯一允许的刷新秘密来源。
	if cookieError != nil || len(value) > 512 || strings.Count(value, ".") != 1 {
		return "", "", ErrInvalidRefreshSession // 缺失、过长或歧义形状都不进入 digest 计算。
	}
	sessionID, refreshToken, foundSeparator := strings.Cut(value, ".")
	if !foundSeparator || !strings.HasPrefix(sessionID, "AS-") || len(sessionID) < 15 || len(refreshToken) < 32 || len(refreshToken) > 256 { // 固定前缀与长度先过滤无效输入。
		return "", "", ErrInvalidRefreshSession
	}
	return sessionID, refreshToken, nil // 原始秘密只在本次命令调用内存在。
}

// --- 反馈冻结的 snake_case 错误 envelope ---
func writeProblem(context *gin.Context, status int, code string, message string) {
	context.AbortWithStatusJSON(status, gin.H{"error": gin.H{
		"code": code, "message": message, "request_id": httpx.RequestID(context),
	}}) // 不复制底层错误、账号、密码、Cookie 或数据库细节。
}

// --- 将一次性会话凭据收敛为浏览器 Cookie ---
func setSessionCookies(context *gin.Context, credential SessionCredential, accessToken string, csrfToken string) {
	http.SetCookie(context.Writer, &http.Cookie{
		Name: accessCookieName, Value: accessToken, Path: "/", MaxAge: int(AccessTokenLifetime.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}) // 访问 JWT 对脚本不可见且只随 HTTPS 同站请求发送。
	http.SetCookie(context.Writer, &http.Cookie{
		Name: refreshCookieName, Value: credential.SessionID + "." + credential.RefreshToken, Path: "/api/v2/auth", MaxAge: int(RefreshAbsoluteLifetime.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}) // 刷新凭据缩小到认证路径并对脚本隐藏。
	http.SetCookie(context.Writer, &http.Cookie{
		Name: httpx.CSRFTokenCookieName, Value: csrfToken, Path: "/", MaxAge: int(RefreshAbsoluteLifetime.Seconds()),
		HttpOnly: false, Secure: true, SameSite: http.SameSiteLaxMode,
	}) // CSRF 值允许同源前端读取，但 Secure/SameSite 阻止跨站获取。
}

func setMFAChallengeCookie(context *gin.Context, challengeSecret string) {
	http.SetCookie(context.Writer, &http.Cookie{
		Name: mfaChallengeCookieName, Value: challengeSecret, Path: "/api/v2/auth/mfa", MaxAge: int(MFAChallengeLifetime.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func readMFAChallengeCookie(context *gin.Context) (string, error) {
	value, cookieError := context.Cookie(mfaChallengeCookieName)
	if cookieError != nil || len(value) < 32 || len(value) > 256 {
		return "", ErrInvalidMFAChallenge
	}
	return value, nil
}

func readMFACodeInput(context *gin.Context) (mfaCodeInput, error) {
	input := mfaCodeInput{}
	if decodeError := decodeSingleJSON(context, &input); decodeError != nil || !utf8.ValidString(input.Code) || len(input.Code) < 6 || len(input.Code) > 128 {
		return mfaCodeInput{}, ErrInvalidMFACode
	}
	return input, nil
}

func clearMFAChallengeCookie(context *gin.Context) {
	http.SetCookie(context.Writer, &http.Cookie{
		Name: mfaChallengeCookieName, Value: "", Path: "/api/v2/auth/mfa", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func writeMFAProblem(context *gin.Context, mfaError error) {
	if errors.Is(mfaError, ErrInvalidMFAChallenge) {
		writeProblem(context, http.StatusUnauthorized, "MFA_CHALLENGE_INVALID", "MFA challenge is invalid or expired.")
		return
	}
	if errors.Is(mfaError, ErrInvalidMFACode) {
		writeProblem(context, http.StatusUnauthorized, "MFA_CODE_INVALID", "MFA code is invalid.")
		return
	}
	writeProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Authentication is temporarily unavailable.")
}

// --- 清除浏览器全部后台认证 Cookie ---
func clearSessionCookies(context *gin.Context) {
	http.SetCookie(context.Writer, &http.Cookie{Name: accessCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})             // 移除脚本不可见的访问 JWT。
	http.SetCookie(context.Writer, &http.Cookie{Name: refreshCookieName, Value: "", Path: "/api/v2/auth", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}) // 移除路径受限的刷新凭据。
	http.SetCookie(context.Writer, &http.Cookie{Name: httpx.CSRFTokenCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: false, Secure: true, SameSite: http.SameSiteLaxMode})   // 移除前端可读的 CSRF 双提交值。
}

// --- 生成一个不可预测的双提交 CSRF 值 ---
func newCSRFToken() (string, error) {
	randomBytes := make([]byte, csrfTokenBytes)                       // 256 位随机空间与刷新秘密强度一致。
	if _, randomError := rand.Read(randomBytes); randomError != nil { // 随机源失败时不回退到时间或请求 ID。
		return "", randomError
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil // 无 padding URL-safe 文本可直接进入 Cookie/Header。
}
