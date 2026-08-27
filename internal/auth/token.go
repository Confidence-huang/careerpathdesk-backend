/*
访问令牌能力：为一个已验证账号会话签发五分钟 Ed25519 JWT，并按同一固定合同验证。
令牌只携带账号 ID、会话 ID、凭据版本和标准时间/来源声明；撤销事实仍由 PostgreSQL 会话负责。
调用示例：rawToken, issueError := tokens.Issue(accountID, sessionID, credentialVersion)。
*/
package auth

import (
	"crypto/ed25519" // 使用 EdDSA 非对称签名，验证端不持有私钥。
	"errors"         // 暴露不复制令牌或密码的固定失败分类。
	"time"           // 建立和验证精确五分钟 UTC 有效期。

	"github.com/golang-jwt/jwt/v5" // 编码并严格解析标准 JWT 声明。
)

const AccessTokenIssuer = "careerpathdesk"           // 只接受 CareerPathDesk 自己签发的访问令牌。
const AccessTokenAudience = "careerpathdesk-browser" // 令牌只供同源浏览器 API 使用。
const AccessTokenLifetime = 5 * time.Minute          // 短期窗口降低泄露后的有效时间。
const accessTokenType = "at+jwt"                     // RFC 风格显式类型，防止不同 JWT 用途混淆。

var ErrInvalidAccessTokenKeys = errors.New("access token keys are invalid")          // 标识 Ed25519 密钥或依赖缺失。
var ErrInvalidAccessTokenClaims = errors.New("access token claims are invalid")      // 标识签发输入不构成可信会话。
var ErrAccessTokenIDUnavailable = errors.New("access token identity is unavailable") // 标识 jti 随机源失败。
var ErrInvalidAccessToken = errors.New("access token is invalid")                    // 所有外部解析失败统一为不泄露原因的分类。

// AccessTokenKeys 保存签发私钥和验证公钥；调用方从受保护文件装配。
type AccessTokenKeys struct {
	Private ed25519.PrivateKey // Private 只用于签发，不能进入日志或响应。
	Public  ed25519.PublicKey  // Public 只用于验证签名。
}

// AccessClaims 是认证中间件可以消费的最小可信会话投影。
type AccessClaims struct {
	AccountID         string    // AccountID 对应 JWT subject。
	SessionID         string    // SessionID 对应数据库刷新会话和 JWT sid。
	CredentialVersion int64     // CredentialVersion 用于拒绝改密或权限变化前令牌。
	Issuer            string    // Issuer 固定为 CareerPathDesk。
	Audience          string    // Audience 固定为同源浏览器 API。
	TokenID           string    // TokenID 是本次访问令牌的 jti。
	IssuedAt          time.Time // IssuedAt 是签发 UTC 时间。
	ExpiresAt         time.Time // ExpiresAt 精确为签发后五分钟。
}

// AccessTokens 集中固定 JWT 合同和 Ed25519 密钥，避免路由自行解析令牌。
type AccessTokens struct {
	keys       AccessTokenKeys        // keys 提供唯一签发/验证边界。
	now        func() time.Time       // now 由系统 UTC 时钟注入，测试可固定。
	newTokenID func() (string, error) // newTokenID 由不透明身份生成器注入。
}

// AccessTokenDraft 保存会话提交前已经取得的随机 JTI 与可信签发时刻。
type AccessTokenDraft struct {
	tokens   *AccessTokens // tokens 提供已验证的 Ed25519 密钥和固定声明合同。
	tokenID  string        // tokenID 在数据库事务前生成，避免提交后随机源失败。
	issuedAt time.Time     // issuedAt 让准备和最终签发使用同一 UTC 时刻。
}

// tokenClaims 是 JWT 库使用的内部传输结构，不直接暴露给业务命令。
type tokenClaims struct {
	SessionID            string `json:"sid"` // sid 绑定一个可撤销数据库会话。
	CredentialVersion    int64  `json:"cv"`  // cv 绑定账号当前凭据版本。
	jwt.RegisteredClaims        // 注册声明保存 sub/iss/aud/iat/nbf/exp/jti。
}

// --- 建立固定访问令牌能力 ---
func NewAccessTokens(keys AccessTokenKeys, now func() time.Time, newTokenID func() (string, error)) (*AccessTokens, error) {
	if len(keys.Private) != ed25519.PrivateKeySize || len(keys.Public) != ed25519.PublicKeySize || now == nil || newTokenID == nil { // 缺少任一边界都不允许签发。
		return nil, ErrInvalidAccessTokenKeys
	}
	return &AccessTokens{keys: keys, now: now, newTokenID: newTokenID}, nil // 反馈只理解固定合同的签发/验证能力。
}

// --- 为一个可信账号会话签发短期访问令牌 ---
func (tokens *AccessTokens) Issue(accountID string, sessionID string, credentialVersion int64) (string, error) {
	draft, prepareError := tokens.Prepare() // 普通调用仍通过同一预留随机身份边界。
	if prepareError != nil {
		return "", prepareError
	}
	return draft.Issue(accountID, sessionID, credentialVersion) // 使用已准备的确定性签发步骤。
}

// --- 在数据库会话创建前准备令牌随机身份 ---
func (tokens *AccessTokens) Prepare() (AccessTokenDraft, error) {
	tokenID, identityError := tokens.newTokenID() // 随机源失败必须发生在任何会话写入之前。
	if identityError != nil || tokenID == "" {
		return AccessTokenDraft{}, ErrAccessTokenIDUnavailable
	}
	return AccessTokenDraft{tokens: tokens, tokenID: tokenID, issuedAt: tokens.now().UTC()}, nil // 后续签发不再读取随机源或墙钟。
}

// --- 使用已准备身份签发一个可信账号会话 ---
func (draft AccessTokenDraft) Issue(accountID string, sessionID string, credentialVersion int64) (string, error) {
	if accountID == "" || sessionID == "" || credentialVersion < 1 { // 不完整会话事实不能进入签名边界。
		return "", ErrInvalidAccessTokenClaims
	}
	if draft.tokens == nil || draft.tokenID == "" { // 非 Prepare 产生的零值草稿不能绕过随机身份门禁。
		return "", ErrAccessTokenIDUnavailable
	}
	issuedAt := draft.issuedAt.UTC()               // 使用会话提交前固定的可信 UTC 时刻。
	expiresAt := issuedAt.Add(AccessTokenLifetime) // 有效期只由固定常量决定。
	claims := tokenClaims{                         // 构造最小账号会话声明。
		SessionID:         sessionID,
		CredentialVersion: credentialVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: AccessTokenIssuer, Subject: accountID, Audience: jwt.ClaimStrings{AccessTokenAudience},
			ExpiresAt: jwt.NewNumericDate(expiresAt), NotBefore: jwt.NewNumericDate(issuedAt), IssuedAt: jwt.NewNumericDate(issuedAt), ID: draft.tokenID,
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims) // 算法固定为 EdDSA，不接受调用方选择。
	accessToken.Header["typ"] = accessTokenType                      // 显式标记用途，防止刷新/邀请令牌混用。
	rawToken, signError := accessToken.SignedString(draft.tokens.keys.Private)
	if signError != nil {
		return "", ErrInvalidAccessTokenKeys
	}
	return rawToken, nil // 只把签名后的紧凑 JWT 反馈给认证 HTTP 层。
}

// --- 按固定合同验证一个访问令牌 ---
func (tokens *AccessTokens) Verify(rawToken string) (AccessClaims, error) {
	claims := tokenClaims{} // 为本次解析建立独立声明容器。
	parsedToken, parseError := jwt.ParseWithClaims(
		rawToken,
		&claims,
		func(parsedToken *jwt.Token) (any, error) {
			if parsedToken.Method != jwt.SigningMethodEdDSA || parsedToken.Header["typ"] != accessTokenType { // 算法或用途不同即统一拒绝。
				return nil, ErrInvalidAccessToken
			}
			return tokens.keys.Public, nil // 只有固定 header 通过后才验证签名。
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(AccessTokenIssuer),
		jwt.WithAudience(AccessTokenAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(func() time.Time { return tokens.now().UTC() }),
	)
	if parseError != nil || parsedToken == nil || !parsedToken.Valid { // 所有外部失败隐藏签名、时间和声明差异。
		return AccessClaims{}, ErrInvalidAccessToken
	}
	if claims.Subject == "" || claims.SessionID == "" || claims.CredentialVersion < 1 || claims.ID == "" || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ExpiresAt == nil { // 必需会话声明缺失时拒绝。
		return AccessClaims{}, ErrInvalidAccessToken
	}
	if !claims.NotBefore.Time.Equal(claims.IssuedAt.Time) || claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) != AccessTokenLifetime { // 时间窗口必须与签发合同精确一致。
		return AccessClaims{}, ErrInvalidAccessToken
	}

	return AccessClaims{
		AccountID: claims.Subject, SessionID: claims.SessionID, CredentialVersion: claims.CredentialVersion,
		Issuer: claims.Issuer, Audience: AccessTokenAudience, TokenID: claims.ID,
		IssuedAt: claims.IssuedAt.Time.UTC(), ExpiresAt: claims.ExpiresAt.Time.UTC(),
	}, nil // 反馈认证命令所需的最小可信会话事实。
}
