/*
访问令牌合同测试：从公开签发/验证入口冻结 EdDSA、at+jwt、issuer、audience 和五分钟期限。
测试使用临时 Ed25519 密钥、固定 UTC 时钟和合成账号/会话，不读取数据库或运行秘密。
*/
package auth

import (
	"crypto/ed25519"  // 生成本测试独立的 Ed25519 签名密钥。
	"crypto/rand"     // 为临时密钥提供系统随机源。
	"encoding/base64" // 解码公开 JWT header 以验证传输合同。
	"encoding/json"   // 将公开 JWT header 解析成固定字段。
	"errors"          // 比较统一无泄露的令牌拒绝分类。
	"strings"         // 分离 JWT 的三个公开传输段。
	"testing"         // 运行 Go 标准行为测试。
	"time"            // 固定签发时刻并核对精确期限。
)

// --- 访问令牌往返保持固定安全合同 ---
func TestAccessTokenRoundTripUsesFixedContract(t *testing.T) {
	publicKey, privateKey, keyError := ed25519.GenerateKey(rand.Reader) // 每次测试使用独立签名边界。
	if keyError != nil {
		t.Fatal("test signing key unavailable")
	}
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) // 固定时钟使期限断言不依赖机器时间。
	tokens, createError := NewAccessTokens(AccessTokenKeys{Private: privateKey, Public: publicKey}, func() time.Time { return now }, func() (string, error) {
		return "J-synthetictoken01", nil // 固定合成 jti 只用于本次可观察合同。
	})
	if createError != nil {
		t.Fatalf("access token capability failed: %v", createError)
	}

	rawToken, issueError := tokens.Issue("A-syntheticowner01", "AS-syntheticsession01", 1) // 通过公开入口签发一个合成会话令牌。
	if issueError != nil {
		t.Fatalf("access token issue failed: %v", issueError)
	}
	claims, verifyError := tokens.Verify(rawToken) // 通过同一公开安全合同验证传输结果。
	if verifyError != nil {
		t.Fatalf("access token verify failed: %v", verifyError)
	}
	if claims.AccountID != "A-syntheticowner01" || claims.SessionID != "AS-syntheticsession01" || claims.CredentialVersion != 1 {
		t.Fatalf("unexpected access claims: %+v", claims)
	}
	if claims.Issuer != AccessTokenIssuer || claims.Audience != AccessTokenAudience || claims.ExpiresAt.Sub(claims.IssuedAt) != AccessTokenLifetime {
		t.Fatalf("unexpected access token contract: %+v", claims)
	}

	header := decodeTokenHeader(t, rawToken) // 独立观察 JWT 公开 header，不读取实现状态。
	if header["alg"] != "EdDSA" || header["typ"] != "at+jwt" {
		t.Fatalf("unexpected JWT header: %+v", header)
	}
}

// --- 修改已签名 claims 后统一拒绝访问令牌 ---
func TestAccessTokenRejectsTamperedClaims(t *testing.T) {
	publicKey, privateKey, keyError := ed25519.GenerateKey(rand.Reader) // 本测试使用独立 Ed25519 密钥。
	if keyError != nil {
		t.Fatal("test signing key unavailable")
	}
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) // 固定时钟避免过期判断掩盖签名失败。
	tokens, createError := NewAccessTokens(AccessTokenKeys{Private: privateKey, Public: publicKey}, func() time.Time { return now }, func() (string, error) {
		return "J-synthetictoken02", nil
	})
	if createError != nil {
		t.Fatalf("access token capability failed: %v", createError)
	}
	rawToken, issueError := tokens.Issue("A-syntheticowner01", "AS-syntheticsession01", 1)
	if issueError != nil {
		t.Fatalf("access token issue failed: %v", issueError)
	}

	tamperedToken := tamperTokenSubject(t, rawToken) // 只改变公开 payload，故意保留原签名。
	_, verifyError := tokens.Verify(tamperedToken)
	if !errors.Is(verifyError, ErrInvalidAccessToken) { // 不向调用方区分签名、声明或格式细节。
		t.Fatalf("expected ErrInvalidAccessToken, got %v", verifyError)
	}
}

// --- 解码公开 JWT header ---
func decodeTokenHeader(t *testing.T, rawToken string) map[string]string {
	t.Helper()                            // 让格式失败指向调用合同测试。
	parts := strings.Split(rawToken, ".") // JWT 必须由 header、claims 和 signature 三段组成。
	if len(parts) != 3 {
		t.Fatal("access token does not have three segments")
	}
	headerBytes, decodeError := base64.RawURLEncoding.DecodeString(parts[0]) // header 使用无 padding URL Base64。
	if decodeError != nil {
		t.Fatal("access token header is not valid base64url")
	}
	header := map[string]string{} // 只接收本测试关心的公开 alg/typ 字符串。
	if parseError := json.Unmarshal(headerBytes, &header); parseError != nil {
		t.Fatal("access token header is not valid JSON")
	}
	return header // 反馈公开传输 header 给合同断言。
}

// --- 修改 JWT subject 但保留原 signature ---
func tamperTokenSubject(t *testing.T, rawToken string) string {
	t.Helper()                            // 让无效测试装配指向调用合同。
	parts := strings.Split(rawToken, ".") // 保留 header 与 signature，只修改 payload。
	if len(parts) != 3 {
		t.Fatal("access token does not have three segments")
	}
	payloadBytes, decodeError := base64.RawURLEncoding.DecodeString(parts[1]) // 解码公开 claims 段。
	if decodeError != nil {
		t.Fatal("access token payload is not valid base64url")
	}
	payload := map[string]any{} // 只修改 subject，不依赖内部 claims 类型。
	if parseError := json.Unmarshal(payloadBytes, &payload); parseError != nil {
		t.Fatal("access token payload is not valid JSON")
	}
	payload["sub"] = "A-syntheticattacker01" // 模拟令牌持有者篡改账号身份。
	tamperedBytes, encodeError := json.Marshal(payload)
	if encodeError != nil {
		t.Fatal("tampered access token payload could not be encoded")
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedBytes) // 重新编码 payload 但不重签名。
	return strings.Join(parts, ".")                                // 反馈必然签名不匹配的外部输入。
}
