/*
访问令牌密钥加载测试：证明受保护 PKCS#8 PEM 文件能装配成真实 Ed25519 签发与验证能力。
测试密钥只存在于 Go 临时目录，测试结束自动清理，不读取运行环境或仓库秘密。
*/
package auth

import (
	"crypto/ed25519" // 生成本测试独享的 Ed25519 密钥对。
	"crypto/rand"    // 为合成密钥生成提供操作系统随机源。
	"crypto/x509"    // 把测试私钥编码为运行入口接受的 PKCS#8 格式。
	"encoding/pem"   // 构造标准 PRIVATE KEY PEM 文件。
	"os"             // 写入权限明确的临时密钥文件。
	"path/filepath"  // 在测试临时目录下建立稳定文件路径。
	"testing"        // 运行 Go 标准行为测试。
	"time"           // 固定签发与验证使用的 UTC 时间。
)

// --- 受保护 PKCS#8 私钥能够签发并验证访问令牌 ---
func TestLoadAccessTokenKeysFromProtectedPKCS8File(t *testing.T) {
	_, privateKey, generateError := ed25519.GenerateKey(rand.Reader) // 本测试不共享任何运行密钥。
	if generateError != nil {
		t.Fatal("synthetic Ed25519 key unavailable")
	}
	privateKeyBytes, marshalError := x509.MarshalPKCS8PrivateKey(privateKey) // 使用通用 PKCS#8，避免绑定 OpenSSL 私有格式。
	if marshalError != nil {
		t.Fatal("synthetic private key encoding failed")
	}
	privateKeyPath := filepath.Join(t.TempDir(), "access_token_private_key.pem") // 路径只属于本测试临时目录。
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	if writeError := os.WriteFile(privateKeyPath, privateKeyPEM, 0o600); writeError != nil { // 私钥只允许当前用户读写。
		t.Fatal("synthetic private key setup failed")
	}

	keys, loadError := LoadAccessTokenKeys(privateKeyPath) // 通过运行入口将文件变成认证密钥能力。
	if loadError != nil {
		t.Fatalf("protected private key failed to load: %v", loadError)
	}
	fixedNow := time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC)
	tokens, tokenError := NewAccessTokens(keys, func() time.Time { return fixedNow }, func() (string, error) { return "JTI-synthetickey01", nil })
	if tokenError != nil {
		t.Fatalf("loaded keys failed to initialize tokens: %v", tokenError)
	}
	rawToken, issueError := tokens.Issue("A-syntheticowner01", "AS-syntheticsession01", 1)
	if issueError != nil {
		t.Fatalf("loaded keys failed to sign: %v", issueError)
	}
	claims, verifyError := tokens.Verify(rawToken)
	if verifyError != nil || claims.AccountID != "A-syntheticowner01" { // 同一私钥派生的公钥必须验证完整固定合同。
		t.Fatal("loaded keys failed to verify their signed token")
	}
}
