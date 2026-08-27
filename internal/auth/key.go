/*
访问令牌密钥入口：从权限受限的 PKCS#8 PEM 文件读取 Ed25519 私钥，并在内存中派生验证公钥。
本模块不生成临时运行密钥、不接受环境变量中的密钥正文，也不向错误或日志复制文件内容。
调用示例：keys, loadError := auth.LoadAccessTokenKeys(configuration.AccessTokenPrivateKeyFile)。
*/
package auth

import (
	"crypto/ed25519" // 核对私钥算法并派生对应验证公钥。
	"crypto/x509"    // 解析明确的 PKCS#8 私钥容器。
	"encoding/pem"   // 解码标准 PRIVATE KEY PEM 文本。
	"errors"         // 暴露不包含路径或密钥内容的稳定失败分类。
	"strings"        // 拒绝 PEM 块之后的额外非空内容。

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/secret" // 复用 0600、非符号链接的本地秘密门禁。
)

var ErrAccessTokenKeyUnavailable = errors.New("access token key unavailable") // 标识文件身份、格式或算法不符合运行合同。

// --- 从受保护文件装配 Ed25519 签发和验证密钥 ---
func LoadAccessTokenKeys(privateKeyFile string) (AccessTokenKeys, error) {
	privateKeyText, readError := secret.Read(privateKeyFile) // 文件权限通过后才把 PEM 读入进程内存。
	if readError != nil || privateKeyText == "" {
		return AccessTokenKeys{}, ErrAccessTokenKeyUnavailable // 缺失、宽权限、链接和空文件共享安全失败分类。
	}
	pemBlock, remainingText := pem.Decode([]byte(privateKeyText))
	if pemBlock == nil || pemBlock.Type != "PRIVATE KEY" || strings.TrimSpace(string(remainingText)) != "" { // 只接受一个通用私钥块。
		return AccessTokenKeys{}, ErrAccessTokenKeyUnavailable
	}
	parsedKey, parseError := x509.ParsePKCS8PrivateKey(pemBlock.Bytes) // PKCS#8 显式携带算法身份，避免误收其他 key 格式。
	if parseError != nil {
		return AccessTokenKeys{}, ErrAccessTokenKeyUnavailable
	}
	privateKey, isEd25519 := parsedKey.(ed25519.PrivateKey)
	if !isEd25519 || len(privateKey) != ed25519.PrivateKeySize { // RSA、ECDSA 或损坏尺寸不能进入 EdDSA 签发器。
		return AccessTokenKeys{}, ErrAccessTokenKeyUnavailable
	}
	publicKey, publicKeyOK := privateKey.Public().(ed25519.PublicKey)
	if !publicKeyOK || len(publicKey) != ed25519.PublicKeySize { // 派生失败时不允许调用方猜测验证材料。
		return AccessTokenKeys{}, ErrAccessTokenKeyUnavailable
	}

	return AccessTokenKeys{
		Private: append(ed25519.PrivateKey(nil), privateKey...),
		Public:  append(ed25519.PublicKey(nil), publicKey...),
	}, nil // 返回独立内存副本，后续签发和验证不依赖 PEM 缓冲区。
}
