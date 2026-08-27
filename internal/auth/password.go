/*
账号密码能力：生成受控 Argon2id PHC 串，并在严格资源上限内验证已有编码。
调用示例：passwordHash, hashError := auth.HashPassword(newPassword)；匹配时调用 auth.VerifyPassword(passwordHash, candidate)。
*/
package auth

import (
	"crypto/rand"     // 为每个新密码生成独立 128 位 salt。
	"crypto/sha256"   // 为确定性密码意图摘要建立域分离的公开 salt。
	"crypto/subtle"   // 恒定时间比较派生值，避免按首个不同字节提前返回。
	"encoding/base64" // 按 PHC 约定编码 salt 和派生值。
	"errors"          // 暴露不复制密码或 hash 正文的稳定失败分类。
	"fmt"             // 生成和核对固定 Argon2id 参数段。
	"strconv"         // 将已验证的十进制 PHC 参数转换为受限整数。
	"strings"         // 按 PHC 分隔符拆分受控编码。
	"unicode/utf8"    // 按用户可见字符验证 6–128 长度合同。

	"golang.org/x/crypto/argon2" // 使用 Go 官方扩展密码学实现 Argon2id。
)

const passwordMemoryKiB uint32 = 64 * 1024     // 每次正式 hash 使用 64 MiB，平衡交互延迟和离线攻击成本。
const passwordIterations uint32 = 3            // 三轮 Argon2id 计算与既有 synthetic seed 保持一致。
const passwordParallelism uint8 = 1            // 单 lane 避免 4 GiB 开发/部署主机出现并发内存峰值。
const passwordSaltBytes = 16                   // 128 位随机 salt 防止相同密码产生相同持久化值。
const passwordHashBytes uint32 = 32            // 256 位派生值满足认证存储强度。
const minPasswordRunes = 6                     // 与 OpenAPI、HTTP 和 Vue 的账号密码输入下限一致。
const maxPasswordRunes = 128                   // 限制异常输入带来的内存复制和审计风险。
const maxPasswordIntentContextBytes = 4096     // 幂等上下文只允许已验证的小型结构，不接受任意大输入。
const maxVerifiedMemoryKiB uint32 = 128 * 1024 // 解析旧 hash 时拒绝攻击者指定过量内存。
const maxVerifiedIterations uint32 = 5         // 解析旧 hash 时拒绝异常高迭代阻塞认证进程。
const maxVerifiedParallelism uint8 = 4         // 解析旧 hash 时限制并行 lane 数。

var ErrInvalidPasswordInput = errors.New("password input is invalid")                  // 标识新密码不满足长度或文本合同。
var ErrPasswordHashUnavailable = errors.New("password hash is unavailable")            // 标识系统随机源无法生成安全 salt。
var ErrInvalidPasswordIntentContext = errors.New("password intent context is invalid") // 标识幂等上下文缺失或异常。

// passwordParameters 是从 PHC 编码得到的受限 Argon2id 工作参数。
type passwordParameters struct {
	memoryKiB   uint32 // memoryKiB 控制每次验证的内存成本。
	iterations  uint32 // iterations 控制重复计算轮数。
	parallelism uint8  // parallelism 控制并行 lane 数。
	salt        []byte // salt 是每个账号密码独立的公开随机输入。
	hash        []byte // hash 是需要恒定时间比较的期望派生值。
}

// --- 为一个合格新密码生成 Argon2id PHC 串 ---
func HashPassword(password string) (string, error) {
	if !validPasswordInput(password) { // 非法文本不进入高成本计算。
		return "", ErrInvalidPasswordInput
	}

	salt := make([]byte, passwordSaltBytes)                // 为本次密码变化建立独立随机输入。
	if _, readError := rand.Read(salt); readError != nil { // 随机源失效时禁止时间戳或固定 salt 回退。
		return "", ErrPasswordHashUnavailable
	}
	hash := argon2.IDKey([]byte(password), salt, passwordIterations, passwordMemoryKiB, passwordParallelism, passwordHashBytes)                                    // 只在输入和随机源通过后执行高成本派生。
	saltText := base64.RawStdEncoding.EncodeToString(salt)                                                                                                         // PHC 字段使用无 padding 标准 Base64。
	hashText := base64.RawStdEncoding.EncodeToString(hash)                                                                                                         // 持久化派生值而不是原始密码。
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, passwordMemoryKiB, passwordIterations, passwordParallelism, saltText, hashText), nil // 返回可独立验证的固定算法编码。
}

// --- 为含密码的幂等意图生成确定性且高成本的 32 字节绑定 ---
func DerivePasswordIntentDigest(password string, context []byte) ([sha256.Size]byte, error) {
	digest := [sha256.Size]byte{}
	if !validPasswordInput(password) {
		return digest, ErrInvalidPasswordInput
	}
	if len(context) == 0 || len(context) > maxPasswordIntentContextBytes {
		return digest, ErrInvalidPasswordIntentContext
	}
	contextHasher := sha256.New()
	_, _ = contextHasher.Write([]byte("careerpathdesk-password-intent-digest-v1\x00")) // 固定域避免与普通内容摘要复用。
	_, _ = contextHasher.Write(context)
	publicSalt := contextHasher.Sum(nil)[:passwordSaltBytes] // salt 可由数据库事实重建；离线猜测仍必须承担完整 Argon2id 成本。
	derived := argon2.IDKey([]byte(password), publicSalt, passwordIterations, passwordMemoryKiB, passwordParallelism, passwordHashBytes)
	copy(digest[:], derived)
	return digest, nil
}

// --- 在资源上限内验证候选密码 ---
func VerifyPassword(passwordHash string, candidate string) bool {
	parameters, parseError := parsePasswordHash(passwordHash) // 先检查算法、版本、参数和编码尺寸再分配 Argon2 内存。
	if parseError != nil {
		return false // 损坏或危险 hash 与普通认证失败保持相同反馈。
	}
	candidateHash := argon2.IDKey([]byte(candidate), parameters.salt, parameters.iterations, parameters.memoryKiB, parameters.parallelism, uint32(len(parameters.hash))) // 用持久化安全参数派生候选值。
	return subtle.ConstantTimeCompare(candidateHash, parameters.hash) == 1                                                                                               // 只反馈匹配事实，不反馈差异位置。
}

// --- 统一验证新密码和密码意图摘要的文本边界 ---
func validPasswordInput(password string) bool {
	passwordLength := utf8.RuneCountInString(password) // 长度按用户输入字符计算，不按 UTF-8 字节误判。
	return utf8.ValidString(password) && passwordLength >= minPasswordRunes && passwordLength <= maxPasswordRunes
}

// --- 解析并限制一个 Argon2id PHC 串 ---
func parsePasswordHash(passwordHash string) (passwordParameters, error) {
	parts := strings.Split(passwordHash, "$")                                              // 标准 PHC 形状为六段且首段为空。
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" { // 其他算法、版本或额外字段全部失败关闭。
		return passwordParameters{}, ErrInvalidPasswordInput
	}

	parameterParts := strings.Split(parts[3], ",") // 参数必须严格按 m、t、p 三段出现。
	if len(parameterParts) != 3 {
		return passwordParameters{}, ErrInvalidPasswordInput
	}
	memoryValue, memoryError := parsePasswordParameter(parameterParts[0], "m=")       // 解析 KiB 内存成本。
	iterationValue, iterationError := parsePasswordParameter(parameterParts[1], "t=") // 解析迭代轮数。
	parallelValue, parallelError := parsePasswordParameter(parameterParts[2], "p=")   // 解析并行 lane 数。
	if memoryError != nil || iterationError != nil || parallelError != nil {          // 任一非十进制或错序参数都拒绝。
		return passwordParameters{}, ErrInvalidPasswordInput
	}
	if memoryValue < 8*1024 || memoryValue > uint64(maxVerifiedMemoryKiB) || iterationValue < 1 || iterationValue > uint64(maxVerifiedIterations) || parallelValue < 1 || parallelValue > uint64(maxVerifiedParallelism) { // 在调用 Argon2 前建立明确资源上限。
		return passwordParameters{}, ErrInvalidPasswordInput
	}

	salt, saltError := base64.RawStdEncoding.DecodeString(parts[4])                                                   // 解码公开 salt。
	hash, hashError := base64.RawStdEncoding.DecodeString(parts[5])                                                   // 解码期望派生值。
	if saltError != nil || hashError != nil || len(salt) < 16 || len(salt) > 64 || len(hash) < 16 || len(hash) > 64 { // 限定解码尺寸，防止畸形输入。
		return passwordParameters{}, ErrInvalidPasswordInput
	}
	return passwordParameters{
		memoryKiB: uint32(memoryValue), iterations: uint32(iterationValue), parallelism: uint8(parallelValue),
		salt: salt, hash: hash,
	}, nil // 返回已证明不会触发异常资源消耗的参数。
}

// --- 读取一个带固定名称的十进制 PHC 参数 ---
func parsePasswordParameter(parameter string, prefix string) (uint64, error) {
	if !strings.HasPrefix(parameter, prefix) || len(parameter) == len(prefix) { // 参数名错误或缺值时不交给宽松解析器猜测。
		return 0, ErrInvalidPasswordInput
	}
	value, parseError := strconv.ParseUint(strings.TrimPrefix(parameter, prefix), 10, 32) // 只接受无符号十进制 32 位范围。
	if parseError != nil {
		return 0, ErrInvalidPasswordInput
	}
	return value, nil // 具体资源上下限由完整 PHC 解析统一判断。
}
