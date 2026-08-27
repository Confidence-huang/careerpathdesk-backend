/*
不透明身份生成器：以已注册领域前缀和 128 位系统随机数创建不可推测 ID。
生成器不接受姓名、邮箱、时间戳或数据库序号，因此 ID 不承载业务内容。
*/
package identity

import (
	"crypto/rand"  // 使用操作系统密码学随机源生成不可预测字节。
	"encoding/hex" // 用固定小写十六进制形成数据库和 URL 安全文本。
	"errors"       // 暴露不包含输入内容的固定失败分类。
	"regexp"       // 限定领域前缀形状，避免任意正文进入 ID。
)

var ErrInvalidPrefix = errors.New("identity prefix is invalid") // 标识调用方使用了未注册形状。
var validPrefix = regexp.MustCompile(`^[A-Z]{1,3}$`)            // 支持 R、A、AS、CT 等短领域前缀。

// --- 创建一个具有领域前缀的不透明身份 ---
func New(prefix string) (string, error) {
	if !validPrefix.MatchString(prefix) { // 前缀必须由调用点固定，不能承载用户输入。
		return "", ErrInvalidPrefix
	}
	randomBytes := make([]byte, 16)                               // 128 位随机空间满足本系统碰撞和不可预测边界。
	if _, readError := rand.Read(randomBytes); readError != nil { // 随机源未知时不回退到时间或计数器。
		return "", readError
	}
	return prefix + "-" + hex.EncodeToString(randomBytes), nil // 反馈固定 32 位随机正文。
}
