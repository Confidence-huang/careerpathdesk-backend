/*
受保护秘密读取器：只从权限收紧的普通本地文件读取一段非空文本。
调用方得到内存字符串；文件路径和内容都不应进入普通日志或错误响应。
调用示例：password, readError := secret.Read(configuration.DatabasePasswordFile)。
*/
package secret

import (
	"errors"  // 暴露可稳定比较的秘密边界错误分类。
	"os"      // 核对文件身份、权限并读取本地内容。
	"strings" // 去除文件末尾换行，不改变秘密内部字符。
)

var ErrBroadPermissions = errors.New("secret file permissions are too broad") // 标识组或其他用户能够读取秘密。
var ErrSymbolicLink = errors.New("secret file must not be a symbolic link")   // 标识秘密路径不是直接受控文件。

// --- 读取权限受限的秘密文本 ---
func Read(path string) (string, error) {
	fileInfo, statError := os.Lstat(path) // 在跟随路径前核对目标本身的文件身份与权限。
	if statError != nil {                 // 缺失或不可读时不提供默认秘密。
		return "", statError
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 { // 间接路径可能在检查后改变目标，必须拒绝。
		return "", ErrSymbolicLink
	}
	if fileInfo.Mode().Perm()&0o077 != 0 { // 组或其他用户拥有任何权限都拒绝继续。
		return "", ErrBroadPermissions
	}

	secretBytes, readError := os.ReadFile(path) // 只在权限门禁通过后读取本地内容。
	if readError != nil {                       // 读取异常不回退到环境变量或空值。
		return "", readError
	}
	return strings.TrimSpace(string(secretBytes)), nil // 反馈去除文件换行后的内存秘密。
}
