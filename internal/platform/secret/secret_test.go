/*
受保护秘密文件行为测试：验证进程只接受当前用户可读写的非空本地文件。
测试使用 Go TempDir 合成文本，结束后由测试框架清理，不读取真实凭据。
调用示例：go test ./internal/platform/secret -count=1。
*/
package secret

import (
	"errors"        // 比较公开秘密文件错误分类，不依赖错误文字。
	"os"            // 在本轮临时目录创建权限明确的合成秘密文件。
	"path/filepath" // 跨 Linux 路径拼接临时文件位置。
	"testing"       // 运行 Go 标准文件边界测试。
)

// --- 组或其他用户可读的秘密文件被拒绝 ---
func TestReadRejectsBroadPermissions(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "database_password")                                     // 锁定本测试唯一临时秘密文件。
	if writeError := os.WriteFile(secretPath, []byte("synthetic-only\n"), 0o644); writeError != nil { // 故意创建权限过宽的文件。
		t.Fatalf("synthetic secret setup failed: %v", writeError)
	}
	if permissionError := os.Chmod(secretPath, 0o644); permissionError != nil { // 覆盖宿主 umask，保证测试真的观察宽权限。
		t.Fatalf("synthetic secret permission setup failed: %v", permissionError)
	}

	_, readError := Read(secretPath)                // 通过公开入口读取危险权限文件。
	if !errors.Is(readError, ErrBroadPermissions) { // 权限未知时必须失败关闭。
		t.Fatalf("expected ErrBroadPermissions, got %v", readError)
	}
}

// --- 符号链接不能成为秘密文件 ---
func TestReadRejectsSymbolicLink(t *testing.T) {
	temporaryRoot := t.TempDir()                                  // 锁定本测试唯一临时目录。
	targetPath := filepath.Join(temporaryRoot, "target_password") // 创建权限安全但不允许间接引用的目标。
	linkPath := filepath.Join(temporaryRoot, "linked_password")   // 创建调用方将尝试读取的符号链接。
	if writeError := os.WriteFile(targetPath, []byte("synthetic-only\n"), 0o600); writeError != nil {
		t.Fatalf("synthetic secret setup failed: %v", writeError)
	}
	if linkError := os.Symlink(targetPath, linkPath); linkError != nil { // 模拟路径可在检查后被替换的间接秘密来源。
		t.Fatalf("synthetic secret link setup failed: %v", linkError)
	}

	_, readError := Read(linkPath)              // 通过公开入口读取符号链接。
	if !errors.Is(readError, ErrSymbolicLink) { // 间接路径必须被稳定拒绝。
		t.Fatalf("expected ErrSymbolicLink, got %v", readError)
	}
}
