/*
密码行为测试：证明认证层只生成可验证的 Argon2id PHC 串，并统一拒绝错误密码与损坏编码。
测试密码是公开 synthetic 字符串；测试不输出密码、salt、hash 或中间派生值。
*/
package auth

import (
	"bytes"         // 比较密码意图摘要而不输出其内容。
	"crypto/sha256" // 独立派生评审冻结的公开 salt 向量。
	"errors"        // 核对边界拒绝仍使用稳定公开分类。
	"strings"       // 只检查公开 PHC 算法前缀，不拆读 salt 或派生值。
	"testing"       // 运行 Go 标准纯密码行为测试。

	"golang.org/x/crypto/argon2" // 独立计算固定算法与成本向量，防止实现悄然降级为快速摘要。
)

// --- Argon2id hash 只接受创建时的原始密码 ---
func TestPasswordHashRoundTripRejectsWrongPassword(t *testing.T) {
	passwordHash, hashError := HashPassword("Synthetic-Password-For-Test-2026!")
	if hashError != nil {
		t.Fatalf("synthetic password hash failed: %v", hashError)
	}
	if !strings.HasPrefix(passwordHash, "$argon2id$v=19$") { // 持久化格式必须显式锁定算法和版本。
		t.Fatal("password hash is not an Argon2id PHC string")
	}
	if !VerifyPassword(passwordHash, "Synthetic-Password-For-Test-2026!") { // 正确密码必须通过公开验证入口。
		t.Fatal("correct synthetic password was rejected")
	}
	if VerifyPassword(passwordHash, "Synthetic-Wrong-Password-2026!") { // 错误密码不能与同一 hash 匹配。
		t.Fatal("wrong synthetic password was accepted")
	}
	if VerifyPassword("$argon2id$v=19$m=999999999,t=3,p=1$broken$broken", "Synthetic-Password-For-Test-2026!") { // 恶意参数必须在分配内存前失败关闭。
		t.Fatal("unsafe Argon2id parameters were accepted")
	}
}

// --- 新密码按六至一百二十八个用户字符接受精确边界 ---
func TestPasswordHashAcceptsSixToOneHundredTwentyEightRunes(t *testing.T) {
	for _, acceptedLength := range []int{6, 128} {
		passwordHash, hashError := HashPassword(strings.Repeat("合", acceptedLength))
		if hashError != nil || passwordHash == "" { // 六位和一百二十八位都必须进入现有 Argon2id 能力。
			t.Fatalf("accepted password length %d was rejected", acceptedLength)
		}
	}
	for _, rejectedLength := range []int{5, 129} {
		passwordHash, hashError := HashPassword(strings.Repeat("合", rejectedLength))
		if passwordHash != "" || !errors.Is(hashError, ErrInvalidPasswordInput) { // 边界外不得留下任何密码材料。
			t.Fatalf("rejected password length %d was accepted", rejectedLength)
		}
	}
}

// --- 密码意图摘要可重放同一请求，但密码或上下文变化都会改变结果 ---
func TestPasswordIntentDigestIsDeterministicContextBoundAndArgonCosted(t *testing.T) {
	password := "Synthetic-Intent-Password-2026!"
	context := []byte(`{"action":"account.create","username":"synthetic-intent"}`)
	first, firstError := DerivePasswordIntentDigest(password, context)
	second, secondError := DerivePasswordIntentDigest(password, context)
	wrongPassword, wrongPasswordError := DerivePasswordIntentDigest("Synthetic-Different-Password-2026!", context)
	wrongContext, wrongContextError := DerivePasswordIntentDigest(password, []byte(`{"action":"account.create","username":"different"}`))
	if firstError != nil || secondError != nil || wrongPasswordError != nil || wrongContextError != nil {
		t.Fatal("synthetic password intent digest failed")
	}
	if !bytes.Equal(first[:], second[:]) || bytes.Equal(first[:], wrongPassword[:]) || bytes.Equal(first[:], wrongContext[:]) {
		t.Fatal("password intent digest is not deterministic and intent-bound")
	}
	expectedSalt := sha256.Sum256(append([]byte("careerpathdesk-password-intent-digest-v1\x00"), context...))
	expectedArgon2id := argon2.IDKey([]byte(password), expectedSalt[:16], 3, 64*1024, 1, 32)
	if !bytes.Equal(first[:], expectedArgon2id) {
		t.Fatal("password intent digest no longer matches the reviewed Argon2id vector")
	}
	if _, shortPasswordError := DerivePasswordIntentDigest("short", context); !errors.Is(shortPasswordError, ErrInvalidPasswordInput) {
		t.Fatal("short password entered the password intent digest")
	}
	if _, invalidTextError := DerivePasswordIntentDigest(string([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa}), context); !errors.Is(invalidTextError, ErrInvalidPasswordInput) {
		t.Fatal("invalid UTF-8 entered the password intent digest")
	}
	if _, emptyContextError := DerivePasswordIntentDigest(password, nil); !errors.Is(emptyContextError, ErrInvalidPasswordIntentContext) {
		t.Fatal("empty password intent context was accepted")
	}
	if _, oversizedContextError := DerivePasswordIntentDigest(password, make([]byte, maxPasswordIntentContextBytes+1)); !errors.Is(oversizedContextError, ErrInvalidPasswordIntentContext) {
		t.Fatal("oversized password intent context was accepted")
	}
}
