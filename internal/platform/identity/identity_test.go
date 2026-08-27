/*
不透明 ID 测试：验证领域前缀、随机长度、唯一性和无效前缀拒绝。
测试只观察 ID 形状，不替换生产随机源。
*/
package identity

import (
	"regexp"
	"testing"
)

func TestNewProducesUniquePrefixedOpaqueIdentifiers(t *testing.T) {
	pattern := regexp.MustCompile(`^R-[a-f0-9]{32}$`)
	seen := make(map[string]struct{}, 100)
	for index := 0; index < 100; index++ {
		identifier, createError := New("R")
		if createError != nil || !pattern.MatchString(identifier) {
			t.Fatalf("invalid generated identifier: value=%q error=%v", identifier, createError)
		}
		if _, duplicate := seen[identifier]; duplicate {
			t.Fatal("generated duplicate identifier")
		}
		seen[identifier] = struct{}{}
	}
}

func TestNewRejectsUnregisteredPrefixShape(t *testing.T) {
	if _, createError := New("request-id"); createError == nil {
		t.Fatal("expected invalid prefix to fail")
	}
}
