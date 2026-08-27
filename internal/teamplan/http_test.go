/* 团队计划 HTTP 装配测试：缺少命令或认证能力时不允许建立半可用入口。 */
package teamplan

import "testing" // 运行最小装配合同。

func TestNewHTTPRejectsIncompleteDependencies(t *testing.T) {
	if _, constructionError := NewHTTP(nil, nil); constructionError == nil {
		t.Fatal("incomplete team-plan HTTP dependencies were accepted")
	}
}
