/*
CareerPathDesk 性能规模合同：只通过自动清理的 synthetic PostgreSQL 随机 schema 验证固定负载。
测试不读取业务行内容，只核对 20 名员工、300 名学生和每人 200 条历史的非敏感计数。
调用示例：go test ./tests/performance -run '^TestSyntheticScaleHasExactFacts$' -count=1。
*/
package performance

import (
	"context" // 为规模计数提供可取消的 PostgreSQL 查询期限。
	"testing" // 把随机 schema 的创建和精确清理绑定到本测试。
)

// --- 精确冻结 SC-003 的 synthetic 规模 ---
func TestSyntheticScaleHasExactFacts(t *testing.T) {
	load := openSyntheticScale(t)                               // 通过未来负载入口建立本测试独有的完整规模。
	counts, countError := load.readCounts(context.Background()) // 只读取四个聚合计数，不读取学生或历史正文。
	if countError != nil {                                      // 数据库夹具错误不能伪装成性能 RED。
		t.Fatalf("synthetic performance counts unavailable: %v", countError)
	}

	expected := syntheticCounts{ // 200 条历史全部是连续跟进记录。
		StaffProfiles:       20,
		Students:            300,
		FollowUps:           60_000,
		StudentHistoryFacts: 60_000,
	}
	if counts != expected { // 任何少装、多装或分类漂移都拒绝进入计时阶段。
		t.Fatalf("synthetic performance scale drifted: got=%+v want=%+v", counts, expected)
	}
}
