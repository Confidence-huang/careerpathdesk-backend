/*
CareerPathDesk p95 合同：在精确 20/300/200 synthetic 规模上测量公开业务命令。
列表使用 500ms 服务端目标，统计和组合工作台使用 2s 交互目标；输出只有类别、样本和时延。
调用示例：go test ./tests/performance -run '^TestSyntheticQueriesMeetP95Targets$' -count=1 -v。
*/
package performance

import (
	"testing" // 运行一次无并行资源竞争的本地 PostgreSQL p95 验收。
	"time"    // 表达规格冻结的 500ms 与 2s 阈值。
)

// --- 证明真实公开查询在目标规模内满足 p95 ---
func TestSyntheticQueriesMeetP95Targets(t *testing.T) {
	load := openSyntheticScale(t)                    // 每次测量拥有独立、自动清理的完整 synthetic schema。
	measurements := measureSyntheticQueries(t, load) // 未来测量入口隐藏预热、样本排序和命令装配。

	expectedTargets := map[string]time.Duration{ // 六类列表与两个组合交互共同覆盖日常工作面。
		"owner_student_page":          500 * time.Millisecond,
		"staff_student_page":          500 * time.Millisecond,
		"student_follow_up_history":   500 * time.Millisecond,
		"owner_audit_page":            500 * time.Millisecond,
		"owner_statistics_overview":   2 * time.Second,
		"staff_workspace_interaction": 2 * time.Second,
	}
	if len(measurements) != len(expectedTargets) { // 缺少任何类别都不能用其余快速查询冒充完整验收。
		t.Fatalf("synthetic performance measurement set is incomplete: got=%d want=%d", len(measurements), len(expectedTargets))
	}

	for _, measurement := range measurements { // 逐类核对固定阈值并输出不含数据库行的证据。
		expectedTarget, known := expectedTargets[measurement.Name]
		if !known || measurement.Target != expectedTarget || measurement.Samples != performanceSampleCount {
			t.Fatalf("synthetic performance measurement contract drifted for %q", measurement.Name)
		}
		if measurement.P95 <= 0 || measurement.P95 > measurement.Target {
			t.Fatalf("synthetic performance target missed: category=%s samples=%d p95_ms=%.3f target_ms=%d", measurement.Name, measurement.Samples, durationMilliseconds(measurement.P95), measurement.Target.Milliseconds())
		}
		t.Logf("PERFORMANCE category=%s samples=%d p95_ms=%.3f target_ms=%d status=PASS", measurement.Name, measurement.Samples, durationMilliseconds(measurement.P95), measurement.Target.Milliseconds())
	}
}
