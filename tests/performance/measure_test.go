/*
CareerPathDesk 性能测量：在固定 synthetic 规模上预热并采集公开命令的最近秩 p95。
测量使用真实 pgx 事务、范围复核、投影扫描和反馈编码；实现不启动 HTTP 或前端监听器。
调用示例：measurements := measureSyntheticQueries(t, load)。
*/
package performance

import (
	"context"       // 为每个真实 PostgreSQL 命令提供独立取消边界。
	"crypto/sha256" // 为 synthetic 关注事项生成不含正文的唯一证据摘要。
	"encoding/json" // 把组合工作台结果编码成与 HTTP 相同的反馈成本。
	"errors"        // 用固定内部错误拒绝数量或投影漂移。
	"fmt"           // 生成固定宽度的审计和关注事项身份。
	"sort"          // 由完整样本序列计算最近秩 p95。
	"testing"       // 把装载、测量与随机 schema 清理绑定到一次验收。
	"time"          // 采集单调时钟时延并表达规格阈值。

	"github.com/jackc/pgx/v5" // 批量写入现实查询需要的审计和关注事实。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"       // 构造只含 synthetic 身份的当前账号投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/followups"  // 穿过完整跟进历史公开命令。
	"github.com/confidence-huang/careerpathdesk-backend/internal/operations" // 穿过审计游标和同定义统计公开命令。
	"github.com/confidence-huang/careerpathdesk-backend/internal/students"   // 穿过学生分页和协作范围公开命令。
)

const (
	performanceWarmupCount = 5  // 五次预热排除首次连接、编译和缓存建立成本。
	performanceSampleCount = 40 // 四十个正式样本让最近秩 p95 丢弃最慢两次抖动。
	maximumSampleDuration  = 5 * time.Second
)

var errUnexpectedSyntheticResult = errors.New("synthetic performance result is invalid") // 固定错误不复制数据库行或正文。

// performanceMeasurement 是报告允许公开的一类非敏感 p95 事实。
type performanceMeasurement struct {
	Name    string        // Name 是固定交互类别，不包含对象身份。
	Samples int           // Samples 不含预热次数。
	P95     time.Duration // P95 使用最近秩算法从本轮样本得到。
	Target  time.Duration // Target 来自 plan.md 的 500ms 或 2s。
}

type performanceProbe struct {
	name   string                      // name 固定报告类别。
	target time.Duration               // target 是该类别的规格阈值。
	run    func(context.Context) error // run 只穿过公开命令并核对最小结果形状。
}

type performanceCommands struct {
	students   *students.Commands   // students 拥有列表游标和对象范围 SQL。
	followUps  *followups.Commands  // followUps 返回一个学生的二百条联系历史。
	operations *operations.Commands // operations 拥有审计和统计查询。
}

// --- 装配查询事实、公开命令和固定测量类别 ---
func measureSyntheticQueries(test *testing.T, load *syntheticLoad) []performanceMeasurement {
	test.Helper()
	copySyntheticQueryFacts(test, load.database)            // 历史规模之外补足审计和关注统计事实。
	analyzeSyntheticScale(test, load.database)              // 让 PostgreSQL 基于完整规模选择真实稳定执行计划。
	commands := newPerformanceCommands(test, load.database) // 所有测量都跨越生产公开命令 seam。
	owner, staff := syntheticPerformanceActors()            // 老板和第一名员工均由命令动态回查数据库。
	studentID := syntheticStudentID(1)                      // 第一名学生恰好属于第一名员工。
	probes := syntheticPerformanceProbes(commands, owner, staff, studentID)

	measurements := make([]performanceMeasurement, 0, len(probes)) // 固定顺序让报告跨运行易比较。
	for _, probe := range probes {
		p95 := measureProbeP95(test, probe) // 每一类别先预热，再独立采集四十次。
		measurements = append(measurements, performanceMeasurement{Name: probe.name, Samples: performanceSampleCount, P95: p95, Target: probe.target})
	}
	return measurements // 只返回类别、样本数、p95 和阈值。
}

// --- 为列表和统计建立最小现实子资源 ---
func copySyntheticQueryFacts(test *testing.T, database *pgx.Conn) {
	test.Helper()
	copySyntheticAttention(test, database) // 每十名学生一个开放关注事项。
	copySyntheticAudit(test, database)     // 每条学生历史对应一个最小审计事实。
}

// --- 每十名学生建立一个最小开放关注事项 ---
func copySyntheticAttention(test *testing.T, database *pgx.Conn) {
	test.Helper()
	attentionCount := syntheticStudentCount / 10 // 三十项足以让团队统计执行非空关联。
	_, copyError := database.CopyFrom(
		context.Background(),
		pgx.Identifier{"student_attention_cases"},
		[]string{"id", "student_id", "rule_code", "trigger_codes", "evidence", "evidence_fingerprint", "first_triggered_at", "last_triggered_at", "status"},
		pgx.CopyFromSlice(attentionCount, func(row int) ([]any, error) {
			studentNumber := row*10 + 1                                 // 关注事项均匀覆盖全部员工范围。
			attentionID := fmt.Sprintf("AC-performancecase%06d", row+1) // ID 不携带学生姓名或正文。
			fingerprint := sha256.Sum256([]byte(attentionID))           // 唯一摘要满足数据库去重约束。
			triggeredAt := syntheticPerformanceTime.Add(time.Duration(row) * time.Minute)
			evidence := fmt.Sprintf(`[{"kind":"follow_up","id":"%s"}]`, syntheticFollowUpID(studentNumber, 1))
			return []any{attentionID, syntheticStudentID(studentNumber), "no_contact_72h", []string{"no_contact_72h"}, evidence, fingerprint[:], triggeredAt, triggeredAt, "open"}, nil
		}),
	)
	if copyError != nil {
		test.Fatal("synthetic performance attention load failed")
	}
}

// --- 每条历史对应一个最小审计事实 ---
func copySyntheticAudit(test *testing.T, database *pgx.Conn) {
	test.Helper()
	totalAuditEvents := syntheticStudentCount * syntheticHistoryFactsPerStudent
	_, copyError := database.CopyFrom(
		context.Background(),
		pgx.Identifier{"audit_events"},
		[]string{"id", "actor_kind", "actor_id", "action", "object_type", "object_id", "outcome", "request_id", "metadata", "occurred_at"},
		pgx.CopyFromSlice(totalAuditEvents, func(row int) ([]any, error) {
			studentNumber := row/syntheticHistoryFactsPerStudent + 1 // 每名学生对应二百条审计排序事实。
			historyNumber := row%syntheticHistoryFactsPerStudent + 1 // 全部是连续跟进历史。
			staffNumber := (studentNumber-1)%syntheticStaffCount + 1 // 主体是当前 synthetic 负责人账号。
			action, objectType, objectID := "follow_up.created", "follow_up", syntheticFollowUpID(studentNumber, historyNumber)
			occurredAt := syntheticPerformanceTime.Add(time.Duration(row) * time.Microsecond)
			return []any{fmt.Sprintf("AU-performance%012d", row+1), "account", syntheticAccountID(staffNumber), action, objectType, objectID, "success", fmt.Sprintf("R-performance%012d", row+1), "{}", occurredAt}, nil
		}),
	)
	if copyError != nil {
		test.Fatal("synthetic performance audit load failed")
	}
}

// --- 刷新完整规模的 PostgreSQL 统计信息 ---
func analyzeSyntheticScale(test *testing.T, database *pgx.Conn) {
	test.Helper()
	_, analyzeError := database.Exec(context.Background(), `
		ANALYZE staff_profiles, accounts, students, follow_up_records,
			student_staff_assignments, student_attention_cases, audit_events`)
	if analyzeError != nil {
		test.Fatal("synthetic performance analyze failed")
	}
}

// --- 装配生产公开命令，不暴露内部 store ---
func newPerformanceCommands(test *testing.T, database *pgx.Conn) performanceCommands {
	test.Helper()
	clock := func() time.Time { return syntheticPerformanceTime } // 列表不写时间，但构造器仍要求完整依赖。
	identity := func(prefix string) (string, error) { return prefix + "-performanceidentity01", nil }
	studentCommands, studentError := students.NewCommands(database, clock, identity)
	followUpCommands, followUpError := followups.NewCommands(database, clock, identity)
	operationCommands, operationError := operations.NewCommands(database, clock)
	if studentError != nil || followUpError != nil || operationError != nil {
		test.Fatal("synthetic performance commands unavailable")
	}
	return performanceCommands{students: studentCommands, followUps: followUpCommands, operations: operationCommands}
}

// --- 建立命令会动态重验的老板和员工投影 ---
func syntheticPerformanceActors() (auth.Account, auth.Account) {
	staffProfileID := syntheticStaffID(1) // 第一名员工精确负责学生 1、21、41 等十五人。
	owner := auth.Account{ID: "A-performanceowner01", Role: "owner", State: "active", CredentialVersion: 1}
	staff := auth.Account{ID: syntheticAccountID(1), Role: "staff", State: "active", StaffProfileID: &staffProfileID, CredentialVersion: 1}
	return owner, staff
}

// --- 定义六类列表和两个交互的真实工作 ---
func syntheticPerformanceProbes(commands performanceCommands, owner auth.Account, staff auth.Account, studentID string) []performanceProbe {
	return []performanceProbe{
		{name: "owner_student_page", target: 500 * time.Millisecond, run: studentPageProbe(commands.students, owner, 30, true)},
		{name: "staff_student_page", target: 500 * time.Millisecond, run: studentPageProbe(commands.students, staff, 15, false)},
		{name: "student_follow_up_history", target: 500 * time.Millisecond, run: followUpHistoryProbe(commands.followUps, staff, studentID)},
		{name: "owner_audit_page", target: 500 * time.Millisecond, run: auditPageProbe(commands.operations, owner)},
		{name: "owner_statistics_overview", target: 2 * time.Second, run: statisticsProbe(commands.operations, owner)},
		{name: "staff_workspace_interaction", target: 2 * time.Second, run: workspaceProbe(commands, staff, studentID)},
	}
}

// --- 核对一页老板或员工学生结果 ---
func studentPageProbe(commands *students.Commands, actor auth.Account, expectedCount int, expectsCursor bool) func(context.Context) error {
	return func(ctx context.Context) error {
		page, listError := commands.List(ctx, actor, 30, "")
		if listError != nil || len(page.Students) != expectedCount || (page.NextCursor != nil) != expectsCursor {
			return errUnexpectedSyntheticResult
		}
		return nil
	}
}

// --- 核对一个学生的二百条跟进历史 ---
func followUpHistoryProbe(commands *followups.Commands, actor auth.Account, studentID string) func(context.Context) error {
	return func(ctx context.Context) error {
		items, listError := commands.List(ctx, actor, studentID)
		if listError != nil || len(items) != syntheticFollowUpsPerStudent {
			return errUnexpectedSyntheticResult
		}
		return nil
	}
}

// --- 核对六万行审计上的首批稳定游标 ---
func auditPageProbe(commands *operations.Commands, owner auth.Account) func(context.Context) error {
	return func(ctx context.Context) error {
		page, listError := commands.ListAuditEvents(ctx, owner, operations.AuditQuery{Limit: 30})
		if listError != nil || len(page.Events) != 30 || page.NextCursor == nil {
			return errUnexpectedSyntheticResult
		}
		return nil
	}
}

// --- 核对团队统计使用完整非空规模 ---
func statisticsProbe(commands *operations.Commands, owner auth.Account) func(context.Context) error {
	return func(ctx context.Context) error {
		statistics, overviewError := commands.Overview(ctx, owner)
		if overviewError != nil || statistics.Scope != "team" || statistics.InServiceStudents != 300 || statistics.OverdueFollowUps != 7_500 || statistics.OpenAttentionCases != 30 {
			return errUnexpectedSyntheticResult
		}
		return nil
	}
}

// --- 模拟员工打开学生工作台并形成完整反馈 ---
func workspaceProbe(commands performanceCommands, staff auth.Account, studentID string) func(context.Context) error {
	return func(ctx context.Context) error {
		studentsPage, studentError := commands.students.List(ctx, staff, 30, "")
		followUps, followUpError := commands.followUps.List(ctx, staff, studentID)
		if studentError != nil || followUpError != nil || len(studentsPage.Students) != 15 || len(followUps) != syntheticFollowUpsPerStudent {
			return errUnexpectedSyntheticResult
		}
		_, encodeError := json.Marshal(struct {
			Students  []students.Student   `json:"students"`
			FollowUps []followups.FollowUp `json:"follow_ups"`
		}{studentsPage.Students, followUps})
		return encodeError // 编码成本属于“完整结果”，内容从不写日志或报告。
	}
}

// --- 预热后采集四十个正式样本并计算最近秩 p95 ---
func measureProbeP95(test *testing.T, probe performanceProbe) time.Duration {
	test.Helper()
	for warmup := 0; warmup < performanceWarmupCount; warmup++ {
		if runError := runPerformanceSample(probe.run); runError != nil {
			test.Fatalf("synthetic performance warmup failed for %s", probe.name)
		}
	}

	durations := make([]time.Duration, performanceSampleCount) // 仅正式样本进入 p95。
	for sample := range durations {
		startedAt := time.Now() // 单调时钟不受墙钟调整影响。
		if runError := runPerformanceSample(probe.run); runError != nil {
			test.Fatalf("synthetic performance sample failed for %s", probe.name)
		}
		durations[sample] = time.Since(startedAt) // 保存完整命令和反馈形成时延。
	}
	sort.Slice(durations, func(left int, right int) bool { return durations[left] < durations[right] })
	p95Index := (95*len(durations)+99)/100 - 1 // 最近秩 ceil(0.95*N) 转换为零基索引。
	return durations[p95Index]
}

// --- 给每个样本独立的最长执行期限 ---
func runPerformanceSample(run func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), maximumSampleDuration)
	defer cancel() // 不让某次异常查询的计时上下文泄漏到下一样本。
	return run(ctx)
}

// --- 将纳秒时延转换为报告用三位毫秒 ---
func durationMilliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
