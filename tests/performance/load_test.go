/*
CareerPathDesk synthetic 性能负载：在迁移后的随机 schema 内建立精确规模并由 testing 自动清理。
负载只含可辨认的 synthetic 身份，联系方式与跟进正文均为空；CopyFrom 隐藏批量装载成本。
调用示例：load := openSyntheticScale(t); counts, err := load.readCounts(ctx)。
*/
package performance

import (
	"context" // 驱动受限于本测试 schema 的批量装载和聚合计数。
	"fmt"     // 生成固定宽度、不可与真实身份混淆的 synthetic ID。
	"testing" // 把负载失败和随机 schema 清理绑定到当前测试。
	"time"    // 构造确定性 UTC 历史时间线。

	"github.com/jackc/pgx/v5" // 使用 PostgreSQL CopyFrom 高效建立目标规模。

	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 复用正式 migration 与随机 schema 清理入口。
)

const (
	syntheticStaffCount             = 20  // SC-003 固定二十名承担学生责任的员工。
	syntheticStudentCount           = 300 // SC-003 固定三百名服务中学生。
	syntheticHistoryFactsPerStudent = 200 // 每名学生二百条连续跟进历史。
	syntheticFollowUpsPerStudent    = syntheticHistoryFactsPerStudent
)

var syntheticPerformanceTime = time.Date(2026, time.August, 6, 8, 0, 0, 0, time.UTC) // 时间固定后，排序和 p95 样本可重复。

// syntheticCounts 是性能证据唯一公开的数据库事实，不携带任何业务行内容。
type syntheticCounts struct {
	StaffProfiles       int // StaffProfiles 必须精确为 20。
	Students            int // Students 必须精确为 300 且全部服务中。
	FollowUps           int // FollowUps 是 60,000 条 synthetic 联系历史。
	StudentHistoryFacts int // StudentHistoryFacts 必须精确为 60,000。
}

// syntheticLoad 保存随机 schema 连接；testsupport 在测试结束时精确删除该 schema。
type syntheticLoad struct {
	database *pgx.Conn // database 的 search_path 已锁定到本测试随机 schema。
}

// --- 建立一个完整且自动清理的目标规模 ---
func openSyntheticScale(test *testing.T) *syntheticLoad {
	test.Helper()                                             // 装载失败归因到调用性能合同。
	database := testsupport.OpenDatabase(test, "performance") // 只连接显式 synthetic 测试库并应用正式 migration。
	clearFoundationSeed(test, database)                       // 清除随机 schema 内的小型 Foundation seed，避免计数混入。
	copySyntheticStaff(test, database)                        // 先建立后续外键需要的二十名员工档案。
	copySyntheticAccounts(test, database)                     // 建立一名老板与二十个不可登录的 synthetic 员工账号。
	copySyntheticStudents(test, database)                     // 每名员工精确承担十五名服务中学生。
	copySyntheticAssignments(test, database)                  // 以当前主负责关系验证员工范围。
	copySyntheticFollowUps(test, database)                    // 写入完整连续跟进历史，不依赖已废弃的阶段状态机。
	return &syntheticLoad{database: database}                 // 反馈可供公开命令读取的深负载 seam。
}

// --- 为三百名学生各建立一条当前主负责关系 ---
func copySyntheticAssignments(test *testing.T, database *pgx.Conn) {
	test.Helper()
	_, copyError := database.CopyFrom(
		context.Background(),
		pgx.Identifier{"student_staff_assignments"},
		[]string{"id", "student_id", "staff_profile_id", "assignment_role", "started_at", "created_by_account_id"},
		pgx.CopyFromSlice(syntheticStudentCount, func(row int) ([]any, error) {
			studentNumber := row + 1
			staffNumber := row%syntheticStaffCount + 1
			return []any{
				fmt.Sprintf("SA-performance%06d", studentNumber), syntheticStudentID(studentNumber),
				syntheticStaffID(staffNumber), "primary", syntheticPerformanceTime, "A-performanceowner01",
			}, nil
		}),
	)
	if copyError != nil {
		test.Fatal("synthetic performance assignment load failed")
	}
}

// --- 清除小型 seed，只保留 migration 和静态问卷定义 ---
func clearFoundationSeed(test *testing.T, database *pgx.Conn) {
	test.Helper() // 让清理失败定位到负载装配。
	_, clearError := database.Exec(context.Background(), `
		TRUNCATE TABLE staff_profiles, accounts, students, audit_events, idempotency_records CASCADE`)
	if clearError != nil { // 随机 schema 无法清空时不得接受混合规模。
		test.Fatal("synthetic performance seed reset failed")
	}
}

// --- 建立二十名 synthetic 员工档案 ---
func copySyntheticStaff(test *testing.T, database *pgx.Conn) {
	test.Helper()
	_, copyError := database.CopyFrom(
		context.Background(),
		pgx.Identifier{"staff_profiles"},
		[]string{"id", "display_name", "state"},
		pgx.CopyFromSlice(syntheticStaffCount, func(row int) ([]any, error) {
			staffNumber := row + 1 // 对外编号从一开始，便于人工核对分布。
			return []any{syntheticStaffID(staffNumber), fmt.Sprintf("Synthetic Staff %02d", staffNumber), "active"}, nil
		}),
	)
	if copyError != nil { // CopyFrom 诊断可能包含行值，因此只反馈固定失败分类。
		test.Fatal("synthetic performance staff load failed")
	}
}

// --- 建立一名老板与二十个员工账号 ---
func copySyntheticAccounts(test *testing.T, database *pgx.Conn) {
	test.Helper()
	accountCount := syntheticStaffCount + 1 // 老板不计入“20 名员工”规模。
	_, copyError := database.CopyFrom(
		context.Background(),
		pgx.Identifier{"accounts"},
		[]string{"id", "username_normalized", "username_display", "display_name", "password_hash", "role", "state", "staff_profile_id", "must_change_password"},
		pgx.CopyFromSlice(accountCount, func(row int) ([]any, error) {
			if row == 0 { // 第一行提供团队列表、审计和统计的当前老板身份。
				return []any{"A-performanceowner01", "synthetic-performance-owner", "synthetic-performance-owner", "Synthetic Owner", "synthetic-login-disabled-material", "owner", "active", nil, false}, nil
			}
			staffNumber := row // 后续行与同编号员工档案一一绑定。
			return []any{syntheticAccountID(staffNumber), fmt.Sprintf("synthetic-performance-staff-%02d", staffNumber), fmt.Sprintf("synthetic-performance-staff-%02d", staffNumber), fmt.Sprintf("Synthetic Staff %02d", staffNumber), "synthetic-login-disabled-material", "staff", "active", syntheticStaffID(staffNumber), false}, nil
		}),
	)
	if copyError != nil {
		test.Fatal("synthetic performance account load failed")
	}
}

// --- 建立三百名服务中学生并均匀分配 ---
func copySyntheticStudents(test *testing.T, database *pgx.Conn) {
	test.Helper()
	_, copyError := database.CopyFrom(
		context.Background(),
		pgx.Identifier{"students"},
		[]string{"id", "name", "service_stage", "job_search_stage", "owner_staff_id", "source_kind", "processing_basis", "privacy_notice_version", "privacy_notice_delivered_at", "version", "created_by", "updated_by", "created_at", "updated_at"},
		pgx.CopyFromSlice(syntheticStudentCount, func(row int) ([]any, error) {
			studentNumber := row + 1                                                    // 学生编号只表达 synthetic 序列。
			staffNumber := row%syntheticStaffCount + 1                                  // 300/20 恰好让每名员工拥有十五人。
			accountID := syntheticAccountID(staffNumber)                                // 创建与更新来源保持逐人 synthetic 归属。
			updatedAt := syntheticPerformanceTime.Add(time.Duration(row) * time.Second) // 不同时间让游标排序可重复。
			return []any{syntheticStudentID(studentNumber), fmt.Sprintf("Synthetic Student %03d", studentNumber), "待服务", "未开始", syntheticStaffID(staffNumber), "staff", "service_contract", "privacy-notice-v1", updatedAt, int64(1), accountID, accountID, updatedAt, updatedAt}, nil
		}),
	)
	if copyError != nil {
		test.Fatal("synthetic performance student load failed")
	}
}

// --- 为每名学生建立二百条最小 synthetic 跟进历史 ---
func copySyntheticFollowUps(test *testing.T, database *pgx.Conn) {
	test.Helper()
	totalFollowUps := syntheticStudentCount * syntheticFollowUpsPerStudent
	_, copyError := database.CopyFrom(
		context.Background(),
		pgx.Identifier{"follow_up_records"},
		[]string{"id", "student_id", "contacted_at", "channel", "content", "valid_contact", "reply_required", "overdue_occurrence", "created_by", "updated_by", "created_at", "updated_at"},
		pgx.CopyFromSlice(totalFollowUps, func(row int) ([]any, error) {
			studentNumber := row/syntheticFollowUpsPerStudent + 1    // 连续一百行属于同一学生。
			historyNumber := row%syntheticFollowUpsPerStudent + 1    // 每个学生内部拥有稳定历史序号。
			staffNumber := (studentNumber-1)%syntheticStaffCount + 1 // 写入者与学生当前负责人一致。
			contactedAt := syntheticPerformanceTime.Add(-time.Duration(historyNumber) * time.Hour)
			return []any{syntheticFollowUpID(studentNumber, historyNumber), syntheticStudentID(studentNumber), contactedAt, "synthetic", "Synthetic performance follow-up", true, false, historyNumber%8 == 0, syntheticAccountID(staffNumber), syntheticAccountID(staffNumber), contactedAt, contactedAt}, nil
		}),
	)
	if copyError != nil {
		test.Fatal("synthetic performance follow-up load failed")
	}
}

// --- 读取报告允许公开的四个聚合计数 ---
func (load *syntheticLoad) readCounts(ctx context.Context) (syntheticCounts, error) {
	counts := syntheticCounts{} // 先建立零值，任何查询失败都不会反馈部分规模。
	countError := load.database.QueryRow(ctx, `
		SELECT
			(SELECT count(*)::integer FROM staff_profiles),
			(SELECT count(*)::integer FROM students),
			(SELECT count(*)::integer FROM follow_up_records),
			(SELECT count(*)::integer FROM follow_up_records)`,
	).Scan(&counts.StaffProfiles, &counts.Students, &counts.FollowUps, &counts.StudentHistoryFacts)
	return counts, countError // 只反馈聚合，不把任何业务行带入测试输出。
}

// --- 生成固定宽度 synthetic 身份 ---
func syntheticStaffID(number int) string {
	return fmt.Sprintf("T-performancestaff%02d", number)
}

func syntheticAccountID(number int) string {
	return fmt.Sprintf("A-performancestaff%02d", number)
}

func syntheticStudentID(number int) string {
	return fmt.Sprintf("S-performancestudent%06d", number)
}

func syntheticFollowUpID(studentNumber int, historyNumber int) string {
	return fmt.Sprintf("FU-performance%06d%03d", studentNumber, historyNumber)
}
