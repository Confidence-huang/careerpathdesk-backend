/*
团队计划行为测试：验证老板和老师读取同一计划、只有老板能保存，并用版本拒绝静默覆盖。
每个测试使用独立 synthetic schema；正文断言同时锁住真实换行，避免再次显示字面量反斜杠。
*/
package teamplan

import (
	"context" // 驱动公开团队计划命令。
	"errors"  // 比较稳定业务失败分类。
	"strings" // 识别正文中的真实换行和字面量反斜杠。
	"testing" // 运行 Go 行为测试。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 构造已认证账号投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立随机 synthetic PostgreSQL schema。
)

// --- 老板和老师读取同一份真实换行计划 ---
func TestReadSharesOneMultilinePlan(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "teamplan") // 本测试拥有独立完整数据库。
	commands, commandError := NewCommands(connection, syntheticIdentity)
	if commandError != nil {
		t.Fatalf("team plan commands unavailable: %v", commandError)
	}

	ownerPlan, ownerError := commands.Read(context.Background(), syntheticOwner()) // 老板读取工作台计划。
	staffPlan, staffError := commands.Read(context.Background(), syntheticStaff()) // 老师读取同一服务端事实。
	if ownerError != nil || staffError != nil || ownerPlan != staffPlan {
		t.Fatalf("shared team plan unavailable: owner=%+v staff=%+v errors=%v/%v", ownerPlan, staffPlan, ownerError, staffError)
	}
	if !strings.Contains(ownerPlan.Content, "\n\n") || strings.Contains(ownerPlan.Content, `\n`) {
		t.Fatalf("team plan does not contain real line breaks: %q", ownerPlan.Content)
	}
}

// --- 老板保存计划后版本递增且最小审计落盘 ---
func TestOwnerUpdatesTeamPlan(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "teamplan") // 本测试拥有独立完整数据库。
	commands, _ := NewCommands(connection, syntheticIdentity)
	input := UpdateInput{Title: "本周团队安排", Summary: "先处理逾期事项", Content: "周一检查。\n\n周五复盘。", Version: 1}

	updated, updateError := commands.Update(context.Background(), syntheticOwner(), "R-synthetic-team-plan-update", input)
	if updateError != nil || updated.Version != 2 || updated.Content != input.Content {
		t.Fatalf("owner update failed: plan=%+v error=%v", updated, updateError)
	}
	var auditCount int // 只核对动作、对象和版本，不读取正文。
	queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action='team_plan.updated' AND object_type='team_plan' AND object_id='TP-primary' AND metadata->>'version'='2'`).Scan(&auditCount)
	if queryError != nil || auditCount != 1 {
		t.Fatalf("team plan audit missing: count=%d error=%v", auditCount, queryError)
	}
}

// --- 老师不能借用公开更新命令改写团队安排 ---
func TestStaffCannotUpdateTeamPlan(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "teamplan") // 本测试拥有独立完整数据库。
	commands, _ := NewCommands(connection, syntheticIdentity)
	input := UpdateInput{Title: "不应保存", Summary: "员工输入", Content: "员工输入", Version: 1}

	_, updateError := commands.Update(context.Background(), syntheticStaff(), "R-synthetic-team-plan-staff", input)
	if !errors.Is(updateError, ErrForbidden) {
		t.Fatalf("expected staff denial, got %v", updateError)
	}
}

// --- 落后的老板页面不能覆盖已经保存的新版本 ---
func TestUpdateRejectsStaleVersion(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "teamplan") // 本测试拥有独立完整数据库。
	commands, _ := NewCommands(connection, syntheticIdentity)
	input := UpdateInput{Title: "本周团队安排", Summary: "第一个版本", Content: "先完成第一次保存。", Version: 1}

	if _, updateError := commands.Update(context.Background(), syntheticOwner(), "R-synthetic-team-plan-first", input); updateError != nil {
		t.Fatalf("first update failed: %v", updateError)
	}
	_, staleError := commands.Update(context.Background(), syntheticOwner(), "R-synthetic-team-plan-stale", input)
	if !errors.Is(staleError, ErrVersionConflict) {
		t.Fatalf("expected stale version conflict, got %v", staleError)
	}
}

func syntheticOwner() auth.Account {
	return auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"} // 返回已认证老板投影。
}

func syntheticStaff() auth.Account {
	staffID := "T-syntheticcoach01" // 员工投影保留本人档案身份。
	return auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffID}
}

func syntheticIdentity(prefix string) (string, error) {
	return prefix + "-syntheticteamplan01", nil // 每个测试只有一次审计写入。
}
