/*
运营统计合同：通过真实 PostgreSQL 随机 schema 冻结团队/本人共用定义和当前学生协作范围。
测试只跨越未来 Commands.Overview 公开 interface；聚合结果不返回学生或关注事项身份。
调用示例：statistics, err := commands.Overview(ctx, actor)。
*/
package operations

import (
	"context"       // 驱动统计查询和 synthetic 事实写入。
	"encoding/json" // 证明公开统计投影只有 OpenAPI 固定聚合字段。
	"errors"        // 比较不泄露账号或范围详情的稳定权限失败。
	"reflect"       // 精确比较同定义统计值和公开字段集合。
	"sort"          // 固定 JSON 字段顺序供可读失败反馈。
	"testing"       // 组织彼此隔离的统计行为。
	"time"          // 建立可重复的 synthetic 业务时间。

	"github.com/jackc/pgx/v5" // 在随机 schema 内建立受控统计事实。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 使用认证模块已经验证的账号投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立并清理独立 synthetic PostgreSQL schema。
)

var syntheticStatisticsTime = time.Date(2026, time.August, 6, 2, 0, 0, 0, time.UTC) // 所有统计状态共享一个无环境漂移的 UTC 时刻。

// --- 同一组业务定义只因团队或本人范围产生不同计数 ---
func TestStatisticsOverviewKeepsDefinitionsIdenticalAcrossTeamAndOwnScopes(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 本行为拥有独立 migration、seed 和随机 schema。
	prepareSyntheticStatistics(t, connection)
	commands, createError := NewCommands(connection)
	if createError != nil {
		t.Fatalf("statistics commands failed to initialize: %v", createError)
	}
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	staffOne := syntheticStatisticsStaff("A-syntheticstaff01", "T-syntheticcoach01")
	staffTwo := syntheticStatisticsStaff("A-syntheticstaff02", "T-syntheticcoach02")

	team, teamError := commands.Overview(context.Background(), owner)
	if teamError != nil {
		t.Fatalf("owner team statistics failed: %v", teamError)
	}
	one, oneError := commands.Overview(context.Background(), staffOne)
	if oneError != nil {
		t.Fatalf("first staff own statistics failed: %v", oneError)
	}
	two, twoError := commands.Overview(context.Background(), staffTwo)
	if twoError != nil {
		t.Fatalf("second staff own statistics failed: %v", twoError)
	}

	expectedTeam := Statistics{Scope: "team", InServiceStudents: 4, OverdueFollowUps: 3, OpenAttentionCases: 2}
	expectedOne := Statistics{Scope: "own", InServiceStudents: 2, OverdueFollowUps: 2, OpenAttentionCases: 1}
	expectedTwo := Statistics{Scope: "own", InServiceStudents: 2, OverdueFollowUps: 1, OpenAttentionCases: 1}
	if !reflect.DeepEqual(team, expectedTeam) || !reflect.DeepEqual(one, expectedOne) || !reflect.DeepEqual(two, expectedTwo) {
		t.Fatalf("statistics definitions or scopes drifted: team=%#v one=%#v two=%#v", team, one, two)
	}
	if team.InServiceStudents != one.InServiceStudents+two.InServiceStudents ||
		team.OverdueFollowUps != one.OverdueFollowUps+two.OverdueFollowUps ||
		team.OpenAttentionCases != one.OpenAttentionCases+two.OpenAttentionCases {
		t.Fatal("team and own scopes did not reuse the same metric definitions")
	}

	encoded, encodeError := json.Marshal(team) // HTTP adapter 后续只能转发这四个非识别性聚合字段。
	if encodeError != nil {
		t.Fatal("statistics projection could not be encoded")
	}
	publicFields := map[string]json.RawMessage{}
	if decodeError := json.Unmarshal(encoded, &publicFields); decodeError != nil {
		t.Fatal("statistics projection did not encode as an object")
	}
	fieldNames := make([]string, 0, len(publicFields))
	for fieldName := range publicFields { // 字段身份足以证明没有学生或业务正文被扩展进结果。
		fieldNames = append(fieldNames, fieldName)
	}
	sort.Strings(fieldNames)
	expectedFields := []string{"in_service_students", "open_attention_cases", "overdue_follow_ups", "scope"}
	if !reflect.DeepEqual(fieldNames, expectedFields) {
		t.Fatalf("statistics projection exposed a non-aggregate field set: %#v", fieldNames)
	}
}

// --- 所有子资源统计跟随当前学生协作关系，而不是调用方旧投影 ---
func TestStatisticsOverviewFollowsCurrentStudentOwnership(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 责任变化只影响本测试的随机 schema。
	prepareSyntheticStatistics(t, connection)
	commands, createError := NewCommands(connection)
	if createError != nil {
		t.Fatalf("statistics commands failed to initialize: %v", createError)
	}
	forgedProfile := "T-syntheticcoach02"
	staffOne := auth.Account{
		ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &forgedProfile,
	} // 外部投影故意声称另一档案；数据库当前账号绑定仍是唯一权威范围。

	before, beforeError := commands.Overview(context.Background(), staffOne)
	if beforeError != nil || !reflect.DeepEqual(before, Statistics{Scope: "own", InServiceStudents: 2, OverdueFollowUps: 2, OpenAttentionCases: 1}) {
		t.Fatalf("statistics trusted actor projection before transfer: value=%#v error=%v", before, beforeError)
	}
	if _, transferError := connection.Exec(context.Background(), `
		WITH ended AS (
			UPDATE student_staff_assignments
			SET ended_at = $2, ended_by_account_id = 'A-syntheticowner01', updated_at = $2
			WHERE student_id = $1 AND ended_at IS NULL RETURNING student_id
		), inserted AS (
			INSERT INTO student_staff_assignments (id, student_id, staff_profile_id, assignment_role, started_at, created_by_account_id)
			SELECT 'SA-syntheticstatstransfer', student_id, 'T-syntheticcoach02', 'primary', $2, 'A-syntheticowner01' FROM ended LIMIT 1
			RETURNING student_id
		)
		UPDATE students SET owner_staff_id = 'T-syntheticcoach02', updated_at = $2 WHERE id = (SELECT student_id FROM inserted)`, "S-syntheticstudent01", syntheticStatisticsTime.Add(time.Hour)); transferError != nil {
		t.Fatalf("synthetic statistics ownership transfer failed: %v", transferError)
	}

	afterOne, afterOneError := commands.Overview(context.Background(), staffOne)
	staffTwo := syntheticStatisticsStaff("A-syntheticstaff02", "T-syntheticcoach02")
	afterTwo, afterTwoError := commands.Overview(context.Background(), staffTwo)
	if afterOneError != nil || !reflect.DeepEqual(afterOne, Statistics{Scope: "own", InServiceStudents: 1, OverdueFollowUps: 1, OpenAttentionCases: 0}) {
		t.Fatalf("old owner retained transferred student facts: value=%#v error=%v", afterOne, afterOneError)
	}
	if afterTwoError != nil || !reflect.DeepEqual(afterTwo, Statistics{Scope: "own", InServiceStudents: 3, OverdueFollowUps: 2, OpenAttentionCases: 2}) {
		t.Fatalf("new owner did not receive the complete student aggregate: value=%#v error=%v", afterTwo, afterTwoError)
	}
}

// --- 当前账号权限先于统计读取，停用或未知投影得到同类空反馈 ---
func TestStatisticsOverviewRequiresCurrentAuthorizedAccount(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "operations") // 权限变化不共享任何其他统计查询。
	prepareSyntheticStatistics(t, connection)
	commands, createError := NewCommands(connection)
	if createError != nil {
		t.Fatalf("statistics commands failed to initialize: %v", createError)
	}
	staleStaff := syntheticStatisticsStaff("A-syntheticstaff01", "T-syntheticcoach01")
	if _, disableError := connection.Exec(context.Background(), `UPDATE accounts SET state = 'disabled' WHERE id = $1`, staleStaff.ID); disableError != nil {
		t.Fatal("synthetic statistics account disable failed")
	}

	disabledResult, disabledError := commands.Overview(context.Background(), staleStaff)
	unknownResult, unknownError := commands.Overview(context.Background(), auth.Account{ID: "A-syntheticunknown01", Role: "owner", State: "active"})
	if !errors.Is(disabledError, ErrForbidden) || !reflect.DeepEqual(disabledResult, Statistics{}) {
		t.Fatalf("disabled statistics query did not fail closed: value=%#v error=%v", disabledResult, disabledError)
	}
	if !errors.Is(unknownError, ErrForbidden) || !reflect.DeepEqual(unknownResult, Statistics{}) {
		t.Fatalf("unknown statistics query leaked a distinct result: value=%#v error=%v", unknownResult, unknownError)
	}
}

// --- 建立包含计入项和终态干扰项的完整 synthetic 统计切片 ---
func prepareSyntheticStatistics(t *testing.T, connection *pgx.Conn) {
	t.Helper() // fixture 失败归因到调用行为测试。
	if _, resetError := connection.Exec(context.Background(), `
		UPDATE students SET
			owner_staff_id = CASE
				WHEN id IN ('S-syntheticstudent01', 'S-syntheticstudent02') THEN 'T-syntheticcoach01'
				ELSE 'T-syntheticcoach02'
			END`); resetError != nil {
		t.Fatal("synthetic statistics baseline setup failed")
	}

	followUps := []syntheticStatisticsFollowUp{
		{ID: "FU-syntheticstat01", StudentID: "S-syntheticstudent01", Overdue: true},
		{ID: "FU-syntheticstat02", StudentID: "S-syntheticstudent02", Overdue: true},
		{ID: "FU-syntheticstat03", StudentID: "S-syntheticstudent02", Overdue: false}, // 未确认逾期不进入统计。
		{ID: "FU-syntheticstat04", StudentID: "S-syntheticstudent03", Overdue: true},
		{ID: "FU-syntheticstat05", StudentID: "S-syntheticstudent04", Overdue: false},
	}
	for index, followUp := range followUps {
		insertSyntheticStatisticsFollowUp(t, connection, followUp, syntheticStatisticsTime.Add(time.Duration(index)*time.Minute))
	}

	cases := []syntheticStatisticsCase{
		{ID: "AC-syntheticstat01", StudentID: "S-syntheticstudent01", Status: "open", FingerprintByte: 1},
		{ID: "AC-syntheticstat02", StudentID: "S-syntheticstudent02", Status: "resolved", FingerprintByte: 2},
		{ID: "AC-syntheticstat03", StudentID: "S-syntheticstudent03", Status: "open", FingerprintByte: 3},
		{ID: "AC-syntheticstat04", StudentID: "S-syntheticstudent04", Status: "dismissed", FingerprintByte: 4},
	}
	for index, attentionCase := range cases {
		insertSyntheticStatisticsCase(t, connection, attentionCase, syntheticStatisticsTime.Add(time.Duration(index)*time.Minute))
	}
}

type syntheticStatisticsFollowUp struct {
	ID        string // ID 是不含正文的合成跟进引用。
	StudentID string // StudentID 决定统计归属范围。
	Overdue   bool   // Overdue 只有 true 才是已确认逾期事实。
}

// --- 写入一条明确是否逾期的合成跟进 ---
func insertSyntheticStatisticsFollowUp(t *testing.T, connection *pgx.Conn, followUp syntheticStatisticsFollowUp, contactedAt time.Time) {
	t.Helper() // fixture 失败归因到调用统计行为。
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO follow_up_records (
			id, student_id, contacted_at, channel, valid_contact, reply_required,
			overdue_occurrence, created_by, updated_by
		) VALUES ($1, $2, $3, 'synthetic', false, false, $4, 'A-syntheticstaff01', 'A-syntheticstaff01')`,
		followUp.ID, followUp.StudentID, contactedAt.UTC(), followUp.Overdue); insertError != nil {
		t.Fatal("synthetic statistics follow-up setup failed")
	}
}

type syntheticStatisticsCase struct {
	ID              string // ID 是不含结论正文的合成事项引用。
	StudentID       string // StudentID 决定事项聚合范围。
	Status          string // Status 覆盖开放、解决和驳回。
	FingerprintByte byte   // FingerprintByte 使同规则 fixture 拥有独立指纹。
}

// --- 写入一项开放或人工终结的合成关注事项 ---
func insertSyntheticStatisticsCase(t *testing.T, connection *pgx.Conn, attentionCase syntheticStatisticsCase, occurredAt time.Time) {
	t.Helper() // fixture 失败归因到调用统计行为。
	fingerprint := make([]byte, 32)
	fingerprint[len(fingerprint)-1] = attentionCase.FingerprintByte
	var conclusionCode, conclusionReason, concludedBy *string
	var concludedAt *time.Time
	if attentionCase.Status != "open" {
		code := "continue_service"
		if attentionCase.Status == "dismissed" {
			code = "dismiss"
		}
		reason := "Synthetic statistics conclusion"
		actorID := "A-syntheticowner01"
		concluded := occurredAt.UTC()
		conclusionCode, conclusionReason, concludedBy, concludedAt = &code, &reason, &actorID, &concluded
	}
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO student_attention_cases (
			id, student_id, rule_code, trigger_codes, evidence, evidence_fingerprint,
			first_triggered_at, last_triggered_at, status, conclusion_code,
			conclusion_reason, concluded_by_account_id, concluded_at
		) VALUES (
			$1, $2, 'complaint', ARRAY['complaint']::text[],
			jsonb_build_array(jsonb_build_object('object_type', 'event', 'object_id', $1::text)),
			$3, $4, $4, $5, $6, $7, $8, $9
		)`, attentionCase.ID, attentionCase.StudentID, fingerprint, occurredAt.UTC(), attentionCase.Status,
		conclusionCode, conclusionReason, concludedBy, concludedAt); insertError != nil {
		t.Fatal("synthetic statistics attention setup failed")
	}
}

// --- 返回指定当前档案的活动 synthetic 员工投影 ---
func syntheticStatisticsStaff(accountID string, staffProfileID string) auth.Account {
	return auth.Account{ID: accountID, Role: "staff", State: "active", StaffProfileID: &staffProfileID}
}
