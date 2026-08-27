/*
关注事项命令合同：通过真实 PostgreSQL 冻结提醒、升级、证据去重和老板人工结论。
测试只跨越未来 Commands 公开 interface；所有时间、账号、学生和证据均属于随机 synthetic schema。
调用示例：err := commands.Evaluate(ctx, studentID)，caseItem, err := commands.Conclude(ctx, owner, requestID, caseID, input)。
*/
package attention

import (
	"context" // 驱动公开关注命令和 synthetic 事实查询。
	"errors"  // 比较不包含业务正文的稳定领域失败。
	"fmt"     // 生成不同且可辨认的合成跟进身份。
	"reflect" // 证明重复扫描和新证据不会改写旧结论。
	"sort"    // 把触发码集合转换为稳定断言顺序。
	"testing" // 组织独立规则行为和故障注入。
	"time"    // 冻结 48/72 小时边界与证据时间。

	"github.com/jackc/pgx/v5" // 在随机 schema 内建立最小证据事实。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 使用认证模块已验证的老板和员工投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立可精确清理的独立 synthetic schema。
)

var syntheticAttentionBaseTime = time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC) // 所有规则边界共享一个可信 UTC 起点。

// --- 48 小时提醒与 72 小时老板关注严格分流 ---
func TestAttentionTimeBoundariesSplitStaffReminderFromOwnerCase(t *testing.T) {
	checkpoints := []struct {
		name             string        // name 直接说明当前边界位置。
		elapsed          time.Duration // elapsed 从最后一次有效联系开始计算。
		reminderExpected bool          // reminderExpected 只属于当前负责人。
		caseExpected     bool          // caseExpected 只在老板升级边界出现。
	}{
		{name: "before reminder", elapsed: 48*time.Hour - time.Second, reminderExpected: false, caseExpected: false},
		{name: "at reminder", elapsed: 48 * time.Hour, reminderExpected: true, caseExpected: false},
		{name: "before owner case", elapsed: 72*time.Hour - time.Second, reminderExpected: true, caseExpected: false},
		{name: "at owner case", elapsed: 72 * time.Hour, reminderExpected: true, caseExpected: true},
	}

	for _, checkpoint := range checkpoints { // 每个时间点使用独立 schema，避免较晚评估污染较早边界。
		t.Run(checkpoint.name, func(t *testing.T) {
			connection := testsupport.OpenDatabase(t, "attention")
			insertSyntheticFollowUp(t, connection, syntheticFollowUp{
				ID: "FU-syntheticattentionbase01", StudentID: "S-syntheticstudent01",
				ContactedAt: syntheticAttentionBaseTime, ValidContact: true,
			})
			insertSyntheticFollowUp(t, connection, syntheticFollowUp{
				ID: "FU-syntheticattentionforeign", StudentID: "S-syntheticstudent03",
				ContactedAt: syntheticAttentionBaseTime, ValidContact: true,
			})
			commands := newAttentionTestCommands(t, connection, syntheticAttentionBaseTime.Add(checkpoint.elapsed))
			if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
				t.Fatalf("attention boundary evaluation failed: %v", evaluateError)
			}

			staffReminders, reminderError := commands.ListStaffReminders(context.Background(), syntheticAttentionStaff())
			if reminderError != nil {
				t.Fatalf("staff reminder list failed: %v", reminderError)
			}
			reminderStudentIDs := syntheticReminderStudentIDs(staffReminders)
			if _, found := reminderStudentIDs["S-syntheticstudent01"]; found != checkpoint.reminderExpected {
				t.Fatalf("48-hour reminder boundary diverged: elapsed=%s reminders=%#v", checkpoint.elapsed, staffReminders)
			}
			if _, leaked := reminderStudentIDs["S-syntheticstudent03"]; leaked { // 外部学生拥有同样时间事实也不能进入本人提醒。
				t.Fatalf("staff reminder leaked a foreign student: %#v", staffReminders)
			}

			cases, caseError := commands.ListCases(context.Background(), syntheticAttentionOwner())
			if caseError != nil || (len(cases) > 0) != checkpoint.caseExpected {
				t.Fatalf("72-hour owner boundary diverged: elapsed=%s cases=%#v error=%v", checkpoint.elapsed, cases, caseError)
			}
			if checkpoint.caseExpected && !syntheticTriggerSet(cases[0])["no_contact_72h"] {
				t.Fatalf("72-hour case omitted its fixed trigger: %#v", cases[0])
			}
		})
	}
}

// --- 已确认投诉无需等待时间门槛，并且证据不复制正文 ---
func TestComplaintOpensImmediateCaseWithMinimalEvidence(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention") // 投诉事实不复用其他触发场景。
	complaintTime := syntheticAttentionBaseTime.Add(time.Hour)
	insertSyntheticComplaintEvent(t, connection, "EV-syntheticcomplaint01", "S-syntheticstudent01", complaintTime)
	commands := newAttentionTestCommands(t, connection, complaintTime)

	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("complaint attention evaluation failed: %v", evaluateError)
	}
	cases, caseError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if caseError != nil || len(cases) != 1 {
		t.Fatalf("complaint did not open exactly one owner case: %#v %v", cases, caseError)
	}
	attentionCase := cases[0]
	if triggers := syntheticSortedTriggers(attentionCase); !reflect.DeepEqual(triggers, []string{"complaint"}) {
		t.Fatalf("complaint case has unexpected triggers: %#v", triggers)
	}
	if len(attentionCase.Evidence) != 1 || attentionCase.Evidence[0].ObjectType != "student_event" || attentionCase.Evidence[0].ObjectID != "EV-syntheticcomplaint01" {
		t.Fatalf("complaint case exposed more than its minimal reference: %#v", attentionCase.Evidence)
	}
}

// --- 用户可达的确认投诉命令必须原子形成事件、关注事项与最小审计 ---
func TestConfirmComplaintCreatesImmediateScopedCaseAndReplaysIdempotently(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention")
	commands := newAttentionTestCommands(t, connection, syntheticAttentionBaseTime.Add(time.Hour))
	staff := syntheticAttentionStaff()

	first, confirmError := commands.ConfirmComplaint(context.Background(), staff, "R-syntheticcomplaintconfirm", "synthetic-key-complaint-confirm-01", "S-syntheticstudent01")
	if confirmError != nil || first.StudentID != "S-syntheticstudent01" || !syntheticTriggerSet(first)["complaint"] {
		t.Fatalf("confirmed complaint did not create its immediate case: %#v %v", first, confirmError)
	}
	replayed, replayError := commands.ConfirmComplaint(context.Background(), staff, "R-syntheticcomplaintreplay", "synthetic-key-complaint-confirm-01", "S-syntheticstudent01")
	if replayError != nil || replayed.ID != first.ID {
		t.Fatalf("confirmed complaint did not replay the same case: first=%#v replay=%#v error=%v", first, replayed, replayError)
	}
	if _, foreignError := commands.ConfirmComplaint(context.Background(), staff, "R-syntheticcomplaintforeign", "synthetic-key-complaint-confirm-02", "S-syntheticstudent03"); !errors.Is(foreignError, ErrNotFound) {
		t.Fatalf("foreign staff complaint confirmation did not preserve object hiding: %v", foreignError)
	}

	var eventCount, auditCount, idempotencyCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_events WHERE student_id = 'S-syntheticstudent01' AND event_type = 'complaint.confirmed'`).Scan(&eventCount); queryError != nil {
		t.Fatal("synthetic confirmed complaint event query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'attention.complaint_confirmed' AND object_id = $1`, first.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic confirmed complaint audit query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE action = 'attention.complaint_confirm' AND idempotency_key = 'synthetic-key-complaint-confirm-01'`).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("synthetic confirmed complaint idempotency query failed")
	}
	if eventCount != 1 || auditCount != 1 || idempotencyCount != 1 {
		t.Fatalf("confirmed complaint facts diverged: events=%d audits=%d idempotency=%d", eventCount, auditCount, idempotencyCount)
	}
}

// --- 老板全量重检把既有事实接到队列，且员工不能触发团队扫描 ---
func TestOwnerEvaluateAllMaterializesExistingFacts(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention")
	insertSyntheticComplaintEvent(t, connection, "EV-syntheticevaluateall01", "S-syntheticstudent01", syntheticAttentionBaseTime)
	commands := newAttentionTestCommands(t, connection, syntheticAttentionBaseTime.Add(time.Hour))

	if _, staffError := commands.EvaluateAll(context.Background(), syntheticAttentionStaff()); !errors.Is(staffError, ErrForbidden) {
		t.Fatalf("staff was allowed to evaluate the owner queue: %v", staffError)
	}
	cases, evaluateError := commands.EvaluateAll(context.Background(), syntheticAttentionOwner())
	if evaluateError != nil || len(cases) != 1 || !syntheticTriggerSet(cases[0])["complaint"] {
		t.Fatalf("owner evaluation did not materialize existing facts: %#v %v", cases, evaluateError)
	}
}

// --- 第三条不同逾期跟进立即升级 ---
func TestThirdDistinctOverdueFollowUpOpensImmediateCase(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention") // 三条逾期事实只属于当前学生。
	for index := 0; index < 3; index++ {
		insertSyntheticFollowUp(t, connection, syntheticFollowUp{
			ID: fmt.Sprintf("FU-syntheticoverdue%02d", index+1), StudentID: "S-syntheticstudent01",
			ContactedAt: syntheticAttentionBaseTime.Add(time.Duration(index+1) * time.Minute), OverdueOccurrence: true,
		})
	}
	commands := newAttentionTestCommands(t, connection, syntheticAttentionBaseTime.Add(time.Hour))

	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("third-overdue attention evaluation failed: %v", evaluateError)
	}
	cases, caseError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if caseError != nil || len(cases) != 1 || !syntheticTriggerSet(cases[0])["third_followup_overdue"] {
		t.Fatalf("third distinct overdue did not open its case: %#v %v", cases, caseError)
	}
	evidenceIDs := syntheticEvidenceIDs(cases[0].Evidence, "follow_up")
	if len(evidenceIDs) != 3 { // 三个不同 ID 共同证明“第三次”，不能用一条记录重复计数。
		t.Fatalf("third-overdue evidence was not distinct: %#v", cases[0].Evidence)
	}
}

// --- 学生未回复必须同时满足 72 小时与同线程连续三次无有效回复 ---
func TestStudentNoReplyRequiresTimeAndConsecutiveAttemptGates(t *testing.T) {
	checks := []struct {
		name         string        // name 描述缺少的门槛或完整满足状态。
		attemptCount int           // attemptCount 只统计同一回复线程的连续失败。
		elapsed      time.Duration // elapsed 从该线程第一次待回复尝试开始。
		caseExpected bool          // caseExpected 只在两个门槛同时满足时为真。
	}{
		{name: "three attempts before time", attemptCount: 3, elapsed: 72*time.Hour - time.Second, caseExpected: false},
		{name: "time with two attempts", attemptCount: 2, elapsed: 72 * time.Hour, caseExpected: false},
		{name: "time with three attempts", attemptCount: 3, elapsed: 72 * time.Hour, caseExpected: true},
	}

	for _, check := range checks { // 每个 AND 组合使用独立 schema，结果互不影响。
		t.Run(check.name, func(t *testing.T) {
			connection := testsupport.OpenDatabase(t, "attention")
			for index := 0; index < check.attemptCount; index++ {
				replyThreadID := "RT-syntheticnoreply01"
				insertSyntheticFollowUp(t, connection, syntheticFollowUp{
					ID: fmt.Sprintf("FU-syntheticnoreply%02d", index+1), StudentID: "S-syntheticstudent01",
					ContactedAt:   syntheticAttentionBaseTime.Add(time.Duration(index) * time.Hour),
					ReplyRequired: true, ReplyThreadID: &replyThreadID,
				})
			}
			insertSyntheticFollowUp(t, connection, syntheticFollowUp{
				ID: "FU-syntheticfreshcontact", StudentID: "S-syntheticstudent01",
				ContactedAt: syntheticAttentionBaseTime.Add(check.elapsed - time.Hour), ValidContact: true,
			}) // 另一线程的近期有效联系隔离普通 72 小时无联系规则。
			commands := newAttentionTestCommands(t, connection, syntheticAttentionBaseTime.Add(check.elapsed))

			if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
				t.Fatalf("no-reply attention evaluation failed: %v", evaluateError)
			}
			cases, caseError := commands.ListCases(context.Background(), syntheticAttentionOwner())
			if caseError != nil || (len(cases) > 0) != check.caseExpected {
				t.Fatalf("no-reply AND gate diverged: attempts=%d elapsed=%s cases=%#v error=%v", check.attemptCount, check.elapsed, cases, caseError)
			}
			if check.caseExpected && !syntheticTriggerSet(cases[0])["student_no_reply"] {
				t.Fatalf("no-reply case omitted its fixed trigger: %#v", cases[0])
			}
		})
	}
}

// --- 明确回复只重置自己的线程，重置前后的失败不能拼接 ---
func TestEffectiveReplyResetsOnlyItsReplyThreadSequence(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention") // 重置前后记录保留在同一有序线程。
	replyThreadID := "RT-syntheticreplyreset"
	for index := 0; index < 2; index++ {
		insertSyntheticFollowUp(t, connection, syntheticFollowUp{
			ID: fmt.Sprintf("FU-syntheticbeforereset%02d", index+1), StudentID: "S-syntheticstudent01",
			ContactedAt:   syntheticAttentionBaseTime.Add(time.Duration(index) * time.Hour),
			ReplyRequired: true, ReplyThreadID: &replyThreadID,
		})
	}
	repliedAt := syntheticAttentionBaseTime.Add(2 * time.Hour)
	insertSyntheticFollowUp(t, connection, syntheticFollowUp{
		ID: "FU-syntheticeffectivereply", StudentID: "S-syntheticstudent01", ContactedAt: repliedAt,
		ValidContact: true, ReplyRequired: true, ReplyThreadID: &replyThreadID, StudentRepliedAt: &repliedAt,
	})
	for index := 0; index < 2; index++ {
		insertSyntheticFollowUp(t, connection, syntheticFollowUp{
			ID: fmt.Sprintf("FU-syntheticafterreset%02d", index+1), StudentID: "S-syntheticstudent01",
			ContactedAt:   syntheticAttentionBaseTime.Add(time.Duration(index+3) * time.Hour),
			ReplyRequired: true, ReplyThreadID: &replyThreadID,
		})
	}
	insertSyntheticFollowUp(t, connection, syntheticFollowUp{
		ID: "FU-syntheticrecentotherthread", StudentID: "S-syntheticstudent01",
		ContactedAt: syntheticAttentionBaseTime.Add(79 * time.Hour), ValidContact: true,
	})
	commands := newAttentionTestCommands(t, connection, syntheticAttentionBaseTime.Add(80*time.Hour))

	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("reply-reset evaluation failed: %v", evaluateError)
	}
	if cases, caseError := commands.ListCases(context.Background(), syntheticAttentionOwner()); caseError != nil || len(cases) != 0 {
		t.Fatalf("reply reset joined attempts across the effective reply: %#v %v", cases, caseError)
	}
	insertSyntheticFollowUp(t, connection, syntheticFollowUp{
		ID: "FU-syntheticafterreset03", StudentID: "S-syntheticstudent01",
		ContactedAt: syntheticAttentionBaseTime.Add(5 * time.Hour), ReplyRequired: true, ReplyThreadID: &replyThreadID,
	})
	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("third post-reset evaluation failed: %v", evaluateError)
	}
	cases, caseError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if caseError != nil || len(cases) != 1 || !syntheticTriggerSet(cases[0])["student_no_reply"] {
		t.Fatalf("third post-reset attempt did not open no-reply case: %#v %v", cases, caseError)
	}
}

// --- 同时触发合并为一项，重复扫描不增加版本或重复证据 ---
func TestAttentionEvaluationMergesTriggersAndDeduplicatesEvidence(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention") // 同一学生的多种事实需要合并观察。
	insertSyntheticFollowUp(t, connection, syntheticFollowUp{
		ID: "FU-syntheticattentioncontact", StudentID: "S-syntheticstudent01",
		ContactedAt: syntheticAttentionBaseTime, ValidContact: true,
	})
	insertSyntheticComplaintEvent(t, connection, "EV-syntheticcomplaintmerge", "S-syntheticstudent01", syntheticAttentionBaseTime.Add(time.Hour))
	for index := 0; index < 3; index++ {
		insertSyntheticFollowUp(t, connection, syntheticFollowUp{
			ID: fmt.Sprintf("FU-syntheticmerge%02d", index+1), StudentID: "S-syntheticstudent01",
			ContactedAt: syntheticAttentionBaseTime.Add(time.Duration(index+1) * time.Minute), OverdueOccurrence: true,
		})
	}
	commands := newAttentionTestCommands(t, connection, syntheticAttentionBaseTime.Add(72*time.Hour))

	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("multi-trigger evaluation failed: %v", evaluateError)
	}
	firstCases, firstListError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if firstListError != nil || len(firstCases) != 1 {
		t.Fatalf("multi-trigger evaluation did not produce one case: %#v %v", firstCases, firstListError)
	}
	firstCase := firstCases[0]
	expectedTriggers := []string{"complaint", "no_contact_72h", "third_followup_overdue"}
	if triggers := syntheticSortedTriggers(firstCase); !reflect.DeepEqual(triggers, expectedTriggers) {
		t.Fatalf("simultaneous triggers were not merged: %#v", triggers)
	}
	if evidenceKeys := syntheticEvidenceKeys(firstCase.Evidence); len(evidenceKeys) != len(firstCase.Evidence) {
		t.Fatalf("attention evidence contains duplicate references: %#v", firstCase.Evidence)
	}

	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("repeated attention evaluation failed: %v", evaluateError)
	}
	secondCases, secondListError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if secondListError != nil || len(secondCases) != 1 || !reflect.DeepEqual(firstCase, secondCases[0]) {
		t.Fatalf("repeated scan changed the case or evidence: first=%#v second=%#v error=%v", firstCase, secondCases, secondListError)
	}
}

// --- 人工结论只限老板且不可改写，旧证据不可重开 ---
func TestOwnerConclusionIsVersionedImmutableAndNeverChangesService(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention") // 人工结论与后续新证据共享一条可审查时间线。
	firstEvidenceTime := syntheticAttentionBaseTime.Add(time.Hour)
	insertSyntheticComplaintEvent(t, connection, "EV-syntheticconclusion01", "S-syntheticstudent01", firstEvidenceTime)
	commands := newAttentionTestCommands(t, connection, firstEvidenceTime)
	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("conclusion source evaluation failed: %v", evaluateError)
	}
	openCases, listError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if listError != nil || len(openCases) != 1 {
		t.Fatalf("conclusion source case is missing: %#v %v", openCases, listError)
	}
	openCase := openCases[0]
	input := ConclusionInput{ConclusionCode: "internal_review", Reason: "Synthetic owner review", Version: openCase.Version}

	if _, staffError := commands.Conclude(context.Background(), syntheticAttentionStaff(), "R-syntheticconclusion01", openCase.ID, input); !errors.Is(staffError, ErrForbidden) {
		t.Fatalf("staff conclusion was not rejected before case access: %v", staffError)
	}
	if _, unknownStaffError := commands.Conclude(context.Background(), syntheticAttentionStaff(), "R-syntheticconclusion02", "AC-syntheticunknown01", input); !errors.Is(unknownStaffError, ErrForbidden) {
		t.Fatalf("staff learned case existence from a different failure: %v", unknownStaffError)
	}
	staleInput := input
	staleInput.Version++
	if _, staleError := commands.Conclude(context.Background(), syntheticAttentionOwner(), "R-syntheticconclusion03", openCase.ID, staleInput); !errors.Is(staleError, ErrVersionConflict) {
		t.Fatalf("stale attention version was not rejected: %v", staleError)
	}

	resolved, conclusionError := commands.Conclude(context.Background(), syntheticAttentionOwner(), "R-syntheticconclusion04", openCase.ID, input)
	if conclusionError != nil || resolved.Status != "resolved" || resolved.ConclusionCode == nil || *resolved.ConclusionCode != "internal_review" || resolved.ConclusionReason == nil || *resolved.ConclusionReason != input.Reason || resolved.Version != openCase.Version+1 {
		t.Fatalf("owner conclusion did not form a versioned resolved case: %#v %v", resolved, conclusionError)
	}
	if _, repeatedError := commands.Conclude(context.Background(), syntheticAttentionOwner(), "R-syntheticconclusion05", openCase.ID, ConclusionInput{
		ConclusionCode: "dismiss", Reason: "Synthetic rewrite attempt", Version: resolved.Version,
	}); !errors.Is(repeatedError, ErrVersionConflict) {
		t.Fatalf("resolved attention conclusion was mutable: %v", repeatedError)
	}

	var studentVersion int64
	var activeAssignmentCount int // 人工结论不能隐式改变协作关系。
	var prohibitedEventCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT version FROM students WHERE id = 'S-syntheticstudent01'`).Scan(&studentVersion); queryError != nil {
		t.Fatal("synthetic concluded student query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_staff_assignments WHERE student_id = 'S-syntheticstudent01' AND ended_at IS NULL`).Scan(&activeAssignmentCount); queryError != nil {
		t.Fatal("synthetic collaboration query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FROM student_events
		WHERE student_id = 'S-syntheticstudent01'
		  AND (event_type LIKE 'refund.%' OR event_type IN ('service.ended', 'service.terminated'))`).Scan(&prohibitedEventCount); queryError != nil {
		t.Fatal("synthetic prohibited automatic-event query failed")
	}
	if studentVersion != 1 || activeAssignmentCount != 1 || prohibitedEventCount != 0 {
		t.Fatalf("manual conclusion changed student collaboration or triggered a prohibited action: version=%d assignments=%d events=%d", studentVersion, activeAssignmentCount, prohibitedEventCount)
	}

	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("resolved evidence re-evaluation failed: %v", evaluateError)
	}
	unchangedCases, unchangedError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if unchangedError != nil || len(unchangedCases) != 1 || !reflect.DeepEqual(resolved, unchangedCases[0]) {
		t.Fatalf("old evidence reopened or rewrote the resolved case: %#v %v", unchangedCases, unchangedError)
	}

	secondEvidenceTime := firstEvidenceTime.Add(time.Hour)
	insertSyntheticComplaintEvent(t, connection, "EV-syntheticconclusion02", "S-syntheticstudent01", secondEvidenceTime)
	laterCommands := newAttentionTestCommands(t, connection, secondEvidenceTime)
	if evaluateError := laterCommands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("new-evidence attention evaluation failed: %v", evaluateError)
	}
	allCases, allCasesError := laterCommands.ListCases(context.Background(), syntheticAttentionOwner())
	if allCasesError != nil || len(allCases) != 2 {
		t.Fatalf("new evidence did not open a separate case: %#v %v", allCases, allCasesError)
	}
	oldCase := findSyntheticAttentionCase(t, allCases, resolved.ID)
	newCase := findSyntheticCaseByStatus(t, allCases, "open")
	newEvidenceIDs := syntheticEvidenceIDs(newCase.Evidence, "student_event")
	if !reflect.DeepEqual(oldCase, resolved) || len(newEvidenceIDs) != 1 || !newEvidenceIDs["EV-syntheticconclusion02"] || countSyntheticCasesByStatus(allCases, "open") != 1 || countSyntheticCasesByStatus(allCases, "resolved") != 1 {
		t.Fatalf("new evidence overwrote historical conclusion: resolved=%#v all=%#v", resolved, allCases)
	}

	var auditCount int        // 只有成功人工结论产生一条审计。
	var minimalAuditCount int // 理由和证据不得复制到最小审计元数据。
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE metadata ? 'conclusion_code' AND metadata ? 'version' AND NOT metadata ? 'reason' AND NOT metadata ? 'evidence') FROM audit_events WHERE action = 'attention.concluded' AND object_id = $1`, openCase.ID).Scan(&auditCount, &minimalAuditCount); queryError != nil {
		t.Fatal("synthetic attention conclusion audit query failed")
	}
	if auditCount != 1 || minimalAuditCount != 1 {
		t.Fatalf("attention conclusion audit is not singular and minimal: count=%d minimal=%d", auditCount, minimalAuditCount)
	}
}

// --- 审计失败必须回滚人工结论的全部状态变化 ---
func TestOwnerConclusionRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "attention") // 故障注入只影响当前随机 schema。
	evidenceTime := syntheticAttentionBaseTime.Add(time.Hour)
	insertSyntheticComplaintEvent(t, connection, "EV-syntheticrollback01", "S-syntheticstudent01", evidenceTime)
	commands := newAttentionTestCommands(t, connection, evidenceTime)
	if evaluateError := commands.Evaluate(context.Background(), "S-syntheticstudent01"); evaluateError != nil {
		t.Fatalf("rollback source evaluation failed: %v", evaluateError)
	}
	openCases, listError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if listError != nil || len(openCases) != 1 {
		t.Fatalf("rollback source case is missing: %#v %v", openCases, listError)
	}
	openCase := openCases[0]
	if _, setupError := connection.Exec(context.Background(), `
		CREATE FUNCTION reject_synthetic_attention_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'attention.concluded' THEN RAISE EXCEPTION 'synthetic attention audit rejection'; END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_synthetic_attention_audit BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_synthetic_attention_audit()`); setupError != nil {
		t.Fatal("synthetic attention audit rejection setup failed")
	}

	_, conclusionError := commands.Conclude(context.Background(), syntheticAttentionOwner(), "R-syntheticattentionrollback", openCase.ID, ConclusionInput{
		ConclusionCode: "contact_student", Reason: "Synthetic conclusion that must roll back", Version: openCase.Version,
	})
	if !errors.Is(conclusionError, ErrWriteFailed) {
		t.Fatalf("attention audit failure did not become a safe write failure: %v", conclusionError)
	}
	afterCases, afterListError := commands.ListCases(context.Background(), syntheticAttentionOwner())
	if afterListError != nil || len(afterCases) != 1 || !reflect.DeepEqual(openCase, afterCases[0]) {
		t.Fatalf("attention audit failure left a partial conclusion: before=%#v after=%#v error=%v", openCase, afterCases, afterListError)
	}
	var auditCount int // 被拒绝的成功审计不得留下行。
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'attention.concluded' AND object_id = $1`, openCase.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic rolled-back attention audit query failed")
	}
	if auditCount != 0 {
		t.Fatalf("attention audit failure left success evidence: %d", auditCount)
	}
}

type syntheticFollowUp struct {
	ID                string     // ID 是证据中唯一出现的跟进引用。
	StudentID         string     // StudentID 绑定一个当前学生范围。
	ContactedAt       time.Time  // ContactedAt 是可信 UTC 联系或尝试时间。
	ValidContact      bool       // ValidContact 重置普通无联系时钟。
	ReplyRequired     bool       // ReplyRequired 声明该线程等待学生回复。
	ReplyThreadID     *string    // ReplyThreadID 把连续尝试限制在同一事项。
	StudentRepliedAt  *time.Time // StudentRepliedAt 明确结束此前无回复序列。
	OverdueOccurrence bool       // OverdueOccurrence 是单调确认的逾期事实。
}

// --- 装配固定 UTC 时钟和 synthetic 身份的关注深模块 ---
func newAttentionTestCommands(t *testing.T, connection *pgx.Conn, now time.Time) *Commands {
	t.Helper()         // 装配失败归因到调用行为测试。
	identityCount := 0 // 同一命令实例内的事项和审计身份保持唯一。
	commands, createError := NewCommands(
		connection,
		func() time.Time { return now.UTC() }, // 所有规则只使用调用方注入的可信 UTC。
		func(prefix string) (string, error) {
			identityCount++
			return fmt.Sprintf("%s-syntheticattention%s%c", prefix, now.UTC().Format("150405"), rune('a'+identityCount)), nil
		},
	)
	if createError != nil {
		t.Fatalf("attention commands failed to initialize: %v", createError)
	}
	return commands // 行为测试只学习 Commands 公开 interface。
}

// --- 返回活动 synthetic 老板账号投影 ---
func syntheticAttentionOwner() auth.Account {
	return auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
}

// --- 返回绑定第一名员工档案的活动账号投影 ---
func syntheticAttentionStaff() auth.Account {
	staffProfileID := "T-syntheticcoach01"
	return auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
}

// --- 写入一条不含正文的合成跟进证据 ---
func insertSyntheticFollowUp(t *testing.T, connection *pgx.Conn, followUp syntheticFollowUp) {
	t.Helper() // fixture 失败归因到调用规则行为。
	actorID := "A-syntheticstaff01"
	if followUp.StudentID == "S-syntheticstudent03" { // 外部学生由其真实 synthetic 负责人产生事实。
		actorID = "A-syntheticstaff02"
	}
	_, insertError := connection.Exec(context.Background(), `
		INSERT INTO follow_up_records (
			id, student_id, contacted_at, channel, valid_contact, reply_required,
			reply_thread_id, student_replied_at, overdue_occurrence, version, created_by, updated_by
		) VALUES ($1, $2, $3, 'synthetic', $4, $5, $6, $7, $8, 1, $9, $9)`,
		followUp.ID, followUp.StudentID, followUp.ContactedAt.UTC(), followUp.ValidContact,
		followUp.ReplyRequired, followUp.ReplyThreadID, followUp.StudentRepliedAt, followUp.OverdueOccurrence, actorID,
	)
	if insertError != nil {
		t.Fatal("synthetic attention follow-up setup failed")
	}
}

// --- 写入一条只含内部引用的确认投诉事件 ---
func insertSyntheticComplaintEvent(t *testing.T, connection *pgx.Conn, eventID string, studentID string, occurredAt time.Time) {
	t.Helper() // fixture 失败归因到调用投诉行为。
	_, insertError := connection.Exec(context.Background(), `
		INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload, occurred_at)
		VALUES ($1, $2, 'complaint.confirmed', 'account', 'A-syntheticstaff01', '{}'::jsonb, $3)`,
		eventID, studentID, occurredAt.UTC(),
	)
	if insertError != nil {
		t.Fatal("synthetic complaint event setup failed")
	}
}

// --- 把员工提醒转换为学生身份集合 ---
func syntheticReminderStudentIDs(reminders []Reminder) map[string]bool {
	studentIDs := make(map[string]bool, len(reminders))
	for _, reminder := range reminders {
		studentIDs[reminder.StudentID] = true
	}
	return studentIDs
}

// --- 把一个事项的触发码转换为集合 ---
func syntheticTriggerSet(attentionCase Case) map[string]bool {
	triggerSet := make(map[string]bool, len(attentionCase.TriggerCodes))
	for _, triggerCode := range attentionCase.TriggerCodes {
		triggerSet[triggerCode] = true
	}
	return triggerSet
}

// --- 返回稳定排序的触发码供完整集合断言 ---
func syntheticSortedTriggers(attentionCase Case) []string {
	triggers := append([]string(nil), attentionCase.TriggerCodes...)
	sort.Strings(triggers)
	return triggers
}

// --- 提取一种对象类型的去重证据身份 ---
func syntheticEvidenceIDs(evidence []EvidenceRef, objectType string) map[string]bool {
	identities := make(map[string]bool)
	for _, reference := range evidence {
		if reference.ObjectType == objectType {
			identities[reference.ObjectID] = true
		}
	}
	return identities
}

// --- 把证据类型与身份组合成唯一键集合 ---
func syntheticEvidenceKeys(evidence []EvidenceRef) map[string]bool {
	keys := make(map[string]bool, len(evidence))
	for _, reference := range evidence {
		keys[reference.ObjectType+":"+reference.ObjectID] = true
	}
	return keys
}

// --- 从老板可见历史中找到一个关注事项 ---
func findSyntheticAttentionCase(t *testing.T, cases []Case, caseID string) Case {
	t.Helper() // 缺失事项归因到调用行为。
	for _, attentionCase := range cases {
		if attentionCase.ID == caseID {
			return attentionCase
		}
	}
	t.Fatalf("attention case %s was not returned", caseID)
	return Case{} // Fatalf 已终止当前测试；空值只满足编译器控制流。
}

// --- 从老板可见历史中找到一种状态的唯一事项 ---
func findSyntheticCaseByStatus(t *testing.T, cases []Case, status string) Case {
	t.Helper() // 缺失或重复状态归因到调用行为。
	matches := make([]Case, 0, 1)
	for _, attentionCase := range cases {
		if attentionCase.Status == status {
			matches = append(matches, attentionCase)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected one %s attention case, got %#v", status, matches)
	}
	return matches[0]
}

// --- 统计一种事项状态的数量 ---
func countSyntheticCasesByStatus(cases []Case, status string) int {
	count := 0
	for _, attentionCase := range cases {
		if attentionCase.Status == status {
			count++
		}
	}
	return count
}
