/*
跟进命令合同：通过真实 PostgreSQL 冻结学生派生下一步、版本、事件、审计和幂等提交边界。
所有账号、学生、时间和正文都是 synthetic；测试只调用未来 Commands 公开接口并读取随机测试 schema。
*/
package followups

import (
	"context" // 驱动公开跟进命令和测试事实查询。
	"errors"  // 比较不含对象正文的稳定领域失败。
	"testing" // 组织独立 synthetic 行为。
	"time"    // 注入固定 UTC 联系和下一次跟进时间。

	"github.com/jackc/pgx/v5" // 将真实随机 schema 连接装配到命令。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 使用认证模块已经验证的账号投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立独立 Foundation 与后续 migration schema。
)

// --- 创建跟进只形成一个事实并同步学生派生字段 ---
func TestCreateFollowUpRefreshesStudentDerivationAndReplaysOnce(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "followups") // 每次行为使用可完整清理的随机 schema。
	commands := newFollowUpTestCommands(t, connection)     // 固定时钟和身份使事件证据可重复。
	staffProfileID := "T-syntheticcoach01"                 // 绑定 seed 中第一名合成员工责任范围。
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	contactedAt := time.Date(2026, time.August, 5, 8, 0, 0, 0, time.UTC) // 联系事实早于固定命令时钟。
	nextFollowUpAt := time.Date(2026, time.August, 8, 2, 0, 0, 0, time.UTC)
	nextAction := "Synthetic resume revision" // 正文只应进入获准业务表，不进入审计或事件 payload。
	replyThreadID := "RT-syntheticreply01"    // 待回复事实绑定一条不透明线程而不是自由文本。
	input := CreateInput{
		ContactedAt: contactedAt, Channel: "video", Content: "Synthetic initial follow-up content", ValidContact: true, ReplyRequired: true,
		ReplyThreadID: &replyThreadID, OverdueOccurrence: false, NextAction: &nextAction,
		NextFollowUpAt: &nextFollowUpAt,
	}

	created, createError := commands.Create(context.Background(), staff, "R-syntheticfollowupcreate01", "synthetic-key-followup-create-01", "S-syntheticstudent01", input)
	if createError != nil { // 首次有效意图必须形成完整跟进事实。
		t.Fatalf("owned follow-up create failed: %v", createError)
	}
	replayed, replayError := commands.Create(context.Background(), staff, "R-syntheticfollowupcreate02", "synthetic-key-followup-create-01", "S-syntheticstudent01", input)
	if replayError != nil || replayed.ID != created.ID { // 网络重试必须返回同一已提交对象。
		t.Fatalf("follow-up create retry did not replay: %#v %v", replayed, replayError)
	}
	if created.StudentID != "S-syntheticstudent01" || created.Version != 1 || !created.ValidContact || !created.ReplyRequired || created.ReplyThreadID == nil || *created.ReplyThreadID != replyThreadID {
		t.Fatalf("created follow-up lost confirmed evidence: %#v", created)
	}

	var derivedAction *string  // 读取学生聚合根当前派生下一步。
	var derivedTime *time.Time // 读取学生聚合根当前派生跟进时间。
	var studentVersion int64   // 派生变化必须推进学生乐观版本。
	var updatedBy string       // 修改来源必须保留当前逐人账号。
	if queryError := connection.QueryRow(context.Background(), `SELECT next_action, next_follow_up_at, version, updated_by FROM students WHERE id = 'S-syntheticstudent01'`).Scan(&derivedAction, &derivedTime, &studentVersion, &updatedBy); queryError != nil {
		t.Fatal("synthetic student derivation query failed")
	}
	if derivedAction == nil || *derivedAction != nextAction || derivedTime == nil || !derivedTime.Equal(nextFollowUpAt) || studentVersion != 2 || updatedBy != staff.ID {
		t.Fatalf("follow-up did not refresh student derivation: action=%v time=%v version=%d actor=%s", derivedAction, derivedTime, studentVersion, updatedBy)
	}

	var followUpCount int     // 重试后仍只能存在一条业务记录。
	var eventCount int        // 创建必须产生一条最小学生事件。
	var minimalEventCount int // 事件只允许引用、布尔和时间事实。
	var auditCount int        // 创建必须产生一条成功审计。
	var minimalAuditCount int // 审计只允许跟进和学生版本。
	var idempotencyCount int  // 幂等事实与业务写入同事务提交。
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM follow_up_records WHERE id = $1`, created.ID).Scan(&followUpCount); queryError != nil {
		t.Fatal("synthetic follow-up count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE payload ? 'follow_up_id' AND payload ? 'valid_contact' AND payload ? 'reply_required' AND NOT payload ? 'next_action') FROM student_events WHERE event_type = 'follow_up.created' AND student_id = 'S-syntheticstudent01'`).Scan(&eventCount, &minimalEventCount); queryError != nil {
		t.Fatal("synthetic follow-up event query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE metadata ? 'version' AND metadata ? 'student_version' AND NOT metadata ? 'next_action') FROM audit_events WHERE action = 'follow_up.created' AND object_id = $1`, created.ID).Scan(&auditCount, &minimalAuditCount); queryError != nil {
		t.Fatal("synthetic follow-up audit query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE actor_scope = $1 AND action = 'follow_up.create' AND idempotency_key = 'synthetic-key-followup-create-01'`, staff.ID).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("synthetic follow-up idempotency query failed")
	}
	if followUpCount != 1 || eventCount != 1 || minimalEventCount != 1 || auditCount != 1 || minimalAuditCount != 1 || idempotencyCount != 1 {
		t.Fatalf("follow-up create facts diverged: followups=%d events=%d minimal_events=%d audits=%d minimal_audits=%d idempotency=%d", followUpCount, eventCount, minimalEventCount, auditCount, minimalAuditCount, idempotencyCount)
	}
}

// --- 员工范围外与未知学生共享同一不存在反馈 ---
func TestStaffFollowUpScopeHidesForeignAndUnknownStudents(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "followups") // 范围断言不复用其他测试业务事实。
	commands := newFollowUpTestCommands(t, connection)     // 所有读取和创建都经过同一公开命令 seam。
	staffProfileID := "T-syntheticcoach01"                 // 当前员工只负责 student01 与 student02。
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	contactedAt := time.Date(2026, time.August, 5, 7, 0, 0, 0, time.UTC)
	input := CreateInput{ContactedAt: contactedAt, Channel: "phone", Content: "Synthetic scoped follow-up content", ValidContact: true, ReplyRequired: false}

	listed, listError := commands.List(context.Background(), staff, "S-syntheticstudent01")
	if listError != nil || len(listed) != 0 { // 本人范围内的空列表是合法结果。
		t.Fatalf("owned empty follow-up list failed: %#v %v", listed, listError)
	}
	if _, foreignError := commands.List(context.Background(), staff, "S-syntheticstudent03"); !errors.Is(foreignError, ErrNotFound) {
		t.Fatalf("foreign follow-up list exposed student existence: %v", foreignError)
	}
	if _, unknownError := commands.List(context.Background(), staff, "S-syntheticunknown01"); !errors.Is(unknownError, ErrNotFound) {
		t.Fatalf("unknown follow-up list used a different failure: %v", unknownError)
	}
	if _, foreignError := commands.Create(context.Background(), staff, "R-syntheticfollowupscope01", "synthetic-key-followup-scope-01", "S-syntheticstudent03", input); !errors.Is(foreignError, ErrNotFound) {
		t.Fatalf("foreign follow-up create exposed student existence: %v", foreignError)
	}
	if _, unknownError := commands.Create(context.Background(), staff, "R-syntheticfollowupscope02", "synthetic-key-followup-scope-02", "S-syntheticunknown01", input); !errors.Is(unknownError, ErrNotFound) {
		t.Fatalf("unknown follow-up create used a different failure: %v", unknownError)
	}
}

// --- 协作老师可新增跟进，操作者不可伪造，下一位老师必须是当前协作成员 ---
func TestCollaboratorCreatesAttributedFollowUpWithActiveNextTeacher(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "followups")
	commands := newFollowUpTestCommands(t, connection)
	primaryStaffID := "T-syntheticcoach01"
	collaboratorStaffID := "T-syntheticcoach02"
	primary := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &primaryStaffID}
	collaborator := auth.Account{ID: "A-syntheticstaff02", Role: "staff", State: "active", StaffProfileID: &collaboratorStaffID}
	contactedAt := time.Date(2026, time.August, 15, 6, 30, 0, 0, time.UTC)
	nextAt := time.Date(2026, time.August, 18, 6, 0, 0, 0, time.UTC)
	nextAction := "Synthetic resume review"

	if _, invalidNextError := commands.Create(t.Context(), primary, "R-syntheticnextstaff01", "synthetic-key-next-staff-01", "S-syntheticstudent01", CreateInput{
		ContactedAt: contactedAt, Channel: "phone", Content: "Synthetic call before collaboration", ValidContact: true,
		NextAction: &nextAction, NextFollowUpAt: &nextAt, NextStaffID: &collaboratorStaffID,
	}); !errors.Is(invalidNextError, ErrInvalidInput) {
		t.Fatalf("follow-up accepted a next teacher outside current collaboration: %v", invalidNextError)
	}
	if _, insertError := connection.Exec(t.Context(), `INSERT INTO student_staff_assignments (id, student_id, staff_profile_id, assignment_role, created_by_account_id) VALUES ('SA-syntheticfollowcollab01', 'S-syntheticstudent01', $1, 'collaborator', 'A-syntheticowner01')`, collaboratorStaffID); insertError != nil {
		t.Fatal("follow-up collaborator fixture setup failed")
	}
	created, createError := commands.Create(t.Context(), collaborator, "R-syntheticnextstaff02", "synthetic-key-next-staff-02", "S-syntheticstudent01", CreateInput{
		ContactedAt: contactedAt, Channel: "video", Content: "Synthetic collaborator completed resume review", ValidContact: true,
		NextAction: &nextAction, NextFollowUpAt: &nextAt, NextStaffID: &primaryStaffID,
	})
	if createError != nil {
		t.Fatalf("active collaborator could not create follow-up: %v", createError)
	}
	if created.CreatedByAccountID != collaborator.ID || created.CreatedByName != "Synthetic Staff Two" || created.NextStaffID == nil || *created.NextStaffID != primaryStaffID || created.NextStaffName == nil || *created.NextStaffName != "Synthetic Coach One" {
		t.Fatalf("follow-up attribution or next teacher diverged: %#v", created)
	}
	listed, listError := commands.List(t.Context(), primary, "S-syntheticstudent01")
	if listError != nil || len(listed) != 1 || listed[0].CreatedByAccountID != collaborator.ID {
		t.Fatalf("primary teacher could not read attributed collaboration timeline: items=%#v error=%v", listed, listError)
	}
}

// --- 最新联系时间决定学生派生事实，更新和删除都受版本保护 ---
func TestUpdateAndDeleteFollowUpRebuildLatestStudentDerivation(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "followups") // 每一步都在同一学生聚合根上形成有序事实。
	commands := newFollowUpTestCommands(t, connection)     // 测试只依赖公开 CRUD 命令。
	staffProfileID := "T-syntheticcoach01"                 // 使用 seed 中 student01 的当前负责人。
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	olderContactedAt := time.Date(2026, time.August, 1, 8, 0, 0, 0, time.UTC)
	newerContactedAt := time.Date(2026, time.August, 2, 8, 0, 0, 0, time.UTC)
	promotedContactedAt := time.Date(2026, time.August, 3, 8, 0, 0, 0, time.UTC)
	olderNextAt := time.Date(2026, time.August, 10, 2, 0, 0, 0, time.UTC)
	newerNextAt := time.Date(2026, time.August, 11, 2, 0, 0, 0, time.UTC)
	promotedNextAt := time.Date(2026, time.August, 12, 2, 0, 0, 0, time.UTC)
	olderAction := "Synthetic older action"       // 第一条跟进先成为派生来源。
	newerAction := "Synthetic newer action"       // 第二条更晚联系覆盖派生来源。
	promotedAction := "Synthetic promoted action" // 更新后的第一条成为最新来源。

	older, olderError := commands.Create(context.Background(), staff, "R-syntheticfollowuporder01", "synthetic-key-followup-order-01", "S-syntheticstudent01", CreateInput{
		ContactedAt: olderContactedAt, Channel: "phone", Content: "Synthetic older follow-up content", ValidContact: true, ReplyRequired: false,
		NextAction: &olderAction, NextFollowUpAt: &olderNextAt,
	})
	if olderError != nil { // 第一条跟进必须建立初始派生值。
		t.Fatalf("older synthetic follow-up create failed: %v", olderError)
	}
	newer, newerError := commands.Create(context.Background(), staff, "R-syntheticfollowuporder02", "synthetic-key-followup-order-02", "S-syntheticstudent01", CreateInput{
		ContactedAt: newerContactedAt, Channel: "video", Content: "Synthetic newer follow-up content", ValidContact: true, ReplyRequired: false,
		NextAction: &newerAction, NextFollowUpAt: &newerNextAt,
	})
	if newerError != nil { // 更晚联系必须成为新的派生来源。
		t.Fatalf("newer synthetic follow-up create failed: %v", newerError)
	}
	updated, updateError := commands.Update(context.Background(), staff, "R-syntheticfollowuporder03", older.ID, UpdateInput{
		ContactedAt: promotedContactedAt, Channel: "video", Content: "Synthetic promoted follow-up content", ValidContact: true, ReplyRequired: false,
		NextAction: &promotedAction, NextFollowUpAt: &promotedNextAt, Version: older.Version,
	})
	if updateError != nil || updated.Version != 2 { // 修改推进跟进版本并重新排序派生来源。
		t.Fatalf("synthetic follow-up promotion failed: %#v %v", updated, updateError)
	}
	if _, staleError := commands.Update(context.Background(), staff, "R-syntheticfollowuporder04", older.ID, UpdateInput{
		ContactedAt: olderContactedAt, Channel: "phone", Content: "Synthetic stale follow-up content", ValidContact: true, ReplyRequired: false,
		NextAction: &olderAction, NextFollowUpAt: &olderNextAt, Version: older.Version,
	}); !errors.Is(staleError, ErrVersionConflict) {
		t.Fatalf("stale follow-up update was accepted: %v", staleError)
	}
	if deleteError := commands.Delete(context.Background(), staff, "R-syntheticfollowuporder05", older.ID, updated.Version); deleteError != nil {
		t.Fatalf("latest synthetic follow-up delete failed: %v", deleteError)
	}

	listed, listError := commands.List(context.Background(), staff, "S-syntheticstudent01")
	if listError != nil || len(listed) != 1 || listed[0].ID != newer.ID { // 删除后只保留未删除的较新原始记录。
		t.Fatalf("follow-up delete left unexpected list: %#v %v", listed, listError)
	}
	var derivedAction *string  // 删除最新来源后应回退到仍存在记录。
	var derivedTime *time.Time // 时间与下一步必须来自同一条记录。
	var studentVersion int64   // 两次创建、一次更新和一次删除各推进一次版本。
	if queryError := connection.QueryRow(context.Background(), `SELECT next_action, next_follow_up_at, version FROM students WHERE id = 'S-syntheticstudent01'`).Scan(&derivedAction, &derivedTime, &studentVersion); queryError != nil {
		t.Fatal("synthetic rebuilt student derivation query failed")
	}
	if derivedAction == nil || *derivedAction != newerAction || derivedTime == nil || !derivedTime.Equal(newerNextAt) || studentVersion != 5 {
		t.Fatalf("follow-up delete did not rebuild latest derivation: action=%v time=%v version=%d", derivedAction, derivedTime, studentVersion)
	}

	var eventCount int // 每个已提交 CRUD 动作形成一条学生事件。
	var auditCount int // 每个已提交 CRUD 动作形成一条最小审计。
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_events WHERE student_id = 'S-syntheticstudent01' AND event_type IN ('follow_up.created', 'follow_up.updated', 'follow_up.deleted')`).Scan(&eventCount); queryError != nil {
		t.Fatal("synthetic follow-up lifecycle event count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE object_type = 'follow_up' AND object_id IN ($1, $2) AND action IN ('follow_up.created', 'follow_up.updated', 'follow_up.deleted')`, older.ID, newer.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic follow-up lifecycle audit count failed")
	}
	if eventCount != 4 || auditCount != 4 { // 被拒绝的旧版本更新不能留下成功事实。
		t.Fatalf("follow-up lifecycle evidence diverged: events=%d audits=%d", eventCount, auditCount)
	}
}

// --- 派生字段、事件或审计任一步骤失败都必须回滚整笔创建 ---
func TestCreateFollowUpRollsBackEveryAtomicWriteOnInjectedFailure(t *testing.T) {
	failureSetups := []struct {
		name string // name 说明被拒绝的提交步骤。
		sql  string // sql 只在当前随机 synthetic schema 安装一次故障触发器。
	}{
		{
			name: "student derivation",
			sql: `
				CREATE FUNCTION reject_synthetic_followup_derivation() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF NEW.id = 'S-syntheticstudent01' AND NEW.next_action IS NOT NULL THEN
						RAISE EXCEPTION 'synthetic derivation rejection';
					END IF;
					RETURN NEW;
				END;
				$$;
				CREATE TRIGGER reject_synthetic_followup_derivation BEFORE UPDATE ON students
				FOR EACH ROW EXECUTE FUNCTION reject_synthetic_followup_derivation()`,
		},
		{
			name: "student event",
			sql: `
				CREATE FUNCTION reject_synthetic_followup_event() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF NEW.event_type = 'follow_up.created' THEN
						RAISE EXCEPTION 'synthetic event rejection';
					END IF;
					RETURN NEW;
				END;
				$$;
				CREATE TRIGGER reject_synthetic_followup_event BEFORE INSERT ON student_events
				FOR EACH ROW EXECUTE FUNCTION reject_synthetic_followup_event()`,
		},
		{
			name: "minimal audit",
			sql: `
				CREATE FUNCTION reject_synthetic_followup_audit() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF NEW.action = 'follow_up.created' THEN
						RAISE EXCEPTION 'synthetic audit rejection';
					END IF;
					RETURN NEW;
				END;
				$$;
				CREATE TRIGGER reject_synthetic_followup_audit BEFORE INSERT ON audit_events
				FOR EACH ROW EXECUTE FUNCTION reject_synthetic_followup_audit()`,
		},
	}

	for _, failureSetup := range failureSetups { // 三种失败分别使用独立 schema，避免触发器互相遮蔽。
		t.Run(failureSetup.name, func(t *testing.T) {
			connection := testsupport.OpenDatabase(t, "followups") // 子测试退出时精确删除本 schema。
			commands := newFollowUpTestCommands(t, connection)     // 故障注入发生在真实命令事务内部。
			if _, setupError := connection.Exec(context.Background(), failureSetup.sql); setupError != nil {
				t.Fatal("synthetic follow-up failure setup failed")
			}
			staffProfileID := "T-syntheticcoach01" // 让失败发生在授权通过之后的写入阶段。
			staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
			contactedAt := time.Date(2026, time.August, 5, 9, 0, 0, 0, time.UTC)
			nextAt := time.Date(2026, time.August, 9, 2, 0, 0, 0, time.UTC)
			nextAction := "Synthetic action that must roll back"

			_, createError := commands.Create(context.Background(), staff, "R-syntheticfollowuprollback01", "synthetic-key-followup-rollback-01", "S-syntheticstudent01", CreateInput{
				ContactedAt: contactedAt, Channel: "video", Content: "Synthetic rollback follow-up content", ValidContact: true, ReplyRequired: false,
				NextAction: &nextAction, NextFollowUpAt: &nextAt,
			})
			if !errors.Is(createError, ErrWriteFailed) { // SQL 细节必须收敛为安全写失败。
				t.Fatalf("injected failure did not become safe write failure: %v", createError)
			}

			var followUpCount int     // 主记录必须回滚。
			var eventCount int        // 事件必须回滚或从未写入。
			var auditCount int        // 审计必须回滚或从未写入。
			var idempotencyCount int  // 失败意图不得被缓存成成功重放。
			var derivedAction *string // 学生派生字段保持 seed 的空值。
			var derivedTime *time.Time
			var studentVersion int64 // 学生版本保持初始值 1。
			if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM follow_up_records`).Scan(&followUpCount); queryError != nil {
				t.Fatal("synthetic rolled-back follow-up count failed")
			}
			if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_events WHERE event_type = 'follow_up.created'`).Scan(&eventCount); queryError != nil {
				t.Fatal("synthetic rolled-back event count failed")
			}
			if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'follow_up.created'`).Scan(&auditCount); queryError != nil {
				t.Fatal("synthetic rolled-back audit count failed")
			}
			if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE action = 'follow_up.create'`).Scan(&idempotencyCount); queryError != nil {
				t.Fatal("synthetic rolled-back idempotency count failed")
			}
			if queryError := connection.QueryRow(context.Background(), `SELECT next_action, next_follow_up_at, version FROM students WHERE id = 'S-syntheticstudent01'`).Scan(&derivedAction, &derivedTime, &studentVersion); queryError != nil {
				t.Fatal("synthetic rolled-back student derivation query failed")
			}
			if followUpCount != 0 || eventCount != 0 || auditCount != 0 || idempotencyCount != 0 || derivedAction != nil || derivedTime != nil || studentVersion != 1 {
				t.Fatalf("injected failure left partial facts: followups=%d events=%d audits=%d idempotency=%d action=%v time=%v student_version=%d", followUpCount, eventCount, auditCount, idempotencyCount, derivedAction, derivedTime, studentVersion)
			}
		})
	}
}

// --- 装配固定 UTC 时钟和 synthetic 身份的跟进深模块 ---
func newFollowUpTestCommands(t *testing.T, connection *pgx.Conn) *Commands {
	t.Helper()         // 装配错误归因到调用行为测试。
	identityCount := 0 // 每次调用产生互不冲突且可辨认的合成身份。
	commands, createError := NewCommands(
		connection,
		func() time.Time { return time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC) }, // 统一事件与审计时间来源。
		func(prefix string) (string, error) {
			identityCount++ // 同一命令内的跟进、事件和审计身份保持唯一。
			return prefix + "-syntheticfollowidentity" + string(rune('a'+identityCount)), nil
		},
	)
	if createError != nil { // 缺失任一依赖时测试必须在业务动作前失败。
		t.Fatalf("follow-up commands failed to initialize: %v", createError)
	}
	return commands // 行为测试只学习 Commands 公开接口。
}
