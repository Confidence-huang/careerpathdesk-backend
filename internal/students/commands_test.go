/*
学生命令测试：通过真实 PostgreSQL 验证员工对象范围在目标读取前收敛为同一不存在反馈。
后续工作量边界、版本和原子审计行为沿同一个 Commands 公开接口逐条 RED→GREEN。
*/
package students

import (
	"context" // 驱动公开学生命令。
	"errors"  // 比较稳定领域失败分类。
	"fmt"     // 生成固定且互不冲突的合成工作量边界学生身份。
	"testing" // 组织独立 synthetic 行为。
	"time"    // 注入固定 UTC 时间。

	"github.com/jackc/pgx/v5" // 把真实测试连接装配到命令。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 使用认证模块已经验证的账号投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立随机 Foundation 合成 schema。
)

// --- 安全沟通风格只随当前学生范围返回，且写后投影不丢失 ---
func TestCommunicationStyleFollowsOwnerAndStaffStudentScope(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	insertSyntheticStudentAssessment(t, connection, "01", "S-syntheticstudent01", "direct_goal", "更容易响应明确目标、结果标准和时间节点。")
	insertSyntheticStudentAssessment(t, connection, "03", "S-syntheticstudent03", "evidence_planning", "更容易响应清晰依据、参考案例和可复核的规划。")

	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	ownerPage, ownerListError := commands.List(context.Background(), owner, 30, "")
	if ownerListError != nil || len(ownerPage.Students) != 4 {
		t.Fatalf("owner communication-style list failed: count=%d error=%v", len(ownerPage.Students), ownerListError)
	}
	ownerStudents := studentsByID(ownerPage.Students)
	if ownerStudents["S-syntheticstudent01"].CommunicationStyle == nil || ownerStudents["S-syntheticstudent01"].CommunicationStyle.Code != "tiger" {
		t.Fatal("owner list lost the assessed tiger projection")
	}
	if ownerStudents["S-syntheticstudent03"].CommunicationStyle == nil || ownerStudents["S-syntheticstudent03"].CommunicationStyle.Code != "owl" {
		t.Fatal("owner list lost the assessed owl projection")
	}
	if ownerStudents["S-syntheticstudent02"].CommunicationStyle != nil {
		t.Fatal("unassessed student did not remain null")
	}

	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	staffPage, staffListError := commands.List(context.Background(), staff, 30, "")
	if staffListError != nil || len(staffPage.Students) != 2 {
		t.Fatalf("staff communication-style list escaped scope: count=%d error=%v", len(staffPage.Students), staffListError)
	}
	staffStudents := studentsByID(staffPage.Students)
	if staffStudents["S-syntheticstudent01"].CommunicationStyle == nil || staffStudents["S-syntheticstudent01"].CommunicationStyle.Label != "老虎型 · 目标推进" || staffStudents["S-syntheticstudent02"].CommunicationStyle != nil {
		t.Fatal("staff list did not preserve assessed/null projections")
	}
	if _, foreignError := commands.Get(context.Background(), staff, "S-syntheticstudent03"); !errors.Is(foreignError, ErrNotFound) {
		t.Fatalf("assessed foreign student existence was exposed: %v", foreignError)
	}
	if _, unknownError := commands.Get(context.Background(), staff, "S-syntheticunknown01"); !errors.Is(unknownError, ErrNotFound) {
		t.Fatalf("unknown student used a different failure: %v", unknownError)
	}

	updated, updateError := commands.Update(context.Background(), staff, "R-syntheticstyleupdate1", "S-syntheticstudent01", UpdateInput{Name: "Synthetic Student Alpha", Version: 1})
	if updateError != nil || updated.CommunicationStyle == nil || updated.CommunicationStyle.Code != "tiger" {
		t.Fatalf("student update lost communication style: present=%t error=%v", updated.CommunicationStyle != nil, updateError)
	}
	targetStaffID := "T-syntheticcoach02"
	assigned, assignError := commands.Assign(context.Background(), owner, "R-syntheticstyleassign1", "S-syntheticstudent01", AssignInput{OwnerStaffID: &targetStaffID, Version: updated.Version})
	if assignError != nil || assigned.CommunicationStyle == nil || assigned.CommunicationStyle.Code != "tiger" {
		t.Fatalf("student assignment lost communication style: present=%t error=%v", assigned.CommunicationStyle != nil, assignError)
	}
}

// --- 员工只能列出和读取本人负责的学生 ---
func TestStaffStudentScopeHidesForeignAndUnknownStudents(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}

	page, listError := commands.List(context.Background(), staff, 30, "")
	if listError != nil {
		t.Fatalf("owned student list failed: %v", listError)
	}
	listed := page.Students
	if len(listed) != 2 || listed[0].OwnerStaffID == nil || *listed[0].OwnerStaffID != staffProfileID || listed[1].OwnerStaffID == nil || *listed[1].OwnerStaffID != staffProfileID {
		t.Fatalf("staff list escaped owned scope: %#v", listed)
	}
	if _, foreignError := commands.Get(context.Background(), staff, "S-syntheticstudent03"); !errors.Is(foreignError, ErrNotFound) {
		t.Fatalf("foreign student existence was exposed: %v", foreignError)
	}
	if _, unknownError := commands.Get(context.Background(), staff, "S-syntheticunknown01"); !errors.Is(unknownError, ErrNotFound) {
		t.Fatalf("unknown student used a different failure: %v", unknownError)
	}
}

// --- 多名老师可以反复协作和交接，当前权限只来自 active 关系且全部历史保留 ---
func TestCollaboratorsShareScopeAndRepeatedTransferPreservesHistory(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	primaryStaffID := "T-syntheticcoach01"
	collaboratorStaffID := "T-syntheticcoach02"
	primary := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &primaryStaffID}
	collaborator := auth.Account{ID: "A-syntheticstaff02", Role: "staff", State: "active", StaffProfileID: &collaboratorStaffID}
	studentID := "S-syntheticstudent01"

	if _, beforeError := commands.Get(t.Context(), collaborator, studentID); !errors.Is(beforeError, ErrNotFound) {
		t.Fatalf("unrelated teacher could read student before collaboration: %v", beforeError)
	}
	withCollaborator, addError := commands.SetCollaborator(t.Context(), owner, "R-syntheticcollab-add01", studentID, CollaboratorInput{StaffProfileID: collaboratorStaffID, Version: 1}, true)
	if addError != nil || len(withCollaborator.Assignments) != 2 {
		t.Fatalf("collaborator was not added: assignments=%#v error=%v", withCollaborator.Assignments, addError)
	}
	if _, readError := commands.Get(t.Context(), collaborator, studentID); readError != nil {
		t.Fatalf("active collaborator could not read student: %v", readError)
	}

	withoutCollaborator, removeError := commands.SetCollaborator(t.Context(), owner, "R-syntheticcollab-remove01", studentID, CollaboratorInput{StaffProfileID: collaboratorStaffID, Version: withCollaborator.Version}, false)
	if removeError != nil || len(withoutCollaborator.Assignments) != 1 {
		t.Fatalf("collaborator was not ended: assignments=%#v error=%v", withoutCollaborator.Assignments, removeError)
	}
	if _, removedReadError := commands.Get(t.Context(), collaborator, studentID); !errors.Is(removedReadError, ErrNotFound) {
		t.Fatalf("ended collaborator retained current scope: %v", removedReadError)
	}

	rejoined, rejoinError := commands.SetCollaborator(t.Context(), owner, "R-syntheticcollab-add02", studentID, CollaboratorInput{StaffProfileID: collaboratorStaffID, Version: withoutCollaborator.Version}, true)
	if rejoinError != nil {
		t.Fatalf("former collaborator could not rejoin: %v", rejoinError)
	}
	transferred, transferError := commands.Assign(t.Context(), owner, "R-syntheticcollab-transfer01", studentID, AssignInput{OwnerStaffID: &collaboratorStaffID, Version: rejoined.Version})
	if transferError != nil || transferred.OwnerStaffID == nil || *transferred.OwnerStaffID != collaboratorStaffID || len(transferred.Assignments) != 2 {
		t.Fatalf("collaborator could not become primary: student=%#v error=%v", transferred, transferError)
	}
	if _, readError := commands.Get(t.Context(), primary, studentID); readError != nil {
		t.Fatalf("former primary was not retained automatically as collaborator: %v", readError)
	}

	var activePrimary, activeCollaborators, totalHistory int
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE assignment_role = 'primary' AND ended_at IS NULL), count(*) FILTER (WHERE assignment_role = 'collaborator' AND ended_at IS NULL), count(*) FROM student_staff_assignments WHERE student_id = $1`, studentID).Scan(&activePrimary, &activeCollaborators, &totalHistory); queryError != nil {
		t.Fatal("collaboration history query failed")
	}
	if activePrimary != 1 || activeCollaborators != 1 || totalHistory != 5 {
		t.Fatalf("collaboration history diverged: primary=%d collaborators=%d history=%d", activePrimary, activeCollaborators, totalHistory)
	}
}

// --- 迁移前只有 owner 缓存的学生首次加协作者时仍保留原老师范围 ---
func TestFirstCollaboratorMaterializesLegacyPrimary(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	primaryStaffID := "T-syntheticcoach01"
	collaboratorStaffID := "T-syntheticcoach02"
	primary := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &primaryStaffID}
	studentID := "S-syntheticstudent02"
	if _, deleteError := connection.Exec(t.Context(), `DELETE FROM student_staff_assignments WHERE student_id = $1`, studentID); deleteError != nil {
		t.Fatal("legacy collaboration fixture setup failed")
	}
	updated, addError := commands.SetCollaborator(t.Context(), owner, "R-syntheticlegacycollab01", studentID, CollaboratorInput{StaffProfileID: collaboratorStaffID, Version: 1}, true)
	if addError != nil || len(updated.Assignments) != 2 {
		t.Fatalf("legacy primary was not materialized: assignments=%#v error=%v", updated.Assignments, addError)
	}
	if _, readError := commands.Get(t.Context(), primary, studentID); readError != nil {
		t.Fatalf("legacy primary lost scope after collaborator addition: %v", readError)
	}
}

// --- 学生修改推进版本、写最小审计并拒绝旧页面覆盖 ---
func TestUpdateStudentIsVersionedAndAuditedAtomically(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	nextAction := "Synthetic next coaching action"

	updated, updateError := commands.Update(context.Background(), staff, "R-syntheticstudentupdate01", "S-syntheticstudent01", UpdateInput{
		Name: "Synthetic Student Alpha Updated", NextAction: &nextAction, Version: 1,
	})
	if updateError != nil {
		t.Fatalf("owned student update failed: %v", updateError)
	}
	if updated.Version != 2 || updated.Name != "Synthetic Student Alpha Updated" || updated.NextAction == nil || *updated.NextAction != nextAction {
		t.Fatalf("unexpected updated student projection: %#v", updated)
	}
	if _, staleError := commands.Update(context.Background(), staff, "R-syntheticstudentupdate02", "S-syntheticstudent01", UpdateInput{
		Name: "Stale Synthetic Name", NextAction: &nextAction, Version: 1,
	}); !errors.Is(staleError, ErrVersionConflict) {
		t.Fatalf("stale student update was not rejected: %v", staleError)
	}
	current, getError := commands.Get(context.Background(), staff, "S-syntheticstudent01")
	if getError != nil || current.Name != updated.Name || current.Version != updated.Version {
		t.Fatalf("stale update changed current student: %#v %v", current, getError)
	}
	var auditCount int
	var metadata string
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), min(metadata::text) FROM audit_events WHERE action = 'student.updated' AND object_id = 'S-syntheticstudent01'`).Scan(&auditCount, &metadata); queryError != nil {
		t.Fatal("synthetic student audit query failed")
	}
	if auditCount != 1 || metadata != `{"version": 2}` { // 审计只保留版本，不复制姓名、联系方式或下一步正文。
		t.Fatalf("student update audit was not minimal: count=%d metadata=%q", auditCount, metadata)
	}
}

// --- 老板和协作老师都可渐进补全问卷资料，只有姓名强制必填且现居地独立于目标城市 ---
func TestUpdateStudentProfileOnlyRequiresNameAndKeepsCurrentLocationDistinct(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	value := func(text string) *string { return &text }
	updated, updateError := commands.Update(t.Context(), staff, "R-syntheticprofilefull01", "S-syntheticstudent01", UpdateInput{
		Name: "Synthetic Complete Profile", Phone: value("13800000000"), Email: value("synthetic@example.invalid"),
		Wechat: value("synthetic-wechat"), School: value("Synthetic University"), Major: value("Computer Science"), Grade: value("大三"),
		CurrentLocation: value("合肥"), TargetCity: value("上海"), TargetPosition: value("Backend Intern"), ExpectedSalary: value("面议"),
		JobIntention: value("Synthetic job intention"), ProjectExperience: value("Synthetic project"), InternshipExperience: value("Synthetic internship"),
		Skills: value("Go, PostgreSQL"), Certificates: value("Synthetic certificate"), Version: 1,
	})
	if updateError != nil {
		t.Fatalf("full optional profile update failed: %v", updateError)
	}
	if updated.CurrentLocation == nil || *updated.CurrentLocation != "合肥" || updated.TargetCity == nil || *updated.TargetCity != "上海" || updated.School == nil || updated.Skills == nil {
		t.Fatalf("full profile fields were not preserved independently: %#v", updated)
	}
	if _, emptyNameError := commands.Update(t.Context(), staff, "R-syntheticprofilefull02", "S-syntheticstudent01", UpdateInput{Name: "  ", Version: updated.Version}); !errors.Is(emptyNameError, ErrInvalidInput) {
		t.Fatalf("empty required name was accepted: %v", emptyNameError)
	}
	minimal, minimalError := commands.Update(t.Context(), staff, "R-syntheticprofilefull03", "S-syntheticstudent01", UpdateInput{Name: "Synthetic Name Only", Version: updated.Version})
	if minimalError != nil || minimal.Name != "Synthetic Name Only" {
		t.Fatalf("name-only profile update failed: student=%#v error=%v", minimal, minimalError)
	}
}

// --- 审计失败必须让学生正文和版本一起回滚 ---
func TestUpdateStudentRollsBackWhenAuditCannotBeWritten(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	if _, setupError := connection.Exec(context.Background(), `
		CREATE FUNCTION reject_synthetic_student_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'student.updated' THEN
				RAISE EXCEPTION 'synthetic audit rejection';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_synthetic_student_audit
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_synthetic_student_audit()`); setupError != nil {
		t.Fatal("synthetic audit rejection setup failed")
	}

	_, updateError := commands.Update(context.Background(), staff, "R-syntheticrollback01", "S-syntheticstudent01", UpdateInput{
		Name: "Synthetic Name That Must Roll Back", Version: 1,
	})
	if !errors.Is(updateError, ErrWriteFailed) {
		t.Fatalf("audit rejection did not become a safe write failure: %v", updateError)
	}
	current, getError := commands.Get(context.Background(), staff, "S-syntheticstudent01")
	if getError != nil || current.Name != "Synthetic Student Alpha" || current.Version != 1 {
		t.Fatalf("audit rejection left a partial student update: %#v %v", current, getError)
	}
}

// --- 老板可调整第十六名学生的主负责人 ---
func TestAssignSixteenthStudentWithoutCapacityLimit(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	targetStaffID := "T-syntheticcoach02"
	for index := 0; index < 14; index++ { // seed 已有一名服务中学生，再加入十四名形成十五人基线。
		studentID := fmt.Sprintf("S-syntheticcapacity%02d", index)
		if _, insertError := connection.Exec(context.Background(), `
			INSERT INTO students (id, name, service_stage, job_search_stage, owner_staff_id, source_kind, created_by, updated_by, processing_basis, privacy_notice_version, privacy_notice_delivered_at)
			VALUES ($1, 'Synthetic Capacity Student', '服务中', '未开始', $2, 'staff', 'A-syntheticowner01', 'A-syntheticowner01', 'service_contract', 'privacy-notice-v1', statement_timestamp())`, studentID, targetStaffID); insertError != nil {
			t.Fatal("synthetic capacity setup failed")
		}
	}
	targetStudentID := "S-syntheticcapacitytarget"
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO students (id, name, service_stage, job_search_stage, owner_staff_id, source_kind, created_by, updated_by, processing_basis, privacy_notice_version, privacy_notice_delivered_at)
		VALUES ($1, 'Synthetic Capacity Target', '服务中', '未开始', NULL, 'staff', 'A-syntheticowner01', 'A-syntheticowner01', 'service_contract', 'privacy-notice-v1', statement_timestamp())`, targetStudentID); insertError != nil {
		t.Fatal("synthetic capacity target setup failed")
	}
	assigned, assignError := commands.Assign(context.Background(), owner, "R-syntheticcapacity01", targetStudentID, AssignInput{
		OwnerStaffID: &targetStaffID, Version: 1,
	})
	if assignError != nil {
		t.Fatalf("sixteenth in-service assignment failed: %v", assignError)
	}
	current, getError := commands.Get(context.Background(), owner, targetStudentID)
	if getError != nil || assigned.OwnerStaffID == nil || *assigned.OwnerStaffID != targetStaffID || assigned.Version != 2 || current.OwnerStaffID == nil || *current.OwnerStaffID != targetStaffID || current.Version != 2 {
		t.Fatalf("sixteenth assignment did not commit exactly once: assigned=%#v current=%#v error=%v", assigned, current, getError)
	}
	var auditCount int
	var activePrimaryCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'student.assigned' AND object_id = $1`, targetStudentID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic capacity audit count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_staff_assignments WHERE student_id = $1 AND assignment_role = 'primary' AND ended_at IS NULL`, targetStudentID).Scan(&activePrimaryCount); queryError != nil {
		t.Fatal("synthetic capacity primary count failed")
	}
	if auditCount != 1 || activePrimaryCount != 1 {
		t.Fatalf("sixteenth assignment facts diverged: audits=%d active_primary=%d", auditCount, activePrimaryCount)
	}
}

// --- 员工已有十五名当前学生时仍可创建第十六名 ---
func TestStaffCreatesSixteenthStudentWithoutCapacityLimit(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	var existing int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM students WHERE owner_staff_id = $1`, staffProfileID).Scan(&existing); queryError != nil {
		t.Fatal("synthetic create baseline query failed")
	}
	for index := existing; index < 15; index++ {
		studentID := fmt.Sprintf("S-syntheticcreatecap%02d", index)
		if _, insertError := connection.Exec(context.Background(), `
			INSERT INTO students (id, name, service_stage, job_search_stage, owner_staff_id, source_kind, created_by, updated_by, processing_basis, privacy_notice_version, privacy_notice_delivered_at)
			VALUES ($1, 'Synthetic Create Capacity Student', '服务中', '未开始', $2, 'staff', $3, $3, 'service_contract', 'privacy-notice-v1', statement_timestamp())`, studentID, staffProfileID, staff.ID); insertError != nil {
			t.Fatal("synthetic create capacity setup failed")
		}
	}

	created, createError := commands.Create(context.Background(), staff, "R-syntheticcreatecapacity01", "synthetic-key-create-capacity-01", CreateInput{
		Name:            "Synthetic Sixteenth Student",
		ProcessingBasis: "service_contract", PrivacyNoticeVersion: "privacy-notice-v1", PrivacyNoticeDelivered: true,
	})
	if createError != nil {
		t.Fatalf("sixteenth in-service creation failed: %v", createError)
	}
	var currentStudentCount, studentCount, auditCount, idempotencyCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM students WHERE owner_staff_id = $1`, staffProfileID).Scan(&currentStudentCount); queryError != nil {
		t.Fatal("synthetic create final count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM students WHERE id = $1 AND version = 1`, created.ID).Scan(&studentCount); queryError != nil {
		t.Fatal("synthetic create student count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'student.created' AND object_id = $1 AND metadata = '{"processing_basis":"service_contract","privacy_notice_version":"privacy-notice-v1"}'::jsonb`, created.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic create audit count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE action = 'student.create' AND resource_id = $1`, created.ID).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("synthetic create idempotency count failed")
	}
	if created.OwnerStaffID == nil || *created.OwnerStaffID != staffProfileID || currentStudentCount != 16 || studentCount != 1 || auditCount != 1 || idempotencyCount != 1 {
		t.Fatalf("sixteenth create facts diverged: student=%#v current=%d rows=%d audits=%d idempotency=%d", created, currentStudentCount, studentCount, auditCount, idempotencyCount)
	}
}

// --- 员工创建学生被固定到本人范围且网络重试不重复事实 ---
func TestStaffCreateStudentIsScopedAndIdempotent(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	input := CreateInput{Name: "Synthetic Created Student", ProcessingBasis: "service_contract", PrivacyNoticeVersion: "privacy-notice-v1", PrivacyNoticeDelivered: true}

	created, createError := commands.Create(context.Background(), staff, "R-syntheticcreate01", "synthetic-key-student-create-01", input)
	if createError != nil {
		t.Fatalf("staff student creation failed: %v", createError)
	}
	replayed, replayError := commands.Create(context.Background(), staff, "R-syntheticcreate02", "synthetic-key-student-create-01", input)
	if replayError != nil || replayed.ID != created.ID {
		t.Fatalf("student creation retry did not replay: %#v %v", replayed, replayError)
	}
	if created.OwnerStaffID == nil || *created.OwnerStaffID != staffProfileID || created.Version != 1 {
		t.Fatalf("staff-created student escaped own scope: %#v", created)
	}
	foreignStaffID := "T-syntheticcoach02"
	foreignInput := input
	foreignInput.OwnerStaffID = &foreignStaffID
	if _, foreignError := commands.Create(context.Background(), staff, "R-syntheticcreate03", "synthetic-key-student-create-02", foreignInput); !errors.Is(foreignError, ErrForbidden) {
		t.Fatalf("staff selected another owner during creation: %v", foreignError)
	}
	var studentCount int
	var auditCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM students WHERE id = $1`, created.ID).Scan(&studentCount); queryError != nil {
		t.Fatal("synthetic created student count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'student.created' AND object_id = $1`, created.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic created student audit count failed")
	}
	if studentCount != 1 || auditCount != 1 {
		t.Fatalf("student retry duplicated facts: students=%d audits=%d", studentCount, auditCount)
	}
}

// --- 学生建档必须携带固定隐私依据和告知确认，告知时间只相信服务端时钟 ---
func TestCreateStudentRequiresPrivacyFactsAndWritesMinimalAudit(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	staffProfileID := "T-syntheticcoach01"
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
	valid := CreateInput{
		Name:            "Synthetic Privacy Student",
		ProcessingBasis: "service_contract", PrivacyNoticeVersion: "privacy-notice-v1", PrivacyNoticeDelivered: true,
	}

	missingBasis := valid
	missingBasis.ProcessingBasis = ""
	if _, createError := commands.Create(t.Context(), staff, "R-syntheticprivacy01", "synthetic-key-privacy-student-01", missingBasis); !errors.Is(createError, ErrInvalidInput) {
		t.Fatalf("student creation accepted a missing processing basis: %v", createError)
	}
	wrongNotice := valid
	wrongNotice.PrivacyNoticeVersion = "privacy-notice-v0"
	if _, createError := commands.Create(t.Context(), staff, "R-syntheticprivacy02", "synthetic-key-privacy-student-02", wrongNotice); !errors.Is(createError, ErrInvalidInput) {
		t.Fatalf("student creation accepted an unapproved notice version: %v", createError)
	}
	missingConfirmation := valid
	missingConfirmation.PrivacyNoticeDelivered = false
	if _, createError := commands.Create(t.Context(), staff, "R-syntheticprivacy03", "synthetic-key-privacy-student-03", missingConfirmation); !errors.Is(createError, ErrInvalidInput) {
		t.Fatalf("student creation accepted a missing delivery confirmation: %v", createError)
	}

	created, createError := commands.Create(t.Context(), staff, "R-syntheticprivacy04", "synthetic-key-privacy-student-04", valid)
	if createError != nil {
		t.Fatalf("valid privacy-aware student creation failed: %v", createError)
	}
	var basis, noticeVersion, deliveredAt, metadata string
	if queryError := connection.QueryRow(t.Context(), `
		SELECT student.processing_basis, student.privacy_notice_version,
		       to_char(student.privacy_notice_delivered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       audit.metadata::text
		FROM students AS student
		JOIN audit_events AS audit ON audit.object_id = student.id AND audit.action = 'student.created'
		WHERE student.id = $1`, created.ID).Scan(&basis, &noticeVersion, &deliveredAt, &metadata); queryError != nil {
		t.Fatal("privacy-aware student facts could not be read")
	}
	if basis != "service_contract" || noticeVersion != "privacy-notice-v1" || deliveredAt != "2026-08-05T16:00:00Z" {
		t.Fatalf("student privacy facts diverged: basis=%q notice=%q delivered=%q", basis, noticeVersion, deliveredAt)
	}
	if metadata != `{"processing_basis": "service_contract", "privacy_notice_version": "privacy-notice-v1"}` {
		t.Fatalf("student create audit was not minimal: %s", metadata)
	}
}

// --- 老板可以在建档时明确指定有效员工，员工建档仍由服务端自动绑定本人 ---
func TestOwnerCreatesPrivacyAwareStudentForSelectedStaff(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "students")
	commands := newStudentTestCommands(t, connection)
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	targetStaffID := "T-syntheticcoach02"
	created, createError := commands.Create(t.Context(), owner, "R-syntheticownerprivacy01", "synthetic-key-owner-privacy-01", CreateInput{
		Name:         "Synthetic Owner Created Student",
		OwnerStaffID: &targetStaffID, ProcessingBasis: "student_consent",
		PrivacyNoticeVersion: "privacy-notice-v1", PrivacyNoticeDelivered: true,
	})
	if createError != nil || created.OwnerStaffID == nil || *created.OwnerStaffID != targetStaffID {
		t.Fatalf("owner could not create for selected active staff: student=%#v error=%v", created, createError)
	}
}

// --- 装配固定时钟和 synthetic 身份的学生深模块 ---
func newStudentTestCommands(t *testing.T, connection *pgx.Conn) *Commands {
	t.Helper()
	identityCount := 0
	commands, createError := NewCommands(
		connection,
		func() time.Time { return time.Date(2026, time.August, 5, 16, 0, 0, 0, time.UTC) },
		func(prefix string) (string, error) {
			identityCount++
			return prefix + "-syntheticstudentidentity" + string(rune('a'+identityCount)), nil
		},
	)
	if createError != nil {
		t.Fatalf("student commands failed to initialize: %v", createError)
	}
	return commands
}

// --- 在当前随机 schema 中建立一个最小权威测评事实 ---
func insertSyntheticStudentAssessment(t *testing.T, connection *pgx.Conn, suffix string, studentID string, primaryType string, summary string) {
	t.Helper()
	_, invitationError := connection.Exec(context.Background(), `
		INSERT INTO student_invitations (
			id, student_id, issued_by_account_id, assessment_version, student_version, state,
			restricted_session_id, expires_at, restricted_session_expires_at, exchanged_at, completed_at
		) VALUES (
			'IV-syntheticstyle' || $1, $2, 'A-syntheticowner01', 'assessment-1', 1, 'completed',
			'IS-syntheticstyle' || $1, statement_timestamp() + interval '1 day', statement_timestamp() + interval '1 hour',
			statement_timestamp(), statement_timestamp()
		)`, suffix, studentID)
	if invitationError != nil {
		t.Fatal("synthetic student assessment invitation setup failed")
	}
	_, assessmentError := connection.Exec(context.Background(), `
		INSERT INTO assessments (
			id, student_id, questionnaire_version, answers, server_score, internal_recommendation,
			source_invitation_id, submitted_at
		) VALUES (
			'AS-syntheticstyle' || $1, $2, 'assessment-1',
			jsonb_build_object('p1','a','p2','a','p3','a','p4','a','p5','a','p6','a','p7','a','p8','a','p9','a','p10','a'),
			jsonb_build_object('primary_type', $3::text, 'secondary_type', 'steady_support', 'core_scores', '{}'::jsonb, 'signal_scores', '{}'::jsonb),
			jsonb_build_object('summary', $4::text, 'advice', '[]'::jsonb, 'support_signals', null, 'support_material', null),
			'IV-syntheticstyle' || $1, statement_timestamp()
		)`, suffix, studentID, primaryType, summary)
	if assessmentError != nil {
		t.Fatal("synthetic student assessment setup failed")
	}
}

func studentsByID(students []Student) map[string]Student {
	indexed := make(map[string]Student, len(students))
	for _, student := range students {
		indexed[student.ID] = student
	}
	return indexed
}
