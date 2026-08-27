/*
受邀测评命令合同：通过真实 PostgreSQL 冻结 assessment-1 十题、资料白名单、服务端评分和原子完成。
所有会话、学生、答案和资料均为 synthetic；测试只跨越未来 Commands 公开接口并读取独立随机 schema。
*/
package assessments

import (
	"bytes"         // 比较受限会话摘要在失败前后是否保持一致。
	"context"       // 驱动公开表单、提交命令与 synthetic 事实查询。
	"crypto/sha256" // 为测试能力构造不可恢复的数据库摘要并冻结问卷投影。
	"encoding/hex"  // 将稳定问卷摘要转换为可审查十六进制合同。
	"encoding/json" // 规范化公开题目并读取服务端内部 JSON 事实。
	"errors"        // 比较不回显答案或对象状态的稳定领域失败。
	"fmt"           // 生成互不冲突且不含业务数据的 synthetic 身份。
	"reflect"       // 证明学生表单与完成回执没有内部评分字段。
	"sort"          // 把资料白名单转换为稳定顺序后比较。
	"strings"       // 审计公开回执 JSON 不包含任何内部字段名。
	"testing"       // 组织独立问卷、评分、冲突与回滚行为。
	"time"          // 注入同一可信 UTC 提交时间与能力有效期。

	"github.com/jackc/pgx/v5" // 在随机 schema 内装配命令和测试能力事实。

	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立完整 migration 链和 Foundation synthetic seed。
)

const syntheticAssessmentVersion = "assessment-1"                                                       // v2 OpenAPI 与 T054 邀请共同使用的唯一活动问卷身份。
const syntheticQuestionnaireDigest = "5aac5add9e8ec4b045b329a29e9779d9695e0f26d5824619538774b9203d83be" // 历史十题公开文字与选项在 v2 版本名下的规范 SHA-256。

var syntheticAssessmentTime = time.Date(2026, time.August, 6, 9, 0, 0, 0, time.UTC) // 所有能力和提交共享可重复时钟。

var syntheticProfileFields = []string{ // 邀请只允许等价迁移的十五个自填字段，不包含内部状态或负责人。
	"certificates", "current_location", "expected_salary", "grade", "internship_experience", "job_intention", "major", "name",
	"phone", "project_experience", "school", "skills", "target_city", "target_position", "wechat",
}

// --- 学生表单保留精确十题且不返回既有资料或私有权重 ---
func TestFormReturnsFrozenQuestionnaireAndBlankWhitelistedFields(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "assessments") // 表单读取只接触本测试随机 schema。
	commands := newAssessmentTestCommands(t, connection)
	capability := insertSyntheticAssessmentCapability(t, connection, "S-syntheticstudent01", 1)
	if _, updateError := connection.Exec(context.Background(), `UPDATE students SET phone = 'Synthetic Existing Phone', email = 'existing@example.invalid' WHERE id = 'S-syntheticstudent01'`); updateError != nil {
		t.Fatal("synthetic existing profile setup failed")
	}

	form, formError := commands.Form(context.Background(), capability)
	if formError != nil {
		t.Fatalf("synthetic assessment form failed: %v", formError)
	}
	if form.AssessmentVersion != syntheticAssessmentVersion || len(form.Questions) != 10 {
		t.Fatalf("assessment form version or question count diverged: version=%s questions=%d", form.AssessmentVersion, len(form.Questions))
	}
	fieldNames := make([]string, 0, len(form.StudentFields)) // 只比较字段身份，不输出任何字段值。
	for fieldName, fieldValue := range form.StudentFields {
		fieldNames = append(fieldNames, fieldName)
		if fieldValue != nil && *fieldValue != "" { // 既有联系方式和资料不能经邀请表单回显。
			t.Fatalf("assessment form exposed existing value for field %s", fieldName)
		}
	}
	sort.Strings(fieldNames)
	if !reflect.DeepEqual(fieldNames, syntheticProfileFields) {
		t.Fatalf("assessment form whitelist diverged: fields=%v", fieldNames)
	}
	for position, question := range form.Questions { // 十题和每题四个选项必须稳定有序。
		expectedQuestionID := fmt.Sprintf("p%d", position+1)
		if question.ID != expectedQuestionID || question.Prompt == "" || len(question.Options) != 4 {
			t.Fatalf("assessment question %d lost its frozen public shape", position+1)
		}
		for optionPosition, option := range question.Options {
			expectedOptionID := fmt.Sprintf("p%d-neutral-option-%c", position+1, 'a'+optionPosition)
			if option.ID != expectedOptionID || option.Label == "" {
				t.Fatalf("assessment question %d option %d diverged", position+1, optionPosition+1)
			}
		}
	}
	if actualDigest := publicQuestionnaireDigest(t, form); actualDigest != syntheticQuestionnaireDigest {
		t.Fatalf("assessment-1 public registry digest diverged: %s", actualDigest)
	}

	formType := reflect.TypeOf(form) // 学生投影只能包含版本、空白资料字段和公开问题。
	if formType.NumField() != 3 {
		t.Fatalf("assessment form exposed %d top-level fields", formType.NumField())
	}
	questionType := reflect.TypeOf(form.Questions[0])
	optionType := reflect.TypeOf(form.Questions[0].Options[0])
	for _, forbiddenField := range []string{"Weights", "Scores", "PrimaryType", "RiskLabels", "Advice", "ReportStatus"} {
		if _, found := formType.FieldByName(forbiddenField); found {
			t.Fatalf("assessment form exposed internal field %s", forbiddenField)
		}
		if _, found := questionType.FieldByName(forbiddenField); found {
			t.Fatalf("assessment question exposed internal field %s", forbiddenField)
		}
		if _, found := optionType.FieldByName(forbiddenField); found {
			t.Fatalf("assessment option exposed internal field %s", forbiddenField)
		}
	}

	wrongSecret := Capability{ID: capability.ID, Secret: "synthetic-wrong-assessment-capability-secret-0001"}
	if _, capabilityError := commands.Form(context.Background(), wrongSecret); !errors.Is(capabilityError, ErrInvalidCapability) {
		t.Fatalf("wrong assessment capability used unsafe feedback: %v", capabilityError)
	}
	unknownCapability := Capability{ID: "IS-syntheticassessmentunknown", Secret: capability.Secret}
	if _, capabilityError := commands.Form(context.Background(), unknownCapability); !errors.Is(capabilityError, ErrInvalidCapability) {
		t.Fatalf("unknown assessment capability used different feedback: %v", capabilityError)
	}
}

// --- 版本、答案和资料只接受当前注册表的精确白名单 ---
func TestSubmitRejectsUnknownVersionAnswersAndProfileFieldsWithoutWrites(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "assessments") // 全部无效输入共享一个仍活动的能力。
	commands := newAssessmentTestCommands(t, connection)
	capability := insertSyntheticAssessmentCapability(t, connection, "S-syntheticstudent01", 1)
	validInput := syntheticAssessmentInput(syntheticDirectAnswers())

	invalidInputs := []struct {
		name  string      // name 描述当前被拒绝的公开合同维度。
		input SubmitInput // input 每次从完整合法意图派生一个错误。
	}{
		{name: "unknown version", input: withAssessmentVersion(validInput, "assessment-2")},
		{name: "missing answer", input: withMissingAssessmentAnswer(validInput, "p10")},
		{name: "extra answer", input: withAssessmentAnswer(validInput, "p11", "p11-neutral-option-a")},
		{name: "cross-question option", input: withAssessmentAnswer(validInput, "p1", "p2-neutral-option-a")},
		{name: "unknown option", input: withAssessmentAnswer(validInput, "p1", "p1-neutral-option-z")},
		{name: "internal profile field", input: withAssessmentField(validInput, "owner_staff_id", "T-syntheticcoach02")},
		{name: "missing required profile", input: withMissingAssessmentField(validInput, "name")},
	}

	for position, invalidInput := range invalidInputs { // 每次失败都必须发生在任何资料或测评写入前。
		_, submitError := commands.Submit(
			context.Background(), capability, fmt.Sprintf("R-syntheticassessmentinvalid%02d", position+1),
			fmt.Sprintf("synthetic-key-assessment-invalid-%02d", position+1), invalidInput.input,
		)
		if !errors.Is(submitError, ErrInvalidInput) {
			t.Fatalf("invalid assessment %s used unexpected failure: %v", invalidInput.name, submitError)
		}
	}

	var assessmentCount int // 无效请求不能保存答案或派生结果。
	var eventCount int      // 无效请求不能形成成功事件。
	var auditCount int      // 无效请求不能形成成功审计。
	var idempotencyCount int
	var studentVersion int64
	var invitationState string
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM assessments`).Scan(&assessmentCount); queryError != nil {
		t.Fatal("synthetic rejected assessment count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_events WHERE event_type = 'assessment.submitted'`).Scan(&eventCount); queryError != nil {
		t.Fatal("synthetic rejected assessment event count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'assessment.submitted'`).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic rejected assessment audit count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE action = 'assessment.submit'`).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("synthetic rejected assessment idempotency count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT version FROM students WHERE id = 'S-syntheticstudent01'`).Scan(&studentVersion); queryError != nil {
		t.Fatal("synthetic rejected assessment student query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT state FROM student_invitations WHERE restricted_session_id = $1`, capability.ID).Scan(&invitationState); queryError != nil {
		t.Fatal("synthetic rejected assessment invitation query failed")
	}
	if assessmentCount != 0 || eventCount != 0 || auditCount != 0 || idempotencyCount != 0 || studentVersion != 1 || invitationState != "exchanged" {
		t.Fatalf("invalid assessment left facts: assessments=%d events=%d audits=%d idempotency=%d student_version=%d invitation_state=%s", assessmentCount, eventCount, auditCount, idempotencyCount, studentVersion, invitationState)
	}
}

// --- 六个等价向量证明分数和内部建议只能由服务端注册表产生 ---
func TestSubmitDerivesCoreAndHybridResultsFromAnswers(t *testing.T) {
	vectors := []struct {
		name           string            // name 是可读的服务端结果分支。
		answers        map[string]string // answers 只包含十个问题绑定选项。
		primaryType    string            // primaryType 由权重和 hybrid 规则产生。
		secondaryType  string            // secondaryType 由固定 core 顺序产生。
		supportSignals []string          // supportSignals 只供内部人工准备。
		publicCode     string            // publicCode 是学生和有权后台共享的稳定机器键。
		publicLabel    string            // publicLabel 使用中性、非诊断的中文名称。
	}{
		{name: "direct", answers: syntheticUniformAnswers('a'), primaryType: "direct_goal", secondaryType: "evidence_planning", publicCode: "tiger", publicLabel: "老虎型 · 目标推进"},
		{name: "expressive", answers: syntheticUniformAnswers('b'), primaryType: "expressive_feedback", secondaryType: "steady_support", supportSignals: []string{"feedback_support"}, publicCode: "peacock", publicLabel: "孔雀型 · 互动反馈"},
		{name: "evidence", answers: syntheticUniformAnswers('c'), primaryType: "evidence_planning", secondaryType: "direct_goal", supportSignals: []string{"context_constraints"}, publicCode: "owl", publicLabel: "猫头鹰型 · 依据规划"},
		{name: "steady", answers: syntheticUniformAnswers('d'), primaryType: "steady_support", secondaryType: "direct_goal", publicCode: "koala", publicLabel: "考拉型 · 稳步支持"},
		{name: "direct expressive hybrid", answers: syntheticAnswerLetters("bba baababa"), primaryType: "direct_expressive", secondaryType: "expressive_feedback", publicCode: "tiger_peacock", publicLabel: "老虎×孔雀型 · 目标与互动"},
		{name: "evidence steady hybrid", answers: syntheticAnswerLetters("cdccdcddcd"), primaryType: "evidence_steady", secondaryType: "steady_support", publicCode: "owl_koala", publicLabel: "猫头鹰×考拉型 · 规划与稳定"},
	}

	for position, vector := range vectors { // 每个提交使用独立 schema，完成终态不会影响下一个向量。
		t.Run(vector.name, func(t *testing.T) {
			connection := testsupport.OpenDatabase(t, "assessments")
			commands := newAssessmentTestCommands(t, connection)
			capability := insertSyntheticAssessmentCapability(t, connection, "S-syntheticstudent01", 1)
			receipt, submitError := commands.Submit(
				context.Background(), capability, fmt.Sprintf("R-syntheticassessmentscore%02d", position+1),
				fmt.Sprintf("synthetic-key-assessment-score-%02d", position+1), syntheticAssessmentInput(vector.answers),
			)
			if submitError != nil {
				t.Fatalf("synthetic scoring vector failed: %v", submitError)
			}

			var scoreBody []byte          // 评分 JSON 保存权威主次键。
			var recommendationBody []byte // 建议 JSON 保存中性人工材料和支持信号。
			if queryError := connection.QueryRow(context.Background(), `SELECT server_score, internal_recommendation FROM assessments WHERE student_id = 'S-syntheticstudent01'`).Scan(&scoreBody, &recommendationBody); queryError != nil {
				t.Fatal("synthetic assessment scoring query failed")
			}
			var score map[string]any
			var recommendation map[string]any
			if json.Unmarshal(scoreBody, &score) != nil || json.Unmarshal(recommendationBody, &recommendation) != nil {
				t.Fatal("synthetic assessment scoring JSON was invalid")
			}
			if score["primary_type"] != vector.primaryType || score["secondary_type"] != vector.secondaryType {
				t.Fatalf("server scoring vector %d diverged", position+1)
			}
			if recommendation["report_status"] != "pending_human_confirmation" || recommendation["summary"] == "" || recommendation["advice"] == nil {
				t.Fatalf("server recommendation vector %d lost its human-confirmation material", position+1)
			}
			if receipt.CommunicationStyle.Code != vector.publicCode || receipt.CommunicationStyle.Label != vector.publicLabel {
				t.Fatalf("public communication-style mapping for vector %d diverged", position+1)
			}
			if receipt.CommunicationStyle.Summary != recommendation["summary"] || receipt.CommunicationStyle.Disclaimer != "这是沟通风格倾向，不代表固定人格、心理诊断、能力高低或职业适配结论。" {
				t.Fatalf("public communication-style material for vector %d diverged", position+1)
			}
			actualSignals := stringSliceFromJSON(t, recommendation["support_signals"])
			if !reflect.DeepEqual(actualSignals, vector.supportSignals) {
				t.Fatalf("server support signals for vector %d diverged", position+1)
			}
		})
	}
}

// --- 一次提交原子更新白名单、测评、证据和邀请终态 ---
func TestSubmitAtomicallyCompletesProfileAssessmentAndInvitation(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "assessments") // 正向事实全部落在一个可清理 schema。
	commands := newAssessmentTestCommands(t, connection)
	capability := insertSyntheticAssessmentCapability(t, connection, "S-syntheticstudent01", 1)
	if _, setupError := connection.Exec(context.Background(), `UPDATE students SET phone = 'Synthetic Old Phone', wechat = 'Synthetic Retained Wechat', skills = 'Synthetic Retained Skills' WHERE id = 'S-syntheticstudent01'`); setupError != nil {
		t.Fatal("synthetic retained profile setup failed")
	}
	input := syntheticAssessmentInput(syntheticDirectAnswers())
	input.StudentFields["phone"] = syntheticAssessmentText("Synthetic New Phone") // 明确非空值更新白名单字段。
	input.StudentFields["wechat"] = syntheticAssessmentText("")                   // 空白可选值保留已有资料。
	input.StudentFields["skills"] = syntheticAssessmentText("")                   // 另一个空白值证明保留规则一致。

	receipt, submitError := commands.Submit(
		context.Background(), capability, "R-syntheticassessmentsubmit1", "synthetic-key-assessment-submit-01", input,
	)
	if submitError != nil || !receipt.Completed {
		t.Fatalf("synthetic assessment submit failed: completed=%t error=%v", receipt.Completed, submitError)
	}
	receiptType := reflect.TypeOf(receipt) // 学生回执只新增安全沟通风格，不得携带答案、评分或内部建议。
	if receiptType.NumField() != 2 {
		t.Fatalf("assessment receipt exposed %d fields", receiptType.NumField())
	}
	styleType := reflect.TypeOf(receipt.CommunicationStyle)
	if styleType.NumField() != 4 || receipt.CommunicationStyle.Code != "tiger" || receipt.CommunicationStyle.Label != "老虎型 · 目标推进" || receipt.CommunicationStyle.Summary == "" {
		t.Fatal("assessment receipt lost its exact safe communication-style projection")
	}
	for _, forbiddenField := range []string{"Answers", "ServerScore", "InternalRecommendation", "PrimaryType", "Advice", "StudentID"} {
		if _, found := receiptType.FieldByName(forbiddenField); found {
			t.Fatalf("assessment receipt exposed internal field %s", forbiddenField)
		}
	}
	receiptBody, receiptEncodingError := json.Marshal(receipt)
	if receiptEncodingError != nil {
		t.Fatal("synthetic public receipt encoding failed")
	}
	for _, forbiddenKey := range []string{"answers", "server_score", "core_scores", "signal_scores", "support_signals", "support_material", "internal_recommendation", "advice", "secondary_type", "phone", "wechat", "secret", "credential"} {
		if strings.Contains(string(receiptBody), forbiddenKey) {
			t.Fatalf("assessment receipt exposed forbidden key %s", forbiddenKey)
		}
	}

	replay, replayError := commands.Submit(
		context.Background(), capability, "R-syntheticassessmentsubmit2", "synthetic-key-assessment-submit-01", input,
	)
	if replayError != nil || !reflect.DeepEqual(replay, receipt) {
		t.Fatalf("assessment replay lost the original safe receipt: equal=%t error=%v", reflect.DeepEqual(replay, receipt), replayError)
	}

	var name, phone, wechat, currentLocation, skills, serviceStage, jobSearchStage, ownerStaffID, sourceKind, updatedBy string
	var studentVersion int64
	if queryError := connection.QueryRow(context.Background(), `SELECT name, phone, wechat, current_location, skills, service_stage, job_search_stage, owner_staff_id, source_kind, updated_by, version FROM students WHERE id = 'S-syntheticstudent01'`).Scan(&name, &phone, &wechat, &currentLocation, &skills, &serviceStage, &jobSearchStage, &ownerStaffID, &sourceKind, &updatedBy, &studentVersion); queryError != nil {
		t.Fatal("synthetic completed student query failed")
	}
	if name != "Synthetic Assessment Student" || phone != "Synthetic New Phone" || wechat != "Synthetic Retained Wechat" || currentLocation != "Synthetic Current City" || skills != "Synthetic Retained Skills" || serviceStage != "服务中" || jobSearchStage != "简历准备" || ownerStaffID != "T-syntheticcoach01" || sourceKind != "invitation" || updatedBy != capability.ID || studentVersion != 2 {
		t.Fatalf("assessment profile completion diverged: name=%t phone=%t wechat_retained=%t current_location=%t skills_retained=%t service=%s job=%s owner=%s source=%s actor=%s version=%d", name == "Synthetic Assessment Student", phone == "Synthetic New Phone", wechat == "Synthetic Retained Wechat", currentLocation == "Synthetic Current City", skills == "Synthetic Retained Skills", serviceStage, jobSearchStage, ownerStaffID, sourceKind, updatedBy, studentVersion)
	}

	var assessmentCount int     // 学生始终最多一个活动结果。
	var answerCount int         // 权威记录保存全部十题答案供顾问追溯。
	var assessmentVersion int64 // 首次提交创建版本 1。
	var sourceInvitationID string
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), max(jsonb_array_length(jsonb_path_query_array(answers, '$.keyvalue()'))), max(version), max(source_invitation_id) FROM assessments WHERE student_id = 'S-syntheticstudent01' AND questionnaire_version = $1`, syntheticAssessmentVersion).Scan(&assessmentCount, &answerCount, &assessmentVersion, &sourceInvitationID); queryError != nil {
		t.Fatal("synthetic completed assessment query failed")
	}
	if assessmentCount != 1 || answerCount != 10 || assessmentVersion != 1 || sourceInvitationID != "IV-syntheticassessment01" {
		t.Fatalf("completed assessment facts diverged: count=%d answers=%d version=%d source=%s", assessmentCount, answerCount, assessmentVersion, sourceInvitationID)
	}

	var invitationState string // 完成终态销毁受限会话摘要。
	var sessionDigest []byte
	var completedAt *time.Time
	if queryError := connection.QueryRow(context.Background(), `SELECT state, restricted_session_digest, completed_at FROM student_invitations WHERE restricted_session_id = $1`, capability.ID).Scan(&invitationState, &sessionDigest, &completedAt); queryError != nil {
		t.Fatal("synthetic completed invitation query failed")
	}
	var eventCount, minimalEventCount, auditCount, minimalAuditCount, idempotencyCount int
	var storedReceiptBody []byte
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE payload ? 'assessment_id' AND payload ? 'assessment_version' AND payload ? 'student_version' AND NOT payload ? 'answers' AND NOT payload ? 'server_score' AND NOT payload ? 'internal_recommendation' AND NOT payload ? 'phone') FROM student_events WHERE student_id = 'S-syntheticstudent01' AND event_type = 'assessment.submitted' AND actor_kind = 'invitation' AND actor_id = $1`, capability.ID).Scan(&eventCount, &minimalEventCount); queryError != nil {
		t.Fatal("synthetic completed assessment event query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE metadata ? 'assessment_version' AND metadata ? 'student_version' AND NOT metadata ? 'answers' AND NOT metadata ? 'server_score' AND NOT metadata ? 'internal_recommendation' AND NOT metadata ? 'phone') FROM audit_events WHERE actor_kind = 'invitation' AND actor_id = $1 AND action = 'assessment.submitted' AND object_type = 'assessment'`, capability.ID).Scan(&auditCount, &minimalAuditCount); queryError != nil {
		t.Fatal("synthetic completed assessment audit query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE actor_scope = $1 AND action = 'assessment.submit' AND idempotency_key = 'synthetic-key-assessment-submit-01'`, capability.ID).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("synthetic completed assessment idempotency query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT response_body FROM idempotency_records WHERE actor_scope = $1 AND action = 'assessment.submit' AND idempotency_key = 'synthetic-key-assessment-submit-01'`, capability.ID).Scan(&storedReceiptBody); queryError != nil {
		t.Fatal("synthetic completed assessment idempotency body query failed")
	}
	var storedReceipt Receipt
	if json.Unmarshal(storedReceiptBody, &storedReceipt) != nil || !reflect.DeepEqual(storedReceipt, receipt) {
		t.Fatal("assessment idempotency record lost the original safe receipt")
	}
	if invitationState != "completed" || sessionDigest != nil || completedAt == nil || eventCount != 1 || minimalEventCount != 1 || auditCount != 1 || minimalAuditCount != 1 || idempotencyCount != 1 {
		t.Fatalf("assessment completion boundary diverged: invitation=%s digest=%t completed_at=%t events=%d minimal_events=%d audits=%d minimal_audits=%d idempotency=%d", invitationState, sessionDigest != nil, completedAt != nil, eventCount, minimalEventCount, auditCount, minimalAuditCount, idempotencyCount)
	}
}

// --- 邀请绑定的学生旧版本冲突时不产生任何部分写入 ---
func TestSubmitRejectsStudentVersionConflictWithoutConsumingCapability(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "assessments") // 能力记录冻结学生版本 1。
	commands := newAssessmentTestCommands(t, connection)
	capability := insertSyntheticAssessmentCapability(t, connection, "S-syntheticstudent01", 1)
	if _, updateError := connection.Exec(context.Background(), `UPDATE students SET name = 'Synthetic Concurrent Student', version = version + 1, updated_by = 'A-syntheticstaff01' WHERE id = 'S-syntheticstudent01'`); updateError != nil {
		t.Fatal("synthetic concurrent student setup failed")
	}

	if _, submitError := commands.Submit(
		context.Background(), capability, "R-syntheticassessmentconflict", "synthetic-key-assessment-conflict", syntheticAssessmentInput(syntheticDirectAnswers()),
	); !errors.Is(submitError, ErrVersionConflict) {
		t.Fatalf("stale invitation student version was accepted: %v", submitError)
	}
	assertNoAssessmentWrites(t, connection, capability, "exchanged", 2) // 冲突后的补发或人工核对仍可使用明确邀请事实。
}

// --- 任一写入阶段失败都必须回滚资料、测评、证据与邀请完成 ---
func TestSubmitRollsBackEveryAtomicWriteOnInjectedFailure(t *testing.T) {
	failures := []struct {
		name string // name 标出被故障注入拒绝的提交阶段。
		sql  string // sql 只安装在当前子测试随机 schema。
	}{
		{name: "assessment", sql: `
			CREATE FUNCTION reject_synthetic_assessment_row() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'synthetic assessment rejection'; END; $$;
			CREATE TRIGGER reject_synthetic_assessment_row BEFORE INSERT OR UPDATE ON assessments
				FOR EACH ROW EXECUTE FUNCTION reject_synthetic_assessment_row()`},
		{name: "student event", sql: `
			CREATE FUNCTION reject_synthetic_assessment_event() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.event_type = 'assessment.submitted' THEN RAISE EXCEPTION 'synthetic event rejection'; END IF;
				RETURN NEW;
			END; $$;
			CREATE TRIGGER reject_synthetic_assessment_event BEFORE INSERT ON student_events
				FOR EACH ROW EXECUTE FUNCTION reject_synthetic_assessment_event()`},
		{name: "minimal audit", sql: `
			CREATE FUNCTION reject_synthetic_assessment_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.action = 'assessment.submitted' THEN RAISE EXCEPTION 'synthetic audit rejection'; END IF;
				RETURN NEW;
			END; $$;
			CREATE TRIGGER reject_synthetic_assessment_audit BEFORE INSERT ON audit_events
				FOR EACH ROW EXECUTE FUNCTION reject_synthetic_assessment_audit()`},
		{name: "invitation completion", sql: `
			CREATE FUNCTION reject_synthetic_invitation_completion() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.state = 'completed' THEN RAISE EXCEPTION 'synthetic completion rejection'; END IF;
				RETURN NEW;
			END; $$;
			CREATE TRIGGER reject_synthetic_invitation_completion BEFORE UPDATE ON student_invitations
				FOR EACH ROW EXECUTE FUNCTION reject_synthetic_invitation_completion()`},
	}

	for position, failure := range failures { // 四个失败点分别证明同一事务包络的完整性。
		t.Run(failure.name, func(t *testing.T) {
			connection := testsupport.OpenDatabase(t, "assessments")
			commands := newAssessmentTestCommands(t, connection)
			capability := insertSyntheticAssessmentCapability(t, connection, "S-syntheticstudent01", 1)
			if _, setupError := connection.Exec(context.Background(), failure.sql); setupError != nil {
				t.Fatal("synthetic assessment failure setup failed")
			}

			if _, submitError := commands.Submit(
				context.Background(), capability, fmt.Sprintf("R-syntheticassessmentrollback%02d", position+1),
				fmt.Sprintf("synthetic-key-assessment-rollback-%02d", position+1), syntheticAssessmentInput(syntheticDirectAnswers()),
			); !errors.Is(submitError, ErrWriteFailed) {
				t.Fatalf("injected assessment failure was not safe: %v", submitError)
			}
			assertNoAssessmentWrites(t, connection, capability, "exchanged", 1)
		})
	}
}

// --- 装配固定时钟与 synthetic 身份的测评深模块 ---
func newAssessmentTestCommands(t *testing.T, connection *pgx.Conn) *Commands {
	t.Helper()         // 装配失败归因到调用行为测试。
	identityCount := 0 // 测评、事件和审计各自取得不透明身份。
	commands, createError := NewCommands(
		connection,
		func() time.Time { return syntheticAssessmentTime },
		func(prefix string) (string, error) {
			identityCount++
			return fmt.Sprintf("%s-syntheticassessment%02d", prefix, identityCount), nil
		},
	)
	if createError != nil {
		t.Fatalf("assessment commands failed to initialize: %v", createError)
	}
	return commands // 测试只学习表单与提交两个公开动作。
}

// --- 在未来 T056 schema 中建立一条已兑换 synthetic 能力 ---
func insertSyntheticAssessmentCapability(t *testing.T, connection *pgx.Conn, studentID string, studentVersion int64) Capability {
	t.Helper() // fixture 失败归因到需要能力的行为测试。
	secret := "synthetic-assessment-capability-secret-material-0001"
	digest := sha256.Sum256([]byte(secret)) // 数据库从不接收原始能力秘密。
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO student_invitations (
			id, student_id, issued_by_account_id, assessment_version, student_version, state,
			invite_digest, expires_at, exchanged_at, restricted_session_id,
			restricted_session_digest, restricted_session_expires_at
		) VALUES (
			'IV-syntheticassessment01', $1, 'A-syntheticstaff01', $2, $3, 'exchanged',
			NULL, $4, $5, 'IS-syntheticassessment01', $6, $7
		)`, studentID, syntheticAssessmentVersion, studentVersion, syntheticAssessmentTime.Add(24*time.Hour),
		syntheticAssessmentTime, digest[:], syntheticAssessmentTime.Add(2*time.Hour)); insertError != nil {
		t.Fatal("synthetic assessment capability setup failed")
	}
	return Capability{ID: "IS-syntheticassessment01", Secret: secret} // 原始值只留在当前测试调用链内。
}

// --- 构造一个完整白名单资料与十题意图 ---
func syntheticAssessmentInput(answers map[string]string) SubmitInput {
	return SubmitInput{
		AssessmentVersion: syntheticAssessmentVersion,
		StudentFields: map[string]*string{
			"name": syntheticAssessmentText("Synthetic Assessment Student"), "phone": syntheticAssessmentText("Synthetic Phone"),
			"wechat": syntheticAssessmentText(""), "school": syntheticAssessmentText("Synthetic School"),
			"major": syntheticAssessmentText("Synthetic Major"), "grade": syntheticAssessmentText("Synthetic Grade"),
			"current_location": syntheticAssessmentText("Synthetic Current City"),
			"target_city":      syntheticAssessmentText("Synthetic City"), "target_position": syntheticAssessmentText("Synthetic Role"),
			"expected_salary": syntheticAssessmentText(""), "job_intention": syntheticAssessmentText(""),
			"project_experience": syntheticAssessmentText(""), "internship_experience": syntheticAssessmentText(""),
			"skills": syntheticAssessmentText(""), "certificates": syntheticAssessmentText(""),
		},
		Answers: cloneAssessmentAnswers(answers),
	}
}

func syntheticAssessmentText(value string) *string {
	return &value // 每个资料字段拥有独立 synthetic 字符串地址。
}

// --- 构造十个问题绑定的选项向量 ---
func syntheticUniformAnswers(letter rune) map[string]string {
	answers := make(map[string]string, 10) // 十题必须完整且不能共享跨题选项。
	for position := 1; position <= 10; position++ {
		answers[fmt.Sprintf("p%d", position)] = fmt.Sprintf("p%d-neutral-option-%c", position, letter)
	}
	return answers
}

func syntheticDirectAnswers() map[string]string {
	return syntheticUniformAnswers('a') // 全 a 向量稳定产生目标推进倾向。
}

func syntheticAnswerLetters(letters string) map[string]string {
	compact := make([]rune, 0, 10) // 忽略测试源码中的视觉分组空格。
	for _, letter := range letters {
		if letter >= 'a' && letter <= 'd' {
			compact = append(compact, letter)
		}
	}
	if len(compact) != 10 {
		panic("synthetic assessment vector must contain ten letters") // 固定测试夹具错误应立即停止。
	}
	answers := make(map[string]string, 10)
	for position, letter := range compact {
		answers[fmt.Sprintf("p%d", position+1)] = fmt.Sprintf("p%d-neutral-option-%c", position+1, letter)
	}
	return answers
}

// --- 派生无别名的无效提交变体 ---
func withAssessmentVersion(input SubmitInput, version string) SubmitInput {
	copy := cloneAssessmentInput(input)
	copy.AssessmentVersion = version
	return copy
}

func withMissingAssessmentAnswer(input SubmitInput, questionID string) SubmitInput {
	copy := cloneAssessmentInput(input)
	delete(copy.Answers, questionID)
	return copy
}

func withAssessmentAnswer(input SubmitInput, questionID string, optionID string) SubmitInput {
	copy := cloneAssessmentInput(input)
	copy.Answers[questionID] = optionID
	return copy
}

func withAssessmentField(input SubmitInput, fieldName string, value string) SubmitInput {
	copy := cloneAssessmentInput(input)
	copy.StudentFields[fieldName] = syntheticAssessmentText(value)
	return copy
}

func withMissingAssessmentField(input SubmitInput, fieldName string) SubmitInput {
	copy := cloneAssessmentInput(input)
	delete(copy.StudentFields, fieldName)
	return copy
}

func cloneAssessmentInput(input SubmitInput) SubmitInput {
	fields := make(map[string]*string, len(input.StudentFields)) // 指针值也复制，避免一个无效变体污染其他用例。
	for fieldName, fieldValue := range input.StudentFields {
		if fieldValue == nil {
			fields[fieldName] = nil
			continue
		}
		fields[fieldName] = syntheticAssessmentText(*fieldValue)
	}
	return SubmitInput{AssessmentVersion: input.AssessmentVersion, StudentFields: fields, Answers: cloneAssessmentAnswers(input.Answers)}
}

func cloneAssessmentAnswers(answers map[string]string) map[string]string {
	copy := make(map[string]string, len(answers))
	for questionID, optionID := range answers {
		copy[questionID] = optionID
	}
	return copy
}

// --- 规范化公开题目树并计算冻结摘要 ---
func publicQuestionnaireDigest(t *testing.T, form Form) string {
	t.Helper() // 编码失败归因到表单行为测试。
	questions := make([]map[string]any, 0, len(form.Questions))
	for _, question := range form.Questions {
		options := make([]map[string]string, 0, len(question.Options))
		for _, option := range question.Options {
			options = append(options, map[string]string{"id": option.ID, "label": option.Label})
		}
		questions = append(questions, map[string]any{"id": question.ID, "prompt": question.Prompt, "options": options})
	}
	body, marshalError := json.Marshal(map[string]any{"questionnaire_version": form.AssessmentVersion, "questions": questions})
	if marshalError != nil {
		t.Fatal("synthetic public questionnaire could not be normalized")
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// --- 把内部 JSON 数组安全转换为固定信号键集合 ---
func stringSliceFromJSON(t *testing.T, value any) []string {
	t.Helper() // JSON 形状错误归因到评分向量测试。
	if value == nil {
		return nil
	}
	rawValues, valid := value.([]any)
	if !valid {
		t.Fatal("synthetic support signals were not an array")
	}
	result := make([]string, 0, len(rawValues))
	for _, rawValue := range rawValues {
		text, valid := rawValue.(string)
		if !valid {
			t.Fatal("synthetic support signal was not text")
		}
		result = append(result, text)
	}
	return result
}

// --- 断言冲突或故障后没有部分成功 ---
func assertNoAssessmentWrites(t *testing.T, connection *pgx.Conn, capability Capability, expectedInvitationState string, expectedStudentVersion int64) {
	t.Helper() // 原子性失败归因到触发命令的测试。
	var assessmentCount, eventCount, auditCount, idempotencyCount int
	var studentVersion int64
	var studentName, invitationState string
	var sessionDigest []byte
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM assessments`).Scan(&assessmentCount); queryError != nil {
		t.Fatal("synthetic rolled-back assessment count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_events WHERE event_type = 'assessment.submitted'`).Scan(&eventCount); queryError != nil {
		t.Fatal("synthetic rolled-back assessment event count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'assessment.submitted'`).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic rolled-back assessment audit count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE action = 'assessment.submit'`).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("synthetic rolled-back assessment idempotency count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT name, version FROM students WHERE id = 'S-syntheticstudent01'`).Scan(&studentName, &studentVersion); queryError != nil {
		t.Fatal("synthetic rolled-back student query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT state, restricted_session_digest FROM student_invitations WHERE restricted_session_id = $1`, capability.ID).Scan(&invitationState, &sessionDigest); queryError != nil {
		t.Fatal("synthetic rolled-back invitation query failed")
	}
	expectedDigest := sha256.Sum256([]byte(capability.Secret))
	if assessmentCount != 0 || eventCount != 0 || auditCount != 0 || idempotencyCount != 0 || studentName == "Synthetic Assessment Student" || studentVersion != expectedStudentVersion || invitationState != expectedInvitationState || !bytes.Equal(sessionDigest, expectedDigest[:]) {
		t.Fatalf("assessment failure left partial facts: assessments=%d events=%d audits=%d idempotency=%d student_changed=%t student_version=%d invitation=%s digest_match=%t", assessmentCount, eventCount, auditCount, idempotencyCount, studentName == "Synthetic Assessment Student", studentVersion, invitationState, bytes.Equal(sessionDigest, expectedDigest[:]))
	}
}
