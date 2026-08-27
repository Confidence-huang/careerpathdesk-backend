/*
关注业务指令：把 48/72 小时、投诉、第三次逾期和同线程连续未回复收敛为最小人工关注事实。
调用示例：commands.Evaluate(ctx, studentID) 形成确定性事项；老板再用 commands.Conclude(...) 记录人工结论。
规则只读取受保护事实并保存对象引用，不复制跟进正文，也不会自动退款、结束服务或修改学生状态。
*/
package attention

import (
	"context"       // 将请求取消和期限传入关注事务。
	"crypto/sha256" // 把确认投诉意图绑定到幂等键而不保存业务正文。
	"errors"        // 暴露不含对象正文或 SQL 的稳定失败分类。
	"sort"          // 固定触发码与证据顺序，使重复评估完全一致。
	"strings"       // 验证不透明身份并清理人工理由外部空白。
	"time"          // 执行精确 48/72 小时 UTC 比较。
	"unicode/utf8"  // 按用户可见字符限制人工理由。

	"github.com/jackc/pgx/v5"        // 让连接池和测试连接共享事务入口。
	"golang.org/x/text/unicode/norm" // 统一人工理由兼容字符但保留合法正文。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth" // 接收认证模块已验证的账号投影。
)

const staffReminderDelay = 48 * time.Hour  // 最后有效联系满 48 小时后进入负责人提醒。
const ownerAttentionDelay = 72 * time.Hour // 最后有效联系满 72 小时后进入老板人工关注。
const requiredNoReplyAttempts = 3          // 同一线程至少三次连续待回复尝试才允许升级。

var ErrInvalidDependencies = errors.New("attention dependencies are invalid") // 数据库、时钟或身份能力缺失。
var ErrForbidden = errors.New("attention access is forbidden")                // 当前账号不具备对应员工或老板能力。
var ErrInvalidInput = errors.New("attention input is invalid")                // 人工结论或身份形状不满足冻结合同。
var ErrNotFound = errors.New("attention object was not found")                // 未知事项或学生共享安全反馈。
var ErrVersionConflict = errors.New("attention version conflicts")            // 事项已结论或页面版本落后。
var ErrIdempotencyConflict = errors.New("attention idempotency conflicts")    // 同一确认键已经绑定另一学生意图。
var ErrWriteFailed = errors.New("attention write failed")                     // 事务没有形成完整事实。

// EvidenceRef 是关注事项允许保存的最小证据，只包含对象种类和不透明身份。
type EvidenceRef struct {
	ObjectType string `json:"object_type"` // ObjectType 只允许 follow_up 或 student_event。
	ObjectID   string `json:"object_id"`   // ObjectID 引用原始受保护事实而不复制正文。
}

// Reminder 是员工本人责任范围内的 48 小时提醒投影。
type Reminder struct {
	StudentID          string    `json:"student_id"`            // StudentID 供工作台打开已授权学生。
	LastValidContactAt time.Time `json:"last_valid_contact_at"` // LastValidContactAt 说明提醒从哪个联系事实计算。
	DueAt              time.Time `json:"due_at"`                // DueAt 是精确 48 小时边界。
}

// Case 是老板可见的最小关注事项；理由只在人工结论后出现。
type Case struct {
	ID                   string        `json:"id"`                      // ID 是不透明事项身份。
	StudentID            string        `json:"student_id"`              // StudentID 绑定受保护学生。
	RuleCode             string        `json:"rule_code"`               // RuleCode 是稳定主规则码。
	TriggerCodes         []string      `json:"trigger_codes"`           // TriggerCodes 合并同时成立的规则。
	Evidence             []EvidenceRef `json:"evidence"`                // Evidence 只含去重对象引用。
	FirstTriggeredAt     time.Time     `json:"first_triggered_at"`      // FirstTriggeredAt 保留事项首次成立时间。
	LastTriggeredAt      time.Time     `json:"last_triggered_at"`       // LastTriggeredAt 保留最近新增证据时间。
	Status               string        `json:"status"`                  // Status 是 open、resolved 或 dismissed。
	ConclusionCode       *string       `json:"conclusion_code"`         // ConclusionCode 只由老板选择固定值。
	ConclusionReason     *string       `json:"conclusion_reason"`       // ConclusionReason 不进入事件或审计。
	ConcludedByAccountID *string       `json:"concluded_by_account_id"` // ConcludedByAccountID 保留逐人老板身份。
	ConcludedAt          *time.Time    `json:"concluded_at"`            // ConcludedAt 是可信 UTC 人工结论时间。
	Version              int64         `json:"version"`                 // Version 防止静默改写结论。
	CreatedAt            time.Time     `json:"created_at"`              // CreatedAt 由 PostgreSQL 生成。
	UpdatedAt            time.Time     `json:"updated_at"`              // UpdatedAt 由 PostgreSQL 生成。
}

// ConclusionInput 是老板对一个开放事项提交的完整人工判断。
type ConclusionInput struct {
	ConclusionCode string // ConclusionCode 来自四个冻结结论码。
	Reason         string // Reason 是 1..500 字符人工理由。
	Version        int64  // Version 绑定老板页面读取的旧事项。
}

// Commands 是关注领域的窄公开接口，调用方无需理解规则 SQL、证据指纹或锁顺序。
type Commands struct {
	data        *store                       // data 执行模块私有 PostgreSQL 操作。
	now         func() time.Time             // now 是所有规则和结论的唯一可信 UTC 来源。
	newIdentity func(string) (string, error) // newIdentity 生成事项和审计身份。
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error) // pgx.Conn 与 pgxpool.Pool 均满足此入口。
}

// evidenceFact 给最小引用附加内部规则时间；时间不会写入公开 evidence JSON。
type evidenceFact struct {
	reference  EvidenceRef // reference 是最终可保存的最小对象引用。
	occurredAt time.Time   // occurredAt 用于 72 小时和先后顺序判断。
}

// replyFact 保存逐线程计算连续未回复序列所需的最少列。
type replyFact struct {
	evidenceFact            // evidenceFact 提供跟进引用和联系时间。
	threadID     string     // threadID 隔离不同待回复事项。
	repliedAt    *time.Time // repliedAt 非空且已到达时重置本线程。
}

// attentionFacts 是一次学生评估事务内读取的完整确定性输入。
type attentionFacts struct {
	lastValidContact *evidenceFact  // lastValidContact 驱动普通 72 小时无联系。
	complaints       []evidenceFact // complaints 保存已确认投诉事件。
	overdueFollowUps []evidenceFact // overdueFollowUps 保存不同逾期跟进。
	replyFollowUps   []replyFact    // replyFollowUps 按线程和联系时间稳定排序。
}

// evaluation 是去除旧事项已消费证据后的本次新增关注事实。
type evaluation struct {
	triggerCodes []string      // triggerCodes 只包含拥有新证据的当前规则。
	evidence     []EvidenceRef // evidence 已去重并稳定排序。
}

var attentionRuleOrder = []string{ // 固定顺序同时决定主规则与数据库数组稳定性。
	"no_contact_72h",         // 普通无有效联系时间升级。
	"complaint",              // 已确认投诉立即升级。
	"third_followup_overdue", // 第三条不同逾期跟进立即升级。
	"student_no_reply",       // 同线程三次且满 72 小时未回复升级。
}

// --- 装配关注深模块 ---
func NewCommands(database transactionSource, now func() time.Time, newIdentity func(string) (string, error)) (*Commands, error) {
	if database == nil || now == nil || newIdentity == nil { // 缺少任一能力时不构造半可用模块。
		return nil, ErrInvalidDependencies
	}
	return &Commands{data: &store{database: database}, now: now, newIdentity: newIdentity}, nil // 所有副作用都集中到私有 store。
}

// --- 根据当前事实确定性形成或扩展关注事项 ---
func (commands *Commands) Evaluate(requestContext context.Context, studentID string) error {
	if !validStudentID(studentID) { // 非法和未知学生共享不存在反馈。
		return ErrNotFound
	}

	transaction, beginError := commands.data.database.Begin(requestContext) // 一个学生评估拥有一个提交边界。
	if beginError != nil {
		return ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }()                                           // 成功提交后 Rollback 是无害空操作。
	if lockError := commands.data.lockStudent(requestContext, transaction, studentID); lockError != nil { // 学生锁串行化同聚合评估。
		return lockError
	}
	_, evaluationError := commands.evaluateLocked(requestContext, transaction, studentID, commands.now().UTC())
	if evaluationError != nil {
		return evaluationError
	}
	return commitEvaluation(requestContext, transaction)
}

// --- 在已锁定学生的事务内消费新证据，供单人扫描与确认投诉共享 ---
func (commands *Commands) evaluateLocked(requestContext context.Context, transaction pgx.Tx, studentID string, now time.Time) (*Case, error) {
	facts, factsError := commands.data.loadAttentionFacts(requestContext, transaction, studentID, now)
	if factsError != nil {
		return nil, factsError
	}
	existingCases, casesError := commands.data.listStudentCases(requestContext, transaction, studentID)
	if casesError != nil {
		return nil, casesError
	}
	result := buildEvaluation(facts, existingCases, now) // 纯计算先完成，再决定是否写入。
	if len(result.evidence) == 0 {                       // 没有新证据时重复扫描不得推进版本。
		return findOpenCase(existingCases), nil
	}

	openCase := findOpenCase(existingCases) // 每名学生最多扩展一个当前开放事项。
	if openCase != nil {
		merged := mergeOpenCase(*openCase, result) // 新证据与当前开放事项形成一个完整事实包。
		updated, updateError := commands.data.updateOpenCase(requestContext, transaction, merged, now)
		if updateError != nil {
			return nil, updateError
		}
		return &updated, nil
	}
	caseID, identityError := commands.newIdentity("AC") // 只有确需新事项时才消耗身份。
	if identityError != nil || caseID == "" {
		return nil, ErrWriteFailed
	}
	created := Case{ID: caseID, StudentID: studentID, RuleCode: result.triggerCodes[0], TriggerCodes: result.triggerCodes, Evidence: result.evidence, FirstTriggeredAt: now, LastTriggeredAt: now, Status: "open", Version: 1}
	inserted, insertError := commands.data.insertCase(requestContext, transaction, created)
	if insertError != nil { // 新事项和证据指纹同事务写入。
		return nil, insertError
	}
	return &inserted, nil
}

// --- 老板显式重检全部学生，把已有确定事实物化为最小关注队列 ---
func (commands *Commands) EvaluateAll(requestContext context.Context, actor auth.Account) ([]Case, error) {
	if !eligibleOwner(actor) {
		return nil, ErrForbidden
	}
	transaction, beginError := commands.data.database.Begin(requestContext)
	if beginError != nil {
		return nil, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }()
	if _, actorError := commands.data.requireActor(requestContext, transaction, actor.ID, "owner"); actorError != nil {
		return nil, actorError
	}
	studentIDs, listError := commands.data.listStudentIDs(requestContext, transaction)
	if listError != nil {
		return nil, listError
	}
	now := commands.now().UTC()
	for _, studentID := range studentIDs {
		if lockError := commands.data.lockStudent(requestContext, transaction, studentID); lockError != nil {
			return nil, lockError
		}
		if _, evaluationError := commands.evaluateLocked(requestContext, transaction, studentID, now); evaluationError != nil {
			return nil, evaluationError
		}
	}
	cases, casesError := commands.data.listCases(requestContext, transaction)
	if casesError != nil {
		return nil, casesError
	}
	if commitError := transaction.Commit(requestContext); commitError != nil {
		return nil, ErrWriteFailed
	}
	return cases, nil
}

// --- 确认一条投诉事实，并在同一事务立即形成老板关注事项 ---
func (commands *Commands) ConfirmComplaint(requestContext context.Context, actor auth.Account, requestID string, idempotencyKey string, studentID string) (Case, error) {
	if !eligibleOperator(actor) {
		return Case{}, ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validText(idempotencyKey, 16, 128) || !validStudentID(studentID) {
		return Case{}, ErrInvalidInput
	}
	digest := sha256.Sum256([]byte("attention.complaint_confirm\x00" + studentID))
	eventID, eventError := commands.newIdentity("EV")
	auditID, auditError := commands.newIdentity("AU")
	if eventError != nil || auditError != nil || eventID == "" || auditID == "" {
		return Case{}, ErrWriteFailed
	}
	transaction, beginError := commands.data.database.Begin(requestContext)
	if beginError != nil {
		return Case{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }()
	currentActor, actorError := commands.data.requireOperator(requestContext, transaction, actor.ID)
	if actorError != nil {
		return Case{}, actorError
	}
	if scopeError := commands.data.lockScopedStudent(requestContext, transaction, currentActor, studentID); scopeError != nil {
		return Case{}, scopeError
	}
	if replay, found, replayError := commands.data.findComplaintReplay(requestContext, transaction, currentActor.id, idempotencyKey, digest); replayError != nil || found {
		return replay, replayError
	}
	now := commands.now().UTC()
	if insertError := commands.data.insertComplaintEvent(requestContext, transaction, eventID, currentActor.id, studentID, now); insertError != nil {
		return Case{}, insertError
	}
	attentionCase, evaluationError := commands.evaluateLocked(requestContext, transaction, studentID, now)
	if evaluationError != nil || attentionCase == nil {
		if evaluationError != nil {
			return Case{}, evaluationError
		}
		return Case{}, ErrWriteFailed
	}
	if insertError := commands.data.insertComplaintAudit(requestContext, transaction, auditID, currentActor.id, attentionCase.ID, requestID); insertError != nil {
		return Case{}, insertError
	}
	if insertError := commands.data.insertComplaintIdempotency(requestContext, transaction, currentActor.id, idempotencyKey, digest, attentionCase.ID); insertError != nil {
		return Case{}, insertError
	}
	if commitError := transaction.Commit(requestContext); commitError != nil {
		return Case{}, ErrWriteFailed
	}
	return *attentionCase, nil
}

// --- 按当前员工责任范围列出 48 小时提醒 ---
func (commands *Commands) ListStaffReminders(requestContext context.Context, actor auth.Account) ([]Reminder, error) {
	if !eligibleStaff(actor) { // 角色门禁先于数据库和学生事实读取。
		return nil, ErrForbidden
	}

	transaction, beginError := commands.data.database.Begin(requestContext) // 列表读取仍使用一致事务快照。
	if beginError != nil {
		return nil, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }()
	currentActor, actorError := commands.data.requireActor(requestContext, transaction, actor.ID, "staff")
	if actorError != nil {
		return nil, actorError
	}
	now := commands.now().UTC() // 提醒边界在整个查询期间保持固定。
	reminders, listError := commands.data.listStaffReminders(requestContext, transaction, currentActor, now)
	if listError != nil {
		return nil, listError
	}
	if commitError := transaction.Commit(requestContext); commitError != nil {
		return nil, ErrWriteFailed
	}
	return reminders, nil
}

// --- 只向当前老板返回全部关注事项 ---
func (commands *Commands) ListCases(requestContext context.Context, actor auth.Account) ([]Case, error) {
	if !eligibleOwner(actor) { // 员工不能用对象是否存在推断老板队列内容。
		return nil, ErrForbidden
	}

	transaction, beginError := commands.data.database.Begin(requestContext) // 账号复核和列表共享一致快照。
	if beginError != nil {
		return nil, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }()
	if _, actorError := commands.data.requireActor(requestContext, transaction, actor.ID, "owner"); actorError != nil {
		return nil, actorError
	}
	cases, listError := commands.data.listCases(requestContext, transaction)
	if listError != nil {
		return nil, listError
	}
	if commitError := transaction.Commit(requestContext); commitError != nil {
		return nil, ErrWriteFailed
	}
	return cases, nil
}

// --- 由老板版本化记录不可改写的人工结论 ---
func (commands *Commands) Conclude(requestContext context.Context, actor auth.Account, requestID string, caseID string, input ConclusionInput) (Case, error) {
	if !eligibleOwner(actor) { // 角色拒绝先于事项 ID 和正文处理，防止员工探测存在性。
		return Case{}, ErrForbidden
	}
	prepared, prepareError := prepareConclusion(requestID, caseID, input)
	if prepareError != nil {
		return Case{}, prepareError
	}
	auditID, identityError := commands.newIdentity("AU") // 审计身份在事务前准备，避免提交后失败。
	if identityError != nil || auditID == "" {
		return Case{}, ErrWriteFailed
	}

	transaction, beginError := commands.data.database.Begin(requestContext) // 事项终态与成功审计必须共同提交。
	if beginError != nil {
		return Case{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }()
	currentActor, actorError := commands.data.requireActor(requestContext, transaction, actor.ID, "owner")
	if actorError != nil {
		return Case{}, actorError
	}
	current, currentError := commands.data.getCase(requestContext, transaction, caseID, true)
	if currentError != nil {
		return Case{}, currentError
	}
	if current.Status != "open" || current.Version != prepared.version { // 已结论和旧页面共享版本冲突反馈。
		return Case{}, ErrVersionConflict
	}
	concludedAt := commands.now().UTC() // 结论与审计使用同一可信时间来源。
	concluded, conclusionError := commands.data.concludeCase(requestContext, transaction, currentActor.id, current.ID, prepared, concludedAt)
	if conclusionError != nil {
		return Case{}, conclusionError
	}
	if auditError := commands.data.insertConclusionAudit(requestContext, transaction, auditID, currentActor.id, current.ID, requestID, concluded); auditError != nil {
		return Case{}, auditError
	}
	if commitError := transaction.Commit(requestContext); commitError != nil {
		return Case{}, ErrWriteFailed
	}
	return concluded, nil // 人工结论只反馈事项，不触碰学生服务状态。
}

type preparedConclusion struct {
	code    string // code 是固定人工结论码。
	reason  string // reason 已完成 NFKC 和外部空白清理。
	status  string // status 由 code 唯一推导为 resolved 或 dismissed。
	version int64  // version 绑定页面读取的旧事项。
}

// --- 在事务前准备人工结论 ---
func prepareConclusion(requestID string, caseID string, input ConclusionInput) (preparedConclusion, error) {
	reason := norm.NFKC.String(strings.TrimSpace(input.Reason))                                                   // 只规范化人工正文，不写入审计。
	if !validText(requestID, 8, 100) || !validCaseID(caseID) || !validText(reason, 1, 500) || input.Version < 1 { // 所有形状错误共享安全反馈。
		return preparedConclusion{}, ErrInvalidInput
	}
	if !validConclusionCode(input.ConclusionCode) {
		return preparedConclusion{}, ErrInvalidInput
	}
	status := "resolved" // 三个继续处理结论都进入已解决终态。
	if input.ConclusionCode == "dismiss" {
		status = "dismissed" // 只有 dismiss 与数据库 dismissed 状态配对。
	}
	return preparedConclusion{code: input.ConclusionCode, reason: reason, status: status, version: input.Version}, nil
}

// --- 从当前事实生成只含新证据的确定性评估 ---
func buildEvaluation(facts attentionFacts, existingCases []Case, now time.Time) evaluation {
	candidates := make(map[string][]EvidenceRef, len(attentionRuleOrder)) // 每个规则先保存完整当前证据。
	if facts.lastValidContact != nil && !now.Before(facts.lastValidContact.occurredAt.Add(ownerAttentionDelay)) {
		candidates["no_contact_72h"] = []EvidenceRef{facts.lastValidContact.reference} // 最新有效联系是时间升级的唯一引用。
	}
	if len(facts.complaints) > 0 {
		candidates["complaint"] = referencesOf(facts.complaints) // 每条确认投诉都是独立证据。
	}
	if len(facts.overdueFollowUps) >= requiredNoReplyAttempts {
		candidates["third_followup_overdue"] = referencesOf(facts.overdueFollowUps) // 不同跟进 ID 防止重复计数。
	}
	if replyEvidence := noReplyEvidence(facts.replyFollowUps, now); len(replyEvidence) > 0 {
		candidates["student_no_reply"] = replyEvidence // 线程内回复只重置自己的连续序列。
	}

	consumed := consumedEvidence(existingCases) // 历史事项已经引用的证据不能重开或改写旧结论。
	result := evaluation{triggerCodes: make([]string, 0, len(attentionRuleOrder)), evidence: make([]EvidenceRef, 0, 8)}
	seen := make(map[string]bool) // 同一跟进同时证明多个规则时只保存一次引用。
	for _, ruleCode := range attentionRuleOrder {
		newReferences := excludeConsumed(candidates[ruleCode], consumed) // 每个触发必须至少贡献一条新证据。
		if len(newReferences) == 0 {
			continue
		}
		result.triggerCodes = append(result.triggerCodes, ruleCode) // 固定规则顺序也固定主规则。
		for _, reference := range newReferences {
			key := evidenceKey(reference) // 对象类型与身份共同构成去重键。
			if !seen[key] {
				seen[key] = true
				result.evidence = append(result.evidence, reference)
			}
		}
	}
	sortEvidence(result.evidence) // 稳定 JSON 顺序保证重复评估指纹一致。
	return result
}

// --- 只保留每个回复线程最后一次有效回复后的连续失败 ---
func noReplyEvidence(facts []replyFact, now time.Time) []EvidenceRef {
	byThread := make(map[string][]evidenceFact) // 每个线程独立累计当前连续失败。
	for _, fact := range facts {                // store 已按线程、时间和身份稳定排序。
		if fact.repliedAt != nil && !fact.repliedAt.After(now) {
			byThread[fact.threadID] = nil // 明确到达的学生回复清空此前失败。
			continue
		}
		byThread[fact.threadID] = append(byThread[fact.threadID], fact.evidenceFact) // 无回复待办加入当前序列。
	}
	threadIDs := make([]string, 0, len(byThread)) // map 遍历前先固定线程顺序。
	for threadID := range byThread {
		threadIDs = append(threadIDs, threadID)
	}
	sort.Strings(threadIDs)
	result := make([]EvidenceRef, 0, 8)
	for _, threadID := range threadIDs {
		attempts := byThread[threadID] // 当前线程只观察最后一次回复之后的尝试。
		if len(attempts) < requiredNoReplyAttempts || now.Before(attempts[0].occurredAt.Add(ownerAttentionDelay)) {
			continue // 次数和 72 小时必须同时满足。
		}
		result = append(result, referencesOf(attempts)...)
	}
	return result
}

// --- 合并当前开放事项与本次新增证据 ---
func mergeOpenCase(openCase Case, result evaluation) Case {
	triggerSet := make(map[string]bool, len(openCase.TriggerCodes)+len(result.triggerCodes)) // 保留旧规则并加入新规则。
	for _, triggerCode := range openCase.TriggerCodes {
		triggerSet[triggerCode] = true
	}
	for _, triggerCode := range result.triggerCodes {
		triggerSet[triggerCode] = true
	}
	openCase.TriggerCodes = orderedTriggers(triggerSet) // 数据库数组保持固定业务顺序。
	evidenceSet := make(map[string]EvidenceRef, len(openCase.Evidence)+len(result.evidence))
	for _, reference := range openCase.Evidence {
		evidenceSet[evidenceKey(reference)] = reference // 先保留事项已经公开的证据。
	}
	for _, reference := range result.evidence {
		evidenceSet[evidenceKey(reference)] = reference // 相同对象引用只保留一份。
	}
	openCase.Evidence = make([]EvidenceRef, 0, len(evidenceSet))
	for _, reference := range evidenceSet {
		openCase.Evidence = append(openCase.Evidence, reference)
	}
	sortEvidence(openCase.Evidence)
	return openCase
}

// --- 找到当前唯一开放事项 ---
func findOpenCase(cases []Case) *Case {
	for index := range cases {
		if cases[index].Status == "open" {
			return &cases[index] // 调用方立即复制该值再合并，不直接持久化切片元素。
		}
	}
	return nil
}

// --- 收集全部历史事项已经消费的证据 ---
func consumedEvidence(cases []Case) map[string]bool {
	consumed := make(map[string]bool)
	for _, attentionCase := range cases {
		for _, reference := range attentionCase.Evidence {
			consumed[evidenceKey(reference)] = true // 开放和终态事项都拥有自己的证据。
		}
	}
	return consumed
}

// --- 移除已经属于任一历史事项的引用 ---
func excludeConsumed(references []EvidenceRef, consumed map[string]bool) []EvidenceRef {
	result := make([]EvidenceRef, 0, len(references))
	for _, reference := range references {
		if !consumed[evidenceKey(reference)] {
			result = append(result, reference) // 只让第一次出现的证据进入新提交。
		}
	}
	return result
}

// --- 从带时间事实提取公开引用 ---
func referencesOf(facts []evidenceFact) []EvidenceRef {
	references := make([]EvidenceRef, 0, len(facts))
	for _, fact := range facts {
		references = append(references, fact.reference) // 时间只参与规则判断，公开结果只保留引用。
	}
	return references
}

// --- 按对象类型和身份固定证据顺序 ---
func sortEvidence(evidence []EvidenceRef) {
	sort.Slice(evidence, func(left int, right int) bool {
		if evidence[left].ObjectType == evidence[right].ObjectType {
			return evidence[left].ObjectID < evidence[right].ObjectID // 同类型按不透明身份稳定排列。
		}
		return evidence[left].ObjectType < evidence[right].ObjectType
	})
}

// --- 把触发码集合恢复为业务固定顺序 ---
func orderedTriggers(triggerSet map[string]bool) []string {
	triggers := make([]string, 0, len(triggerSet))
	for _, ruleCode := range attentionRuleOrder {
		if triggerSet[ruleCode] {
			triggers = append(triggers, ruleCode)
		}
	}
	return triggers
}

// --- 提交只含确定性评估变化的事务 ---
func commitEvaluation(requestContext context.Context, transaction pgx.Tx) error {
	if commitError := transaction.Commit(requestContext); commitError != nil {
		return ErrWriteFailed
	}
	return nil
}

func evidenceKey(reference EvidenceRef) string {
	return reference.ObjectType + ":" + reference.ObjectID
}
func eligibleOwner(actor auth.Account) bool {
	return actor.ID != "" && actor.Role == "owner" && actor.State == "active" && !actor.MustChangePassword
}
func eligibleStaff(actor auth.Account) bool {
	return actor.ID != "" && actor.Role == "staff" && actor.State == "active" && !actor.MustChangePassword && actor.StaffProfileID != nil
}
func eligibleOperator(actor auth.Account) bool {
	return eligibleOwner(actor) || eligibleStaff(actor)
}
func validStudentID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "S-")
}
func validCaseID(value string) bool {
	return len(value) >= 16 && len(value) <= 84 && strings.HasPrefix(value, "AC-")
}
func validConclusionCode(value string) bool {
	return value == "continue_service" || value == "contact_student" || value == "internal_review" || value == "dismiss"
}
func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}
