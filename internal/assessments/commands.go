/*
受邀测评指令：用一个受限能力读取空白表单，并在提交时协调资料、评分和完成事实。
公开接口只有 Form 与 Submit；PostgreSQL 锁、问卷私有定义和跨表写入都留在模块内部。
调用示例：commands.Form(ctx, capability)、commands.Submit(ctx, capability, requestID, key, input)。
*/
package assessments

import (
	"context"       // 驱动表单读取和后续原子提交事务。
	"crypto/sha256" // 把原始能力秘密转换为数据库可匹配的固定摘要。
	"encoding/json" // 将数据库公开问卷解码为窄学生投影。
	"errors"        // 暴露可用 errors.Is 比较的稳定领域失败。
	"strings"       // 检查不透明能力身份的固定前缀。
	"time"          // 注入精确 UTC 过期与提交时间。
	"unicode/utf8"  // 按公开字符上限验证请求文本。

	"github.com/jackc/pgx/v5" // 只向模块内部暴露短事务能力。
)

var ErrInvalidDependencies = errors.New("assessment dependencies are invalid") // 模块装配缺少数据库、时钟或身份生成器。
var ErrInvalidCapability = errors.New("assessment capability is invalid")      // 未知、错误、过期或动态失权能力共享失败。
var ErrInvalidInput = errors.New("assessment input is invalid")                // 问卷版本、答案或资料白名单不合法。
var ErrVersionConflict = errors.New("assessment student version conflicts")    // 邀请冻结的学生版本已落后。
var ErrIdempotencyConflict = errors.New("assessment idempotency conflicts")    // 同一提交键不能代表另一份意图。
var ErrWriteFailed = errors.New("assessment write failed")                     // 数据库或生成能力未完成可靠写入。

var studentProfileFields = []string{ // 表单始终返回完整十五字段身份，但绝不读取现有字段值。
	"name", "phone", "wechat", "school", "major", "grade", "current_location", "target_city", "target_position",
	"expected_salary", "job_intention", "project_experience", "internship_experience", "skills", "certificates",
}

// Capability 是浏览器受限 Cookie 提供的会话身份和一次原始秘密。
type Capability struct {
	ID     string `json:"id"`     // ID 只定位一条受限会话，不代表后台账号。
	Secret string `json:"secret"` // Secret 仅在内存中计算 SHA-256，不进入持久化或反馈。
}

// Option 是学生可见的单个固定选项，不包含任何权重。
type Option struct {
	ID    string `json:"id"`    // ID 把答案绑定到所属问题。
	Label string `json:"label"` // Label 是版本化公开文字。
}

// Question 是学生可见的一个固定问题及其四个有序选项。
type Question struct {
	ID      string   `json:"id"`      // ID 是答案对象的键。
	Prompt  string   `json:"prompt"`  // Prompt 是公开问题文字。
	Options []Option `json:"options"` // Options 保留数据库注册顺序。
}

// Form 只反馈问卷版本、空白资料字段和公开问题。
type Form struct {
	AssessmentVersion string             `json:"assessment_version"` // AssessmentVersion 固定后续提交的定义。
	StudentFields     map[string]*string `json:"student_fields"`     // StudentFields 的值全部为空，避免回显既有资料。
	Questions         []Question         `json:"questions"`          // Questions 恰好来自活动注册表。
}

// SubmitInput 是学生一次完整资料与十题答案意图。
type SubmitInput struct {
	AssessmentVersion string             `json:"assessment_version"` // AssessmentVersion 必须等于能力绑定版本。
	StudentFields     map[string]*string `json:"student_fields"`     // StudentFields 只能出现十五个固定键。
	Answers           map[string]string  `json:"answers"`            // Answers 必须逐题绑定一个已注册选项。
}

// Receipt 是学生可见的全部完成反馈，只携带安全沟通风格而不携带答案或内部结果。
type Receipt struct {
	Completed          bool         `json:"completed"`           // Completed 只在完整事务提交后为 true。
	CommunicationStyle PublicResult `json:"communication_style"` // CommunicationStyle 是与该提交绑定的四字段窄投影。
}

// Commands 把能力复核和问卷定义隐藏在两个高杠杆动作后面。
type Commands struct {
	data        *store                       // data 集中执行不提交事务的显式 SQL。
	now         func() time.Time             // now 为过期与提交提供单一可信时间。
	newIdentity func(string) (string, error) // newIdentity 为测评、事件和审计生成独立身份。
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error) // Begin 创建调用方拥有的短事务。
}

// --- 装配测评深模块 ---
func NewCommands(database transactionSource, now func() time.Time, newIdentity func(string) (string, error)) (*Commands, error) {
	if database == nil || now == nil || newIdentity == nil { // 任一依赖缺失都会让授权或原子性不可证明。
		return nil, ErrInvalidDependencies
	}

	return &Commands{data: &store{database: database}, now: now, newIdentity: newIdentity}, nil // 只暴露两个业务动作。
}

// --- 读取空白资料与固定公开问卷 ---
func (commands *Commands) Form(requestContext context.Context, capability Capability) (Form, error) {
	if !validCapability(capability) { // 无效形状与未知数据库能力共享同一公开反馈。
		return Form{}, ErrInvalidCapability
	}

	digest := sha256.Sum256([]byte(capability.Secret))                      // 原始秘密只在当前栈帧转换为摘要。
	transaction, beginError := commands.data.database.Begin(requestContext) // 表单读取也保持一个一致授权快照。
	if beginError != nil {                                                  // 数据库不可用时不能猜测问卷或能力事实。
		return Form{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }() // 任何提前返回都释放本次短事务。

	record, capabilityError := commands.data.getCapability(requestContext, transaction, capability.ID, digest, commands.now().UTC()) // 每次读取动态复核能力。
	if capabilityError != nil {                                                                                                      // 未通过能力门禁时不解码问卷或读取学生资料。
		return Form{}, capabilityError
	}
	questions, questionError := decodePublicQuestions(record.publicQuestions) // 私有评分定义从不进入公开结构。
	if questionError != nil {                                                 // 注册表损坏必须失败关闭，不能返回部分题目。
		return Form{}, ErrWriteFailed
	}
	if commitError := transaction.Commit(requestContext); commitError != nil { // 未提交的一致读取不能报告成功。
		return Form{}, ErrWriteFailed
	}

	return Form{AssessmentVersion: record.assessmentVersion, StudentFields: blankStudentFields(), Questions: questions}, nil // 反馈只含固定公开事实。
}

// --- 原子提交资料与权威测评 ---
func (commands *Commands) Submit(requestContext context.Context, capability Capability, requestID string, idempotencyKey string, input SubmitInput) (Receipt, error) {
	if !validCapability(capability) { // 无效会话形状不能进入幂等或业务查询。
		return Receipt{}, ErrInvalidCapability
	}
	if !validText(requestID, 8, 100) || !validText(idempotencyKey, 16, 128) { // 请求证据和重试键必须满足共享合同。
		return Receipt{}, ErrInvalidInput
	}
	prepared, prepareError := prepareSubmit(input) // 资料白名单和明显答案形状在任何数据库写入前冻结。
	if prepareError != nil {
		return Receipt{}, prepareError
	}
	requestDigest, digestError := submitDigest(capability, prepared) // 幂等摘要绑定能力秘密与规范化意图。
	if digestError != nil {
		return Receipt{}, ErrWriteFailed
	}

	transaction, beginError := commands.data.database.Begin(requestContext) // 后续五类写入共享一个短事务。
	if beginError != nil {
		return Receipt{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(requestContext) }()                                                                    // 任一步失败都会撤销已执行的资料或证据写入。
	if lockError := commands.data.lockSubmitIntent(requestContext, transaction, capability.ID, idempotencyKey); lockError != nil { // 同能力同 key 网络重试串行化。
		return Receipt{}, lockError
	}
	if replay, found, replayError := commands.data.findSubmitReplay(requestContext, transaction, capability.ID, idempotencyKey, requestDigest); replayError != nil || found { // 已提交意图原样返回安全完成回执。
		if replayError != nil {
			return Receipt{}, replayError
		}
		if commitError := transaction.Commit(requestContext); commitError != nil { // 重放读取也只在事务成功后反馈。
			return Receipt{}, ErrWriteFailed
		}
		return replay, nil
	}

	now := commands.now().UTC()                                                                                               // 等待同键重试锁后读取一次时间，授权和写入共享该事实。
	capabilityDigest := sha256.Sum256([]byte(capability.Secret))                                                              // 原始秘密不会越过 Commands 进入 store。
	record, capabilityError := commands.data.getCapability(requestContext, transaction, capability.ID, capabilityDigest, now) // 锁定动态授权与学生版本。
	if capabilityError != nil {
		return Receipt{}, capabilityError
	}
	if prepared.assessmentVersion != record.assessmentVersion { // 客户端不能选择能力之外的问卷定义。
		return Receipt{}, ErrInvalidInput
	}
	if record.invitedStudentVersion != record.currentStudentVersion { // 签发后的学生并发修改要求补发或人工核对。
		return Receipt{}, ErrVersionConflict
	}
	questions, questionError := decodePublicQuestions(record.publicQuestions) // 答案白名单直接来自同一活动注册表。
	if questionError != nil {
		return Receipt{}, ErrWriteFailed
	}
	scoreBody, recommendationBody, scoreError := scoreAssessment(questions, record.scoringDefinition, prepared.answers) // 服务器独占评分和内部材料派生。
	if errors.Is(scoreError, errAnswerOutsideQuestionnaire) {
		return Receipt{}, ErrInvalidInput
	}
	if scoreError != nil {
		return Receipt{}, ErrWriteFailed
	}
	communicationStyle, projectionValid := publicResultFromBodies(scoreBody, recommendationBody) // 在任何写入前失败关闭未知类型或损坏摘要。
	if !projectionValid {
		return Receipt{}, ErrWriteFailed
	}
	receipt := Receipt{Completed: true, CommunicationStyle: communicationStyle}  // 同一对象同时驱动首次响应和幂等存储。
	assessmentID, eventID, auditID, identityError := commands.submitIdentities() // 所有待写对象在第一个写动作前拥有独立身份。
	if identityError != nil {
		return Receipt{}, identityError
	}

	studentVersion, studentError := commands.data.updateStudent(requestContext, transaction, record, capability.ID, prepared.studentFields, now)
	if studentError != nil {
		return Receipt{}, studentError
	}
	answersBody, answerEncodingError := json.Marshal(prepared.answers) // 只在业务表保存权威答案 JSON。
	if answerEncodingError != nil {
		return Receipt{}, ErrWriteFailed
	}
	storedAssessmentID, assessmentError := commands.data.saveAssessment(requestContext, transaction, assessmentID, record, answersBody, scoreBody, recommendationBody, now)
	if assessmentError != nil {
		return Receipt{}, assessmentError
	}
	if eventError := commands.data.insertAssessmentEvent(requestContext, transaction, eventID, capability.ID, record.studentID, storedAssessmentID, record.assessmentVersion, studentVersion, now); eventError != nil { // 事件不复制答案或资料。
		return Receipt{}, eventError
	}
	if auditError := commands.data.insertAssessmentAudit(requestContext, transaction, auditID, capability.ID, storedAssessmentID, requestID, record.assessmentVersion, studentVersion, now); auditError != nil { // 审计只保存版本和对象引用。
		return Receipt{}, auditError
	}
	if idempotencyError := commands.data.insertSubmitIdempotency(requestContext, transaction, capability.ID, idempotencyKey, requestDigest, receipt, storedAssessmentID, now); idempotencyError != nil { // 重试事实与安全结果共同提交。
		return Receipt{}, idempotencyError
	}
	if completionError := commands.data.completeInvitation(requestContext, transaction, record, now); completionError != nil { // 最后销毁会话摘要；失败会回滚前面全部事实。
		return Receipt{}, completionError
	}
	if commitError := transaction.Commit(requestContext); commitError != nil { // 只有真正提交后才能显示成功。
		return Receipt{}, ErrWriteFailed
	}
	return receipt, nil
}

// --- 为测评、事件与审计生成独立身份 ---
func (commands *Commands) submitIdentities() (string, string, string, error) {
	assessmentID, assessmentError := commands.newIdentity("AS")                                                                                                                   // AS 标识可版本化权威测评。
	eventID, eventError := commands.newIdentity("EV")                                                                                                                             // EV 标识学生时间线事实。
	auditID, auditError := commands.newIdentity("AU")                                                                                                                             // AU 标识最小审计事实。
	if assessmentError != nil || eventError != nil || auditError != nil || !validIdentity(assessmentID, "AS") || !validIdentity(eventID, "EV") || !validIdentity(auditID, "AU") { // 生成器异常不能交给数据库猜测。
		return "", "", "", ErrWriteFailed
	}
	return assessmentID, eventID, auditID, nil
}

// --- 解码并验证公开十题形状 ---
func decodePublicQuestions(body []byte) ([]Question, error) {
	questions := make([]Question, 0, 10)                                     // 预分配固定十题，避免暴露额外注册内容。
	if decodeError := json.Unmarshal(body, &questions); decodeError != nil { // 数据库 JSON 必须能映射到公开结构。
		return nil, decodeError
	}
	if len(questions) != 10 { // 当前固定问卷不得静默增减题目。
		return nil, ErrWriteFailed
	}
	for _, question := range questions { // 每题必须拥有身份、文字和恰好四个公开选项。
		if question.ID == "" || question.Prompt == "" || len(question.Options) != 4 {
			return nil, ErrWriteFailed
		}
		for _, option := range question.Options { // 空选项不能成为可提交答案。
			if option.ID == "" || option.Label == "" {
				return nil, ErrWriteFailed
			}
		}
	}
	return questions, nil // 数组顺序保持 migration 注册顺序。
}

// --- 建立不回显现有资料的十五字段投影 ---
func blankStudentFields() map[string]*string {
	fields := make(map[string]*string, len(studentProfileFields)) // map 只表达允许填写哪些业务字段。
	for _, fieldName := range studentProfileFields {              // nil 明确表示表单初始值为空。
		fields[fieldName] = nil
	}
	return fields // 调用方无法借此读取学生数据库现值。
}

// --- 检查受限能力公开形状 ---
func validCapability(capability Capability) bool {
	return validIdentity(capability.ID, "IS") && validText(capability.Secret, 32, 256) // 会话 ID 与秘密都必须满足冻结合同。
}

// --- 检查带领域前缀的不透明身份 ---
func validIdentity(value string, prefix string) bool {
	return len(value) >= len(prefix)+13 && len(value) <= len(prefix)+81 && strings.HasPrefix(value, prefix+"-") // 与 migration 的 12..80 后缀一致。
}

// --- 按 Unicode 字符验证公开文本 ---
func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)                                                                          // PostgreSQL char_length 同样按字符而不是字节计数。
	return utf8.ValidString(value) && length >= minimum && length <= maximum && !strings.ContainsRune(value, '\x00') // NUL 不能进入 PostgreSQL text。
}
