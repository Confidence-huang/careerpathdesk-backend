/*
测评规则实现：验证十五字段资料与十题答案，并只依据数据库 scoring_definition 生成内部结果。
该文件是无 I/O 的私有实现；调用方得到可持久化 JSON，学生接口永不接触分数或建议。
调用示例：prepareSubmit(input)、scoreAssessment(questions, definition, answers)。
*/
package assessments

import (
	"crypto/sha256" // 将能力秘密与规范化提交意图绑定为幂等摘要。
	"encoding/json" // 解码服务器规则并生成权威 JSON 结果。
	"errors"        // 区分学生答案错误与注册表损坏。
	"sort"          // 按固定 core_order 稳定解决同分次序。
	"strings"       // 规范化资料并验证问卷版本前缀。
	"unicode/utf8"  // 让应用字符上限与 PostgreSQL char_length 一致。

	"golang.org/x/text/unicode/norm" // 用 NFKC 消除等价输入的幂等漂移。
)

var errAnswerOutsideQuestionnaire = errors.New("answer is outside questionnaire") // 学生答案不属于当前公开注册表。
var errScoringDefinition = errors.New("scoring definition is invalid")            // 数据库私有规则缺失或自相矛盾。

var studentFieldLimits = map[string]int{ // 每个上限与 migration 的对应 students 列一致。
	"name": 80, "phone": 40, "wechat": 100, "school": 200, "major": 200, "grade": 100,
	"current_location": 200, "target_city": 200, "target_position": 200, "expected_salary": 200,
	"job_intention": 4000, "project_experience": 4000, "internship_experience": 4000,
	"skills": 4000, "certificates": 4000,
}

type preparedStudentFields struct {
	name                 string  // name 是唯一必须非空且每次写入的资料字段。
	phone                *string // 其余指针为 nil 时保留数据库现值。
	wechat               *string
	school               *string
	major                *string
	grade                *string
	currentLocation      *string // currentLocation 是学生当前实际居住地，不等同于求职目标城市。
	targetCity           *string
	targetPosition       *string
	expectedSalary       *string
	jobIntention         *string
	projectExperience    *string
	internshipExperience *string
	skills               *string
	certificates         *string
}

type preparedSubmit struct {
	assessmentVersion string                // assessmentVersion 稍后必须匹配能力绑定版本。
	studentFields     preparedStudentFields // studentFields 已完成白名单、规范化与上限检查。
	answers           map[string]string     // answers 是无别名的十题意图副本。
}

type scoringDefinition struct {
	CoreOrder       []string                  `json:"core_order"`       // CoreOrder 同时定义同分稳定顺序。
	SignalOrder     []string                  `json:"signal_order"`     // SignalOrder 固定内部支持信号顺序。
	SignalThreshold int                       `json:"signal_threshold"` // SignalThreshold 决定人工支持材料入选。
	HybridRules     []hybridRule              `json:"hybrid_rules"`     // HybridRules 覆盖接近的两种核心结果。
	OptionWeights   map[string]map[string]int `json:"option_weights"`   // OptionWeights 是答案到服务器分值的唯一来源。
	ResultMaterial  map[string]resultMaterial `json:"result_material"`  // ResultMaterial 提供中性摘要和建议。
	SupportMaterial map[string]string         `json:"support_material"` // SupportMaterial 只保存内部人工准备文字。
	Disclaimer      string                    `json:"disclaimer"`       // Disclaimer 强制结果等待人工确认。
}

type hybridRule struct {
	PrimaryType   string `json:"primary_type"`   // PrimaryType 是满足规则后的组合结果键。
	Left          string `json:"left"`           // Left 是参与比较的第一个核心键。
	Right         string `json:"right"`          // Right 是参与比较的第二个核心键。
	MinimumScore  int    `json:"minimum_score"`  // MinimumScore 防止低信号偶然组合。
	MaximumGap    int    `json:"maximum_gap"`    // MaximumGap 限制两个核心分数差。
	SecondaryType string `json:"secondary_type"` // SecondaryType 是组合结果的固定次键。
}

type resultMaterial struct {
	Summary string   `json:"summary"` // Summary 是中性、非诊断的内部概括。
	Advice  []string `json:"advice"`  // Advice 是顾问人工确认前的准备材料。
}

type serverScore struct {
	PrimaryType   string         `json:"primary_type"`   // PrimaryType 是权威主结果键。
	SecondaryType string         `json:"secondary_type"` // SecondaryType 保留次高或规则指定结果。
	CoreScores    map[string]int `json:"core_scores"`    // CoreScores 允许内部复核计算。
	SignalScores  map[string]int `json:"signal_scores"`  // SignalScores 解释支持信号阈值。
}

type internalRecommendation struct {
	ReportStatus    string            `json:"report_status"`    // ReportStatus 永远要求人工确认。
	Summary         string            `json:"summary"`          // Summary 来自服务器注册材料。
	Advice          []string          `json:"advice"`           // Advice 不进入学生完成回执。
	SupportSignals  []string          `json:"support_signals"`  // SupportSignals 为 nil 时编码 null，表示无额外信号。
	SupportMaterial map[string]string `json:"support_material"` // SupportMaterial 仅包含越过阈值的键。
	Disclaimer      string            `json:"disclaimer"`       // Disclaimer 防止结果被当作诊断或自动决策。
}

// --- 验证并规范化一次学生提交 ---
func prepareSubmit(input SubmitInput) (preparedSubmit, error) {
	if !validAssessmentVersion(input.AssessmentVersion) || len(input.StudentFields) != len(studentProfileFields) || len(input.Answers) != 10 { // 先拒绝明显不完整形状。
		return preparedSubmit{}, ErrInvalidInput
	}

	fields := make(map[string]*string, len(studentProfileFields)) // 规范副本避免调用方在事务期间修改 map。
	for _, fieldName := range studentProfileFields {              // 每个允许字段都必须显式出现。
		fieldValue, exists := input.StudentFields[fieldName]
		if !exists { // 缺字段与额外字段同属公开白名单失败。
			return preparedSubmit{}, ErrInvalidInput
		}
		normalizedValue, normalizeError := normalizeStudentField(fieldName, fieldValue)
		if normalizeError != nil { // NUL、非法 UTF-8、空必填或超长文本均在写入前拒绝。
			return preparedSubmit{}, ErrInvalidInput
		}
		fields[fieldName] = normalizedValue
	}
	if fields["name"] == nil { // name 是唯一不能用空白表示“保留”的字段。
		return preparedSubmit{}, ErrInvalidInput
	}

	answers := make(map[string]string, len(input.Answers)) // 答案副本把公开意图固定在当前命令内。
	for questionID, optionID := range input.Answers {
		if !validText(questionID, 1, 80) || !validText(optionID, 1, 100) { // 非文本或异常长身份不进入规则查找。
			return preparedSubmit{}, ErrInvalidInput
		}
		answers[questionID] = optionID
	}
	return preparedSubmit{
		assessmentVersion: input.AssessmentVersion,
		studentFields: preparedStudentFields{
			name: *fields["name"], phone: fields["phone"], wechat: fields["wechat"], school: fields["school"],
			major: fields["major"], grade: fields["grade"], currentLocation: fields["current_location"], targetCity: fields["target_city"], targetPosition: fields["target_position"],
			expectedSalary: fields["expected_salary"], jobIntention: fields["job_intention"], projectExperience: fields["project_experience"],
			internshipExperience: fields["internship_experience"], skills: fields["skills"], certificates: fields["certificates"],
		},
		answers: answers,
	}, nil
}

// --- 将空白可选值转为“保留现值” ---
func normalizeStudentField(fieldName string, fieldValue *string) (*string, error) {
	maximum, allowed := studentFieldLimits[fieldName]
	if !allowed { // 未注册键永远不能影响 students 列。
		return nil, ErrInvalidInput
	}
	if fieldValue == nil { // nil 可选值明确表示不覆盖；name 在上层单独拒绝。
		return nil, nil
	}
	normalized := norm.NFKC.String(strings.TrimSpace(*fieldValue)) // 规范化后再执行与数据库一致的上限。
	if normalized == "" {                                          // 空白可选值保留现有资料而不是清空。
		return nil, nil
	}
	if !utf8.ValidString(normalized) || utf8.RuneCountInString(normalized) > maximum || strings.ContainsRune(normalized, '\x00') { // 非法文本失败关闭。
		return nil, ErrInvalidInput
	}
	return &normalized, nil // 非空合法值将在同一学生 UPDATE 中写入。
}

// --- 绑定能力秘密与规范化提交意图 ---
func submitDigest(capability Capability, prepared preparedSubmit) ([32]byte, error) {
	secretDigest := sha256.Sum256([]byte(capability.Secret)) // 幂等记录不保存或编码原始能力秘密。
	studentFields := map[string]any{                         // 显式键让私有 prepared 结构也能完整进入规范摘要。
		"name": prepared.studentFields.name, "phone": prepared.studentFields.phone, "wechat": prepared.studentFields.wechat,
		"school": prepared.studentFields.school, "major": prepared.studentFields.major, "grade": prepared.studentFields.grade,
		"current_location": prepared.studentFields.currentLocation,
		"target_city":      prepared.studentFields.targetCity, "target_position": prepared.studentFields.targetPosition,
		"expected_salary": prepared.studentFields.expectedSalary, "job_intention": prepared.studentFields.jobIntention,
		"project_experience": prepared.studentFields.projectExperience, "internship_experience": prepared.studentFields.internshipExperience,
		"skills": prepared.studentFields.skills, "certificates": prepared.studentFields.certificates,
	}
	body, marshalError := json.Marshal(struct {
		CapabilityID      string            `json:"capability_id"`
		SecretDigest      [32]byte          `json:"secret_digest"`
		AssessmentVersion string            `json:"assessment_version"`
		StudentFields     map[string]any    `json:"student_fields"`
		Answers           map[string]string `json:"answers"`
	}{capability.ID, secretDigest, prepared.assessmentVersion, studentFields, prepared.answers})
	if marshalError != nil { // 规范结构理论上可编码，失败时仍不得开始业务写入。
		return [32]byte{}, marshalError
	}
	return sha256.Sum256(body), nil // 固定摘要用于同 key 重放比较。
}

// --- 根据服务器注册表验证答案并生成权威结果 ---
func scoreAssessment(questions []Question, definitionBody []byte, answers map[string]string) ([]byte, []byte, error) {
	definition := scoringDefinition{}                                                                                          // 私有规则只从当前活动问卷记录加载。
	if decodeError := json.Unmarshal(definitionBody, &definition); decodeError != nil || !validScoringDefinition(definition) { // 损坏规则失败关闭。
		return nil, nil, errScoringDefinition
	}
	if !answersMatchQuestions(questions, answers, definition.OptionWeights) { // 答案必须逐题选择所属选项。
		return nil, nil, errAnswerOutsideQuestionnaire
	}

	coreScores := zeroScores(definition.CoreOrder)     // 先建立完整核心键，零分同样参与稳定次序。
	signalScores := zeroScores(definition.SignalOrder) // 支持信号与核心结果分开累计。
	for _, optionID := range answers {                 // map 顺序不会影响整数加法结果。
		for scoreKey, weight := range definition.OptionWeights[optionID] {
			if _, isCore := coreScores[scoreKey]; isCore { // 核心权重只进入核心集合。
				coreScores[scoreKey] += weight
				continue
			}
			if _, isSignal := signalScores[scoreKey]; isSignal { // 其余允许键只能是支持信号。
				signalScores[scoreKey] += weight
				continue
			}
			return nil, nil, errScoringDefinition // 未知权重键说明服务器注册表不可信。
		}
	}

	ranking := append([]string(nil), definition.CoreOrder...)                                                                   // 稳定排序副本，不改变数据库规则顺序。
	sort.SliceStable(ranking, func(left int, right int) bool { return coreScores[ranking[left]] > coreScores[ranking[right]] }) // 同分保留 core_order。
	primaryType, secondaryType := ranking[0], ranking[1]                                                                        // 默认取最高与次高核心键。
	for _, rule := range definition.HybridRules {                                                                               // 第一条满足的固定规则覆盖纯核心主键。
		leftScore, rightScore := coreScores[rule.Left], coreScores[rule.Right]
		if leftScore >= rule.MinimumScore && rightScore >= rule.MinimumScore && absoluteDifference(leftScore, rightScore) <= rule.MaximumGap {
			primaryType, secondaryType = rule.PrimaryType, rule.SecondaryType
			break
		}
	}

	supportSignals := make([]string, 0, len(definition.SignalOrder)) // 只按注册顺序选取越过阈值的内部信号。
	supportMaterial := make(map[string]string, len(definition.SignalOrder))
	for _, signalKey := range definition.SignalOrder {
		if signalScores[signalKey] < definition.SignalThreshold { // 低于阈值的偶发信号不进入建议。
			continue
		}
		supportSignals = append(supportSignals, signalKey)
		supportMaterial[signalKey] = definition.SupportMaterial[signalKey]
	}
	if len(supportSignals) == 0 { // nil 编码为 null，与“没有额外信号”语义一致。
		supportSignals = nil
		supportMaterial = nil
	}
	material, found := definition.ResultMaterial[primaryType]
	if !found || material.Summary == "" || len(material.Advice) == 0 { // 每个可能结果都必须有人工材料。
		return nil, nil, errScoringDefinition
	}

	scoreBody, scoreError := json.Marshal(serverScore{PrimaryType: primaryType, SecondaryType: secondaryType, CoreScores: coreScores, SignalScores: signalScores}) // 保存可复核分值。
	recommendationBody, recommendationError := json.Marshal(internalRecommendation{
		ReportStatus: "pending_human_confirmation", Summary: material.Summary, Advice: material.Advice,
		SupportSignals: supportSignals, SupportMaterial: supportMaterial, Disclaimer: definition.Disclaimer,
	})
	if scoreError != nil || recommendationError != nil { // JSON 编码失败不能产生部分测评事实。
		return nil, nil, errScoringDefinition
	}
	return scoreBody, recommendationBody, nil
}

// --- 验证私有规则的最小完整性 ---
func validScoringDefinition(definition scoringDefinition) bool {
	if len(definition.CoreOrder) < 2 || len(definition.SignalOrder) == 0 || definition.SignalThreshold < 1 || len(definition.OptionWeights) == 0 || definition.Disclaimer == "" { // 核心排序与人工门禁不可缺失。
		return false
	}
	seen := make(map[string]bool, len(definition.CoreOrder)+len(definition.SignalOrder))
	for _, scoreKey := range append(append([]string(nil), definition.CoreOrder...), definition.SignalOrder...) {
		if scoreKey == "" || seen[scoreKey] { // 重复键会让权重归属和同分顺序不确定。
			return false
		}
		seen[scoreKey] = true
	}
	for _, rule := range definition.HybridRules {
		if rule.PrimaryType == "" || !seen[rule.Left] || !seen[rule.Right] || !seen[rule.SecondaryType] || rule.MinimumScore < 0 || rule.MaximumGap < 0 { // 组合规则只能引用已注册核心键。
			return false
		}
	}
	for _, signalKey := range definition.SignalOrder {
		if definition.SupportMaterial[signalKey] == "" { // 每个可能信号都必须有人类可读材料。
			return false
		}
	}
	return true
}

// --- 验证每题只选择所属的一个注册选项 ---
func answersMatchQuestions(questions []Question, answers map[string]string, weights map[string]map[string]int) bool {
	if len(questions) != 10 || len(answers) != len(questions) { // 当前合同恰好十题十答。
		return false
	}
	seenQuestions := make(map[string]bool, len(questions))
	for _, question := range questions {
		if seenQuestions[question.ID] { // 重复问题身份会让答案归属不明确。
			return false
		}
		seenQuestions[question.ID] = true
		answer, answered := answers[question.ID]
		if !answered { // 每个公开问题都必须有答案。
			return false
		}
		belongsToQuestion := false
		for _, option := range question.Options {
			if option.ID == answer { // 只接受当前问题自己的选项。
				belongsToQuestion = true
				break
			}
		}
		if _, registered := weights[answer]; !belongsToQuestion || !registered { // 公开选项还必须拥有服务器权重定义。
			return false
		}
	}
	return true
}

// --- 建立包含零分键的稳定分数集合 ---
func zeroScores(order []string) map[string]int {
	scores := make(map[string]int, len(order)) // 零分键保证次结果仍能按注册顺序确定。
	for _, scoreKey := range order {
		scores[scoreKey] = 0
	}
	return scores
}

// --- 计算两个整数分数的非负差 ---
func absoluteDifference(left int, right int) int {
	if left >= right { // 大值减小值避免引入浮点或符号歧义。
		return left - right
	}
	return right - left
}

// --- 检查版本身份只包含固定前缀与数字 ---
func validAssessmentVersion(value string) bool {
	digits := strings.TrimPrefix(value, "assessment-") // 移除固定业务前缀后只能剩数字。
	if digits == value || digits == "" || len(value) > 40 {
		return false
	}
	for _, character := range digits {
		if character < '0' || character > '9' { // 未知格式在数据库查询前失败关闭。
			return false
		}
	}
	return true
}
