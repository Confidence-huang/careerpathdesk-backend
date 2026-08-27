/*
安全沟通风格投影：把权威测评中的一个结果键和中性摘要收窄为学生与有权后台共享的四字段结构。
该模块不接受浏览器提供的类型；答案、分值、次类型、支持信号和内部建议从不进入返回值。
调用示例：ProjectPublicResult(primaryType, summary)。
*/
package assessments

import (
	"encoding/json" // 从当前权威 JSON 中只解码主键和摘要。
	"strings"       // 拒绝空白、NUL 和过长摘要。
	"unicode/utf8"  // 以 Unicode 字符数执行窄投影上限。
)

const publicResultDisclaimer = "这是沟通风格倾向，不代表固定人格、心理诊断、能力高低或职业适配结论。" // 固定边界文案防止将沟通倾向当作人格诊断。

type publicResultName struct {
	code  string // code 是稳定 API 键，不暴露内部评分键。
	label string // label 是中性且可读的界面名称。
}

var publicResultNames = map[string]publicResultName{ // 只有已冻结的四核心和两混合类型可离开测评模块。
	"direct_goal":         {code: "tiger", label: "老虎型 · 目标推进"},
	"expressive_feedback": {code: "peacock", label: "孔雀型 · 互动反馈"},
	"evidence_planning":   {code: "owl", label: "猫头鹰型 · 依据规划"},
	"steady_support":      {code: "koala", label: "考拉型 · 稳步支持"},
	"direct_expressive":   {code: "tiger_peacock", label: "老虎×孔雀型 · 目标与互动"},
	"evidence_steady":     {code: "owl_koala", label: "猫头鹰×考拉型 · 规划与稳定"},
}

// PublicResult 是测评完成回执和受限学生投影共用的全部公开结果。
type PublicResult struct {
	Code       string `json:"code"`       // Code 只能是六个冻结公开键之一。
	Label      string `json:"label"`      // Label 是与 Code 固定绑定的中性名称。
	Summary    string `json:"summary"`    // Summary 来自服务器注册材料，不含分值或建议。
	Disclaimer string `json:"disclaimer"` // Disclaimer 明确这不是诊断或职业决策。
}

// ProjectPublicResult 是后台学生查询复用的唯一投影缝；false 要求调用方失败关闭。
func ProjectPublicResult(primaryType string, summary string) (PublicResult, bool) {
	name, known := publicResultNames[primaryType]
	if !known || !validPublicSummary(summary) { // 未知主键或已损坏摘要不能降级为猜测结果。
		return PublicResult{}, false
	}
	return PublicResult{Code: name.code, Label: name.label, Summary: summary, Disclaimer: publicResultDisclaimer}, true
}

// publicResultFromBodies 在写入之前从同一次权威评分中生成回执，避免提交后再猜测。
func publicResultFromBodies(scoreBody []byte, recommendationBody []byte) (PublicResult, bool) {
	var score struct {
		PrimaryType string `json:"primary_type"`
	}
	var recommendation struct {
		Summary string `json:"summary"`
	}
	if json.Unmarshal(scoreBody, &score) != nil || json.Unmarshal(recommendationBody, &recommendation) != nil {
		return PublicResult{}, false
	}
	return ProjectPublicResult(score.PrimaryType, recommendation.Summary)
}

// validPublicResult 在幂等重放时证明库中响应仍是当前窄合同。
func validPublicResult(result PublicResult) bool {
	for primaryType := range publicResultNames {
		expected, valid := ProjectPublicResult(primaryType, result.Summary)
		if valid && expected == result {
			return true
		}
	}
	return false
}

func validPublicSummary(summary string) bool {
	trimmed := strings.TrimSpace(summary)
	return trimmed == summary && trimmed != "" && utf8.ValidString(summary) && utf8.RuneCountInString(summary) <= 500 && !strings.ContainsRune(summary, '\x00')
}
