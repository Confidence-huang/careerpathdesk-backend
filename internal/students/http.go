/*
学生 HTTP 入口：把已认证浏览器触发转换为一个学生 Commands 动作和固定 JSON 反馈。
本文件只负责身份门禁、严格输入、局部 PATCH 合并与错误映射；范围、版本、事务和审计留在命令层。
调用示例：studentHTTP.Register(router.Group("/api/v2"))。
*/
package students

import (
	"errors"   // 将认证与学生命令错误映射为稳定问题码。
	"net/http" // 使用冻结 REST 状态码反馈结果。
	"strconv"  // 解析受限学生列表数量。
	"time"     // 接收 RFC 3339 UTC 跟进时间。

	"github.com/gin-gonic/gin" // 注册版本化学生路由。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"           // 接收认证模块的当前逐人账号。
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx" // 复用请求身份、严格 JSON 与幂等门禁。
)

var ErrInvalidHTTPDependencies = errors.New("student HTTP dependencies are invalid") // 命令或认证能力缺失。

type currentAccount func(*gin.Context) (auth.Account, error) // 只接收学生模块需要的认证投影。

// HTTP 将学生传输触发收敛到 Commands 深模块。
type HTTP struct {
	commands *Commands      // commands 隐藏范围、事务、版本和审计实现。
	current  currentAccount // current 验证访问 JWT 与数据库会话终态。
}

type createInput struct {
	Name                   string  `json:"name"`                     // Name 是学生显示姓名。
	Phone                  *string `json:"phone"`                    // Phone 可空且不进入普通日志。
	Email                  *string `json:"email"`                    // Email 可空且不进入普通日志。
	OwnerStaffID           *string `json:"owner_staff_id"`           // OwnerStaffID 对员工最终固定为本人。
	ProcessingBasis        string  `json:"processing_basis"`         // ProcessingBasis 只接收固定处理依据枚举。
	PrivacyNoticeVersion   string  `json:"privacy_notice_version"`   // PrivacyNoticeVersion 必须匹配当前公开说明。
	PrivacyNoticeDelivered bool    `json:"privacy_notice_delivered"` // PrivacyNoticeDelivered 必须由操作人员明确确认。
}

type updateInput struct {
	Name                 httpx.OptionalField[string]     `json:"name"`  // Name 缺失时保留当前值。
	Phone                httpx.OptionalField[*string]    `json:"phone"` // Phone 的 null 表示明确清空。
	Email                httpx.OptionalField[*string]    `json:"email"` // Email 的 null 表示明确清空。
	Wechat               httpx.OptionalField[*string]    `json:"wechat"`
	School               httpx.OptionalField[*string]    `json:"school"`
	Major                httpx.OptionalField[*string]    `json:"major"`
	Grade                httpx.OptionalField[*string]    `json:"grade"`
	CurrentLocation      httpx.OptionalField[*string]    `json:"current_location"`
	TargetCity           httpx.OptionalField[*string]    `json:"target_city"`
	TargetPosition       httpx.OptionalField[*string]    `json:"target_position"`
	ExpectedSalary       httpx.OptionalField[*string]    `json:"expected_salary"`
	JobIntention         httpx.OptionalField[*string]    `json:"job_intention"`
	ProjectExperience    httpx.OptionalField[*string]    `json:"project_experience"`
	InternshipExperience httpx.OptionalField[*string]    `json:"internship_experience"`
	Skills               httpx.OptionalField[*string]    `json:"skills"`
	Certificates         httpx.OptionalField[*string]    `json:"certificates"`
	NextAction           httpx.OptionalField[*string]    `json:"next_action"`       // NextAction 的 null 表示明确清空。
	NextFollowUpAt       httpx.OptionalField[*time.Time] `json:"next_follow_up_at"` // 时间由标准库按 RFC 3339 解码。
	Version              int64                           `json:"version"`           // Version 必须匹配当前学生事实。
}

type assignmentInput struct {
	OwnerStaffID httpx.OptionalField[*string] `json:"owner_staff_id"` // null 表示取消当前负责人。
	Version      httpx.OptionalField[int64]   `json:"version"`        // Version 必须明确存在并大于零。
}

type collaboratorInput struct {
	Version int64 `json:"version"`
}

type responseMeta struct {
	RequestID  string  `json:"request_id"`            // RequestID 关联本次最小问题或成功反馈。
	NextCursor *string `json:"next_cursor,omitempty"` // NextCursor 只在列表仍有下一批时出现。
}

type studentEnvelope struct {
	Data Student      `json:"data"` // Data 只在命令授权后包含学生投影。
	Meta responseMeta `json:"meta"` // Meta 不含游标时只反馈请求身份。
}

type studentListEnvelope struct {
	Data []Student    `json:"data"` // Data 已由命令按当前账号范围过滤。
	Meta responseMeta `json:"meta"` // Meta 关联本次列表请求。
}

// --- 装配学生 HTTP 入口 ---
func NewHTTP(commands *Commands, current currentAccount) (*HTTP, error) {
	if commands == nil || current == nil { // 缺少任一深模块时不建立半可用路由。
		return nil, ErrInvalidHTTPDependencies
	}
	return &HTTP{commands: commands, current: current}, nil
}

// --- 注册冻结学生与负责人路由 ---
func (studentHTTP *HTTP) Register(versionedAPI *gin.RouterGroup) {
	versionedAPI.GET("/students", studentHTTP.list)                                   // 老板全量、员工本人范围列表。
	versionedAPI.POST("/students", httpx.RequireIdempotencyKey(), studentHTTP.create) // 创建要求调用方稳定幂等键。
	versionedAPI.GET("/students/:studentId", studentHTTP.get)                         // 未知和范围外目标共享 404。
	versionedAPI.PATCH("/students/:studentId", studentHTTP.update)                    // 局部 PATCH 合并后调用版本化命令。
	versionedAPI.PUT("/students/:studentId/assignment", studentHTTP.assign)           // 分配入口只允许老板。
	versionedAPI.PUT("/students/:studentId/collaborators/:staffId", studentHTTP.addCollaborator)
	versionedAPI.DELETE("/students/:studentId/collaborators/:staffId", studentHTTP.removeCollaborator)
}

func (studentHTTP *HTTP) addCollaborator(context *gin.Context) {
	studentHTTP.setCollaborator(context, true)
}
func (studentHTTP *HTTP) removeCollaborator(context *gin.Context) {
	studentHTTP.setCollaborator(context, false)
}

func (studentHTTP *HTTP) setCollaborator(context *gin.Context, active bool) {
	actor, authorized := studentHTTP.authorize(context)
	if !authorized {
		return
	}
	if actor.Role != "owner" {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
		return
	}
	studentID, staffID := context.Param("studentId"), context.Param("staffId")
	if !validStudentID(studentID) || !validStaffID(staffID) {
		writeStudentProblem(context, ErrNotFound)
		return
	}
	input := collaboratorInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 1024); decodeError != nil || input.Version < 1 {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Student collaboration input is invalid.")
		return
	}
	updated, commandError := studentHTTP.commands.SetCollaborator(context.Request.Context(), actor, httpx.RequestID(context), studentID, CollaboratorInput{StaffProfileID: staffID, Version: input.Version}, active)
	if commandError != nil {
		writeStudentProblem(context, commandError)
		return
	}
	context.JSON(http.StatusOK, studentEnvelope{Data: updated, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 列出当前账号可见学生 ---
func (studentHTTP *HTTP) list(context *gin.Context) {
	actor, authorized := studentHTTP.authorize(context)
	if !authorized {
		return
	}
	limit, validLimit := readListLimit(context)
	if !validLimit {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Student list input is invalid.")
		return
	}
	page, listError := studentHTTP.commands.List(context.Request.Context(), actor, limit, context.Query("cursor"))
	if listError != nil {
		writeStudentProblem(context, listError)
		return
	}
	context.JSON(http.StatusOK, studentListEnvelope{
		Data: page.Students,
		Meta: responseMeta{RequestID: httpx.RequestID(context), NextCursor: page.NextCursor},
	})
}

// --- 创建一个当前账号可管理的学生 ---
func (studentHTTP *HTTP) create(context *gin.Context) {
	actor, authorized := studentHTTP.authorize(context) // 认证门禁先于业务正文。
	if !authorized {
		return
	}
	input := createInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Student input is invalid.")
		return
	}
	created, createError := studentHTTP.commands.Create(context.Request.Context(), actor, httpx.RequestID(context), httpx.IdempotencyKey(context), CreateInput{
		Name: input.Name, Phone: input.Phone, Email: input.Email, OwnerStaffID: input.OwnerStaffID,
		ProcessingBasis: input.ProcessingBasis, PrivacyNoticeVersion: input.PrivacyNoticeVersion,
		PrivacyNoticeDelivered: input.PrivacyNoticeDelivered,
	})
	if createError != nil {
		writeStudentProblem(context, createError)
		return
	}
	context.JSON(http.StatusCreated, studentEnvelope{Data: created, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 读取一个当前账号可见学生 ---
func (studentHTTP *HTTP) get(context *gin.Context) {
	actor, authorized := studentHTTP.authorize(context)
	if !authorized {
		return
	}
	studentID := context.Param("studentId")
	if !validStudentID(studentID) { // 非法和未知身份都不进入数据库目标查询。
		writeStudentProblem(context, ErrNotFound)
		return
	}
	student, getError := studentHTTP.commands.Get(context.Request.Context(), actor, studentID)
	if getError != nil {
		writeStudentProblem(context, getError)
		return
	}
	context.JSON(http.StatusOK, studentEnvelope{Data: student, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 合并局部字段并版本化更新学生 ---
func (studentHTTP *HTTP) update(context *gin.Context) {
	actor, authorized := studentHTTP.authorize(context)
	if !authorized {
		return
	}
	studentID := context.Param("studentId")
	if !validStudentID(studentID) { // 目标形状先收敛为不存在，不暴露正文差异。
		writeStudentProblem(context, ErrNotFound)
		return
	}
	input := updateInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil || input.Version < 1 {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Student input is invalid.")
		return
	}
	currentStudent, getError := studentHTTP.commands.Get(context.Request.Context(), actor, studentID)
	if getError != nil { // 范围外与未知目标在解析合法正文后共享命令反馈。
		writeStudentProblem(context, getError)
		return
	}
	updated, updateError := studentHTTP.commands.Update(context.Request.Context(), actor, httpx.RequestID(context), studentID, mergeStudentUpdate(currentStudent, input))
	if updateError != nil {
		writeStudentProblem(context, updateError)
		return
	}
	context.JSON(http.StatusOK, studentEnvelope{Data: updated, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 由老板分配或取消学生负责人 ---
func (studentHTTP *HTTP) assign(context *gin.Context) {
	actor, authorized := studentHTTP.authorize(context)
	if !authorized {
		return
	}
	if actor.Role != "owner" { // 角色拒绝先于目标 ID 和正文解析。
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Owner access is required.")
		return
	}
	studentID := context.Param("studentId")
	if !validStudentID(studentID) {
		writeStudentProblem(context, ErrNotFound)
		return
	}
	input := assignmentInput{}
	if decodeError := httpx.DecodeSingleJSON(context, &input, 4096); decodeError != nil || !input.OwnerStaffID.Set || !input.Version.Set || input.Version.Value < 1 {
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Student assignment input is invalid.")
		return
	}
	assigned, assignError := studentHTTP.commands.Assign(context.Request.Context(), actor, httpx.RequestID(context), studentID, AssignInput{
		OwnerStaffID: input.OwnerStaffID.Value, Version: input.Version.Value,
	})
	if assignError != nil {
		writeStudentProblem(context, assignError)
		return
	}
	context.JSON(http.StatusOK, studentEnvelope{Data: assigned, Meta: responseMeta{RequestID: httpx.RequestID(context)}})
}

// --- 恢复当前后台账号并限制首次改密状态 ---
func (studentHTTP *HTTP) authorize(context *gin.Context) (auth.Account, bool) {
	actor, authenticationError := studentHTTP.current(context)
	if authenticationError != nil {
		if errors.Is(authenticationError, auth.ErrAuthenticationRequired) || errors.Is(authenticationError, auth.ErrAccountDisabled) {
			httpx.AbortProblem(context, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication is required.")
		} else {
			httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Student access is temporarily unavailable.")
		}
		return auth.Account{}, false
	}
	if actor.MustChangePassword {
		httpx.AbortProblem(context, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "Password change is required.")
		return auth.Account{}, false
	}
	if actor.State != "active" || (actor.Role != "owner" && actor.Role != "staff") {
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Student access is forbidden.")
		return auth.Account{}, false
	}
	return actor, true
}

// --- 将 PATCH 明确字段覆盖到当前完整学生快照 ---
func mergeStudentUpdate(current Student, input updateInput) UpdateInput {
	merged := UpdateInput{
		Name: current.Name, Phone: current.Phone, Email: current.Email,
		Wechat: current.Wechat, School: current.School, Major: current.Major, Grade: current.Grade,
		CurrentLocation: current.CurrentLocation, TargetCity: current.TargetCity,
		TargetPosition: current.TargetPosition, ExpectedSalary: current.ExpectedSalary,
		JobIntention: current.JobIntention, ProjectExperience: current.ProjectExperience,
		InternshipExperience: current.InternshipExperience, Skills: current.Skills,
		Certificates: current.Certificates,
		NextAction:   current.NextAction, NextFollowUpAt: current.NextFollowUpAt, Version: input.Version,
	}
	if input.Name.Set {
		merged.Name = input.Name.Value
	}
	if input.Phone.Set {
		merged.Phone = input.Phone.Value
	}
	if input.Email.Set {
		merged.Email = input.Email.Value
	}
	if input.Wechat.Set {
		merged.Wechat = input.Wechat.Value
	}
	if input.School.Set {
		merged.School = input.School.Value
	}
	if input.Major.Set {
		merged.Major = input.Major.Value
	}
	if input.Grade.Set {
		merged.Grade = input.Grade.Value
	}
	if input.CurrentLocation.Set {
		merged.CurrentLocation = input.CurrentLocation.Value
	}
	if input.TargetCity.Set {
		merged.TargetCity = input.TargetCity.Value
	}
	if input.TargetPosition.Set {
		merged.TargetPosition = input.TargetPosition.Value
	}
	if input.ExpectedSalary.Set {
		merged.ExpectedSalary = input.ExpectedSalary.Value
	}
	if input.JobIntention.Set {
		merged.JobIntention = input.JobIntention.Value
	}
	if input.ProjectExperience.Set {
		merged.ProjectExperience = input.ProjectExperience.Value
	}
	if input.InternshipExperience.Set {
		merged.InternshipExperience = input.InternshipExperience.Value
	}
	if input.Skills.Set {
		merged.Skills = input.Skills.Value
	}
	if input.Certificates.Set {
		merged.Certificates = input.Certificates.Value
	}
	if input.NextAction.Set {
		merged.NextAction = input.NextAction.Value
	}
	if input.NextFollowUpAt.Set {
		merged.NextFollowUpAt = input.NextFollowUpAt.Value
	}
	return merged
}

// --- 读取默认 30 且最多 100 的列表数量 ---
func readListLimit(context *gin.Context) (int, bool) {
	rawLimit := context.Query("limit")
	if rawLimit == "" {
		return 30, true // OpenAPI 默认值在服务端明确实现。
	}
	limit, parseError := strconv.Atoi(rawLimit)
	return limit, parseError == nil && limit >= 1 && limit <= 100
}

// --- 映射学生命令的稳定失败分类 ---
func writeStudentProblem(context *gin.Context, commandError error) {
	switch {
	case errors.Is(commandError, ErrForbidden):
		httpx.AbortProblem(context, http.StatusForbidden, "FORBIDDEN", "Student access is forbidden.")
	case errors.Is(commandError, ErrInvalidInput):
		httpx.AbortProblem(context, http.StatusBadRequest, "INVALID_INPUT", "Student input is invalid.")
	case errors.Is(commandError, ErrNotFound):
		httpx.AbortProblem(context, http.StatusNotFound, "NOT_FOUND", "Student was not found.")
	case errors.Is(commandError, ErrVersionConflict):
		httpx.AbortProblem(context, http.StatusConflict, "VERSION_CONFLICT", "Student state changed; reload and retry.")
	case errors.Is(commandError, ErrIdempotencyConflict):
		httpx.AbortProblem(context, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency key conflicts with another request.")
	default:
		httpx.AbortProblem(context, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "Student access is temporarily unavailable.")
	}
}
