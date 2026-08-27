/*
学生业务指令：老板跨范围、员工按当前责任范围读取和修改学生，并隐藏所有 PostgreSQL 细节。
每个公开动作先重验逐人账号，再由同一事务完成范围、版本、目标员工校验、审计和最终反馈。
调用示例：student, err := commands.Get(ctx, actor, studentID)。
*/
package students

import (
	"bytes"           // 严格解码不透明学生列表游标。
	"context"         // 将请求取消和期限传入学生事务。
	"crypto/sha256"   // 将学生创建意图压缩为固定幂等摘要。
	"encoding/base64" // 将分页边界编码为 URL 安全文本。
	"encoding/json"   // 用稳定字段顺序形成创建意图摘要。
	"errors"          // 暴露不含对象正文或 SQL 的稳定失败分类。
	"io"              // 证明游标 JSON 只有一个对象。
	"net/mail"        // 验证可选邮箱是单一地址而不是自由文本。
	"strings"         // 清理学生姓名和可选正文的外部空白。
	"time"            // 保存学生时间投影并注入可信 UTC 时间。
	"unicode/utf8"    // 按用户可见字符验证字段上限。

	"github.com/jackc/pgx/v5"        // 让连接池和测试连接共享事务入口。
	"golang.org/x/text/unicode/norm" // 统一兼容字符但不改变合法业务正文。

	"github.com/confidence-huang/careerpathdesk-backend/internal/assessments" // 复用测评模块唯一安全公开结果形状。
	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 接收认证模块已验证的当前账号投影。
)

var ErrInvalidDependencies = errors.New("student dependencies are invalid") // 数据库、时钟或身份生成能力缺失。
var ErrForbidden = errors.New("student access is forbidden")                // 当前账号不是可用老板或员工。
var ErrInvalidInput = errors.New("student input is invalid")                // 输入形状不满足冻结合同。
var ErrNotFound = errors.New("student was not found")                       // 未知和范围外学生共享此反馈。
var ErrVersionConflict = errors.New("student version conflicts")            // 客户端版本落后于当前事实。
var ErrIdempotencyConflict = errors.New("student idempotency conflicts")    // 同键绑定了不同创建意图。
var ErrWriteFailed = errors.New("student write failed")                     // 事务未形成完整事实。

// Student 是获准账号可查看的学生主档投影；联系方式只在通过对象范围后出现。
type Student struct {
	ID                       string                    `json:"id"`                          // ID 是不透明学生身份。
	Name                     string                    `json:"name"`                        // Name 是页面显示姓名。
	Phone                    *string                   `json:"phone"`                       // Phone 只反馈给获准后台账号。
	Email                    *string                   `json:"email"`                       // Email 只反馈给获准后台账号。
	Wechat                   *string                   `json:"wechat"`                      // Wechat 是可选联系资料。
	School                   *string                   `json:"school"`                      // School 是可渐进补充的学校资料。
	Major                    *string                   `json:"major"`                       // Major 是可选专业资料。
	Grade                    *string                   `json:"grade"`                       // Grade 是可选学习阶段。
	CurrentLocation          *string                   `json:"current_location"`            // CurrentLocation 是现居地，不等同目标城市。
	TargetCity               *string                   `json:"target_city"`                 // TargetCity 是求职目标城市。
	TargetPosition           *string                   `json:"target_position"`             // TargetPosition 是目标岗位。
	ExpectedSalary           *string                   `json:"expected_salary"`             // ExpectedSalary 是可选薪资意向。
	JobIntention             *string                   `json:"job_intention"`               // JobIntention 是求职方向正文。
	ProjectExperience        *string                   `json:"project_experience"`          // ProjectExperience 是项目经历正文。
	InternshipExperience     *string                   `json:"internship_experience"`       // InternshipExperience 是实习经历正文。
	Skills                   *string                   `json:"skills"`                      // Skills 是能力资料正文。
	Certificates             *string                   `json:"certificates"`                // Certificates 是证书资料正文。
	OwnerStaffID             *string                   `json:"owner_staff_id"`              // OwnerStaffID 决定员工对象范围。
	NextAction               *string                   `json:"next_action"`                 // NextAction 是下一步正文，不进入审计。
	NextFollowUpAt           *time.Time                `json:"next_follow_up_at"`           // NextFollowUpAt 是 UTC 跟进事实。
	ProcessingBasis          string                    `json:"processing_basis"`            // ProcessingBasis 是建档时确认的固定处理依据。
	PrivacyNoticeVersion     string                    `json:"privacy_notice_version"`      // PrivacyNoticeVersion 是已交付的公开说明版本。
	PrivacyNoticeDeliveredAt time.Time                 `json:"privacy_notice_delivered_at"` // PrivacyNoticeDeliveredAt 只由服务端时钟生成。
	Version                  int64                     `json:"version"`                     // Version 阻止静默并发覆盖。
	CreatedAt                time.Time                 `json:"created_at"`                  // CreatedAt 由数据库生成。
	UpdatedAt                time.Time                 `json:"updated_at"`                  // UpdatedAt 由数据库生成。
	CommunicationStyle       *assessments.PublicResult `json:"communication_style"`         // CommunicationStyle 为 nil 表示尚无权威测评。
	Assignments              []Assignment              `json:"assignments"`                 // Assignments 只包含当前 active 主负责人和协作者。
}

// Assignment 是页面识别当前协作成员所需的最小公开投影。
type Assignment struct {
	ID             string    `json:"id"`
	StaffProfileID string    `json:"staff_profile_id"`
	DisplayName    string    `json:"display_name"`
	Role           string    `json:"role"`
	StartedAt      time.Time `json:"started_at"`
}

// Page 是一批已授权学生和下一页不透明位置。
type Page struct {
	Students   []Student // Students 已按更新时间和身份稳定倒序排列。
	NextCursor *string   // NextCursor 为 nil 表示当前范围已经读完。
}

// CreateInput 是获准账号创建学生的一次完整意图。
type CreateInput struct {
	Name                   string  // Name 是学生显示姓名。
	Phone                  *string // Phone 可选且不进入审计。
	Email                  *string // Email 可选且不进入审计。
	OwnerStaffID           *string // OwnerStaffID 对员工只能为空或本人档案。
	ProcessingBasis        string  // ProcessingBasis 只接受当前批准的固定依据枚举。
	PrivacyNoticeVersion   string  // PrivacyNoticeVersion 必须是当前公开说明版本。
	PrivacyNoticeDelivered bool    // PrivacyNoticeDelivered 表示员工已完成告知，不接收客户端时间。
}

// UpdateInput 是一次完整的学生可编辑主档快照；Version 绑定页面读取的旧事实。
type UpdateInput struct {
	Name                 string  // Name 是更新后的合法显示姓名。
	Phone                *string // Phone 可明确清空为 nil。
	Email                *string // Email 可明确清空为 nil。
	Wechat               *string
	School               *string
	Major                *string
	Grade                *string
	CurrentLocation      *string
	TargetCity           *string
	TargetPosition       *string
	ExpectedSalary       *string
	JobIntention         *string
	ProjectExperience    *string
	InternshipExperience *string
	Skills               *string
	Certificates         *string
	NextAction           *string    // 兼容由最新跟进派生的下一步，不再在资料表单中直接维护。
	NextFollowUpAt       *time.Time // 兼容由最新跟进派生的 UTC 时间。
	Version              int64      // Version 防止覆盖另一页面先提交的修改。
}

// AssignInput 是老板修改学生责任范围的一次版本化意图。
type AssignInput struct {
	OwnerStaffID *string // OwnerStaffID 为 nil 表示暂不分配负责人。
	Version      int64   // Version 绑定老板页面读取的学生旧事实。
}

// CollaboratorInput 是老板添加或结束一名协作老师的版本化意图。
type CollaboratorInput struct {
	StaffProfileID string
	Version        int64
}

// Commands 是学生领域的窄公开接口，调用方不需要理解范围 SQL 或锁顺序。
type Commands struct {
	data        *store                       // data 执行模块私有 PostgreSQL 操作。
	now         func() time.Time             // now 为后续状态和事件提供唯一 UTC 来源。
	newIdentity func(string) (string, error) // newIdentity 生成学生和审计身份。
}

type preparedCreate struct {
	studentID                string            // studentID 是提交前准备的不透明身份。
	auditID                  string            // auditID 与学生身份分离。
	name                     string            // name 已完成 NFKC 和空白清理。
	phone                    *string           // phone 已验证但不会进入审计。
	email                    *string           // email 已验证但不会进入审计。
	serviceStage             string            // serviceStage 是旧非空列的固定兼容值。
	jobSearchStage           string            // jobSearchStage 是旧非空列的固定兼容值。
	requestedOwner           *string           // requestedOwner 是老板选择或员工本人范围。
	processingBasis          string            // processingBasis 已收敛为固定枚举。
	privacyNoticeVersion     string            // privacyNoticeVersion 已验证为当前说明版本。
	privacyNoticeDeliveredAt time.Time         // privacyNoticeDeliveredAt 来自受信任服务端时钟。
	requestDigest            [sha256.Size]byte // requestDigest 绑定完整创建意图。
}

type studentCursor struct {
	UpdatedAt time.Time `json:"updated_at"` // UpdatedAt 是上一页最后一行的排序时间。
	ID        string    `json:"id"`         // ID 在相同时间下提供稳定次序。
}

type transactionSource interface {
	Begin(context.Context) (pgx.Tx, error) // pgx.Conn 与 pgxpool.Pool 均满足此入口。
}

// --- 装配学生业务指令 ---
func NewCommands(database transactionSource, now func() time.Time, newIdentity func(string) (string, error)) (*Commands, error) {
	if database == nil || now == nil || newIdentity == nil { // 缺少任一能力时不构造半可用模块。
		return nil, ErrInvalidDependencies
	}
	return &Commands{data: &store{database: database}, now: now, newIdentity: newIdentity}, nil
}

// --- 创建一个学生并固定责任范围 ---
func (commands *Commands) Create(ctx context.Context, actor auth.Account, requestID string, idempotencyKey string, input CreateInput) (Student, error) {
	if !actorEligible(actor) { // 身份门禁先于学生正文处理。
		return Student{}, ErrForbidden
	}
	if actor.Role == "staff" && input.OwnerStaffID != nil && (actor.StaffProfileID == nil || *input.OwnerStaffID != *actor.StaffProfileID) { // 员工不能借创建选择他人范围。
		return Student{}, ErrForbidden
	}
	prepared, prepareError := commands.prepareCreate(requestID, idempotencyKey, input)
	if prepareError != nil {
		return Student{}, prepareError
	}

	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Student{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return Student{}, actorError
	}
	effectiveOwner := prepared.requestedOwner
	if currentActor.role == "staff" {
		effectiveOwner = currentActor.staffProfileID // 数据库最新员工关联覆盖外部投影。
	}
	if replay, found, replayError := commands.data.findCreateReplay(ctx, transaction, currentActor.id, idempotencyKey, prepared.requestDigest); replayError != nil || found {
		return replay, replayError
	}
	if effectiveOwner != nil {
		if staffError := commands.data.requireActiveStaff(ctx, transaction, *effectiveOwner); staffError != nil {
			return Student{}, staffError
		}
	}
	created, insertError := commands.data.insertStudent(ctx, transaction, currentActor.id, effectiveOwner, prepared)
	if insertError != nil {
		return Student{}, insertError
	}
	if effectiveOwner != nil {
		assignmentID, identityError := commands.newIdentity("SA")
		if identityError != nil || assignmentID == "" {
			return Student{}, ErrWriteFailed
		}
		if assignmentError := commands.data.insertAssignment(ctx, transaction, assignmentID, created.ID, *effectiveOwner, "primary", currentActor.id); assignmentError != nil {
			return Student{}, assignmentError
		}
	}
	if auditError := commands.data.insertCreateAudit(ctx, transaction, prepared.auditID, currentActor.id, created.ID, requestID, prepared.processingBasis, prepared.privacyNoticeVersion); auditError != nil {
		return Student{}, auditError
	}
	if idempotencyError := commands.data.insertCreateIdempotency(ctx, transaction, currentActor.id, idempotencyKey, prepared.requestDigest, created.ID); idempotencyError != nil {
		return Student{}, idempotencyError
	}
	created, insertError = commands.data.getStudent(ctx, transaction, currentActor, created.ID, false)
	if insertError != nil {
		return Student{}, insertError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Student{}, ErrWriteFailed
	}
	return created, nil
}

// --- 在事务前准备学生创建意图 ---
func (commands *Commands) prepareCreate(requestID string, idempotencyKey string, input CreateInput) (preparedCreate, error) {
	name := norm.NFKC.String(strings.TrimSpace(input.Name))
	phone := normalizeOptional(input.Phone)
	email := normalizeOptional(input.Email)
	if !validText(requestID, 8, 100) || !validText(idempotencyKey, 16, 128) || !validText(name, 1, 80) || !validOptionalText(phone, 40) || !validEmail(email) {
		return preparedCreate{}, ErrInvalidInput
	}
	if input.OwnerStaffID != nil && !validStaffID(*input.OwnerStaffID) {
		return preparedCreate{}, ErrInvalidInput
	}
	if !validProcessingBasis(input.ProcessingBasis) || input.PrivacyNoticeVersion != "privacy-notice-v1" || !input.PrivacyNoticeDelivered {
		return preparedCreate{}, ErrInvalidInput
	}
	studentID, studentIdentityError := commands.newIdentity("S")
	auditID, auditIdentityError := commands.newIdentity("AU")
	if studentIdentityError != nil || auditIdentityError != nil || studentID == "" || auditID == "" {
		return preparedCreate{}, ErrWriteFailed
	}
	digestBody, marshalError := json.Marshal(struct {
		Name                   string  `json:"name"`
		Phone                  *string `json:"phone"`
		Email                  *string `json:"email"`
		OwnerStaffID           *string `json:"owner_staff_id"`
		ProcessingBasis        string  `json:"processing_basis"`
		PrivacyNoticeVersion   string  `json:"privacy_notice_version"`
		PrivacyNoticeDelivered bool    `json:"privacy_notice_delivered"`
	}{name, phone, email, input.OwnerStaffID, input.ProcessingBasis, input.PrivacyNoticeVersion, input.PrivacyNoticeDelivered})
	if marshalError != nil {
		return preparedCreate{}, ErrWriteFailed
	}
	return preparedCreate{
		studentID: studentID, auditID: auditID, name: name, phone: phone, email: email,
		serviceStage: "待服务", jobSearchStage: "未开始",
		requestedOwner: input.OwnerStaffID, processingBasis: input.ProcessingBasis,
		privacyNoticeVersion: input.PrivacyNoticeVersion, privacyNoticeDeliveredAt: commands.now().UTC(),
		requestDigest: sha256.Sum256(digestBody),
	}, nil
}

// --- 只接受当前业务已定义的两种学生数据处理依据 ---
func validProcessingBasis(basis string) bool {
	return basis == "service_contract" || basis == "student_consent"
}

// --- 按当前账号范围列出一页学生 ---
func (commands *Commands) List(ctx context.Context, actor auth.Account, limit int, rawCursor string) (Page, error) {
	if !actorEligible(actor) || limit < 1 || limit > 100 { // 先拒绝不完整身份和无界列表。
		return Page{}, ErrForbidden
	}
	cursor, cursorError := decodeStudentCursor(rawCursor)
	if cursorError != nil {
		return Page{}, ErrInvalidInput
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Page{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return Page{}, actorError
	}
	students, listError := commands.data.listStudents(ctx, transaction, currentActor, limit+1, cursor)
	if listError != nil {
		return Page{}, listError
	}
	page := Page{Students: students}
	if len(students) > limit { // 额外一行只证明还有下一页，不反馈给当前页面。
		page.Students = students[:limit]
		nextCursor, encodeError := encodeStudentCursor(page.Students[len(page.Students)-1])
		if encodeError != nil {
			return Page{}, ErrWriteFailed
		}
		page.NextCursor = &nextCursor
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Page{}, ErrWriteFailed
	}
	return page, nil
}

// --- 严格恢复一个服务端生成的学生列表游标 ---
func decodeStudentCursor(rawCursor string) (*studentCursor, error) {
	if rawCursor == "" {
		return nil, nil // 首批列表没有上一页边界。
	}
	if len(rawCursor) > 512 {
		return nil, ErrInvalidInput
	}
	encoded, decodeError := base64.RawURLEncoding.DecodeString(rawCursor)
	if decodeError != nil {
		return nil, ErrInvalidInput
	}
	cursor := studentCursor{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if objectError := decoder.Decode(&cursor); objectError != nil {
		return nil, ErrInvalidInput
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) || cursor.UpdatedAt.IsZero() || !validStudentID(cursor.ID) {
		return nil, ErrInvalidInput
	}
	return &cursor, nil
}

// --- 将当前页最后一个学生转换为不透明下一页位置 ---
func encodeStudentCursor(student Student) (string, error) {
	encoded, marshalError := json.Marshal(studentCursor{UpdatedAt: student.UpdatedAt.UTC(), ID: student.ID})
	if marshalError != nil {
		return "", marshalError
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// --- 按当前账号范围读取一个学生 ---
func (commands *Commands) Get(ctx context.Context, actor auth.Account, studentID string) (Student, error) {
	if !actorEligible(actor) { // 身份门禁先于目标 ID 解析。
		return Student{}, ErrForbidden
	}
	if !validStudentID(studentID) {
		return Student{}, ErrNotFound
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Student{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return Student{}, actorError
	}
	student, getError := commands.data.getStudent(ctx, transaction, currentActor, studentID, false)
	if getError != nil {
		return Student{}, getError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Student{}, ErrWriteFailed
	}
	return student, nil
}

// --- 修改本人范围内学生的允许主档字段 ---
func (commands *Commands) Update(ctx context.Context, actor auth.Account, requestID string, studentID string, input UpdateInput) (Student, error) {
	if !actorEligible(actor) { // 身份门禁先于目标和正文处理。
		return Student{}, ErrForbidden
	}
	prepared, prepareError := prepareUpdate(requestID, studentID, input)
	if prepareError != nil {
		return Student{}, prepareError
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || auditID == "" {
		return Student{}, ErrWriteFailed
	}

	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Student{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil {
		return Student{}, actorError
	}
	current, currentError := commands.data.getStudent(ctx, transaction, currentActor, studentID, true)
	if currentError != nil {
		return Student{}, currentError
	}
	if current.Version != input.Version {
		return Student{}, ErrVersionConflict
	}
	updated, updateError := commands.data.updateStudent(ctx, transaction, currentActor.id, studentID, prepared)
	if updateError != nil {
		return Student{}, updateError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, currentActor.id, "student.updated", studentID, requestID, updated.Version); auditError != nil {
		return Student{}, auditError
	}
	updatedProjection, projectionError := commands.data.getStudent(ctx, transaction, currentActor, studentID, false) // 写后从同一事务恢复测评左连接投影。
	if projectionError != nil {
		return Student{}, projectionError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Student{}, ErrWriteFailed
	}
	return updatedProjection, nil
}

// --- 由老板分配或取消学生负责人 ---
func (commands *Commands) Assign(ctx context.Context, actor auth.Account, requestID string, studentID string, input AssignInput) (Student, error) {
	if !actorEligible(actor) || actor.Role != "owner" { // 老板门禁先于目标和员工档案解析。
		return Student{}, ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validStudentID(studentID) || input.Version < 1 || (input.OwnerStaffID != nil && !validStaffID(*input.OwnerStaffID)) {
		return Student{}, ErrInvalidInput
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || auditID == "" {
		return Student{}, ErrWriteFailed
	}

	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Student{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil || currentActor.role != "owner" {
		return Student{}, ErrForbidden
	}
	current, currentError := commands.data.getStudent(ctx, transaction, currentActor, studentID, true)
	if currentError != nil {
		return Student{}, currentError
	}
	if current.Version != input.Version {
		return Student{}, ErrVersionConflict
	}
	if input.OwnerStaffID != nil {
		if staffError := commands.data.requireActiveStaff(ctx, transaction, *input.OwnerStaffID); staffError != nil {
			return Student{}, staffError
		}
	}
	assignmentID := ""
	formerPrimaryAssignmentID := ""
	if input.OwnerStaffID != nil {
		assignmentID, identityError = commands.newIdentity("SA")
		formerPrimaryAssignmentID, identityError = commands.newIdentity("SA")
		if identityError != nil || assignmentID == "" || formerPrimaryAssignmentID == "" {
			return Student{}, ErrWriteFailed
		}
	}
	if assignmentError := commands.data.replacePrimaryAssignment(ctx, transaction, assignmentID, formerPrimaryAssignmentID, studentID, current.OwnerStaffID, input.OwnerStaffID, currentActor.id); assignmentError != nil {
		return Student{}, assignmentError
	}
	assigned, assignError := commands.data.assignStudent(ctx, transaction, currentActor.id, studentID, input)
	if assignError != nil {
		return Student{}, assignError
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, currentActor.id, "student.assigned", studentID, requestID, assigned.Version); auditError != nil {
		return Student{}, auditError
	}
	assignedProjection, projectionError := commands.data.getStudent(ctx, transaction, currentActor, studentID, false) // 责任范围写入后仍返回完整安全结果。
	if projectionError != nil {
		return Student{}, projectionError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Student{}, ErrWriteFailed
	}
	return assignedProjection, nil
}

// SetCollaborator 追加或结束一段协作关系；删除只结束 active 段，不物理覆盖历史。
func (commands *Commands) SetCollaborator(ctx context.Context, actor auth.Account, requestID string, studentID string, input CollaboratorInput, active bool) (Student, error) {
	if !actorEligible(actor) || actor.Role != "owner" {
		return Student{}, ErrForbidden
	}
	if !validText(requestID, 8, 100) || !validStudentID(studentID) || !validStaffID(input.StaffProfileID) || input.Version < 1 {
		return Student{}, ErrInvalidInput
	}
	auditID, identityError := commands.newIdentity("AU")
	if identityError != nil || auditID == "" {
		return Student{}, ErrWriteFailed
	}
	assignmentID := ""
	if active {
		assignmentID, identityError = commands.newIdentity("SA")
		if identityError != nil || assignmentID == "" {
			return Student{}, ErrWriteFailed
		}
	}
	transaction, beginError := commands.data.database.Begin(ctx)
	if beginError != nil {
		return Student{}, ErrWriteFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	currentActor, actorError := commands.data.requireActor(ctx, transaction, actor.ID)
	if actorError != nil || currentActor.role != "owner" {
		return Student{}, ErrForbidden
	}
	current, currentError := commands.data.getStudent(ctx, transaction, currentActor, studentID, true)
	if currentError != nil {
		return Student{}, currentError
	}
	if current.Version != input.Version {
		return Student{}, ErrVersionConflict
	}
	if active {
		if staffError := commands.data.requireActiveStaff(ctx, transaction, input.StaffProfileID); staffError != nil {
			return Student{}, staffError
		}
		if current.OwnerStaffID != nil {
			legacyPrimaryID, legacyIdentityError := commands.newIdentity("SA")
			if legacyIdentityError != nil || legacyPrimaryID == "" {
				return Student{}, ErrWriteFailed
			}
			if legacyError := commands.data.ensureLegacyPrimaryAssignment(ctx, transaction, legacyPrimaryID, studentID, *current.OwnerStaffID, currentActor.id); legacyError != nil {
				return Student{}, legacyError
			}
		}
		if relationError := commands.data.insertAssignment(ctx, transaction, assignmentID, studentID, input.StaffProfileID, "collaborator", currentActor.id); relationError != nil {
			return Student{}, relationError
		}
	} else if relationError := commands.data.endCollaborator(ctx, transaction, studentID, input.StaffProfileID, currentActor.id); relationError != nil {
		return Student{}, relationError
	}
	updated, updateError := commands.data.touchStudent(ctx, transaction, studentID, currentActor.id, input.Version)
	if updateError != nil {
		return Student{}, updateError
	}
	action := "student.collaborator_added"
	if !active {
		action = "student.collaborator_removed"
	}
	if auditError := commands.data.insertAudit(ctx, transaction, auditID, currentActor.id, action, studentID, requestID, updated.Version); auditError != nil {
		return Student{}, auditError
	}
	updated, updateError = commands.data.getStudent(ctx, transaction, currentActor, studentID, false)
	if updateError != nil {
		return Student{}, updateError
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Student{}, ErrWriteFailed
	}
	return updated, nil
}

type preparedUpdate struct {
	name                 string  // name 已完成 NFKC 和外部空白清理。
	phone                *string // phone 已验证字符上限。
	email                *string // email 已验证单一地址形状。
	wechat               *string
	school               *string
	major                *string
	grade                *string
	currentLocation      *string
	targetCity           *string
	targetPosition       *string
	expectedSalary       *string
	jobIntention         *string
	projectExperience    *string
	internshipExperience *string
	skills               *string
	certificates         *string
	nextAction           *string    // nextAction 已把空白正文统一为 nil。
	nextFollowUpAt       *time.Time // nextFollowUpAt 已统一 UTC。
	version              int64      // version 是当前页面旧版本。
}

// --- 在事务前准备可持久化学生修改 ---
func prepareUpdate(requestID string, studentID string, input UpdateInput) (preparedUpdate, error) {
	name := norm.NFKC.String(strings.TrimSpace(input.Name))
	phone := normalizeOptional(input.Phone)
	email := normalizeOptional(input.Email)
	wechat := normalizeOptional(input.Wechat)
	school := normalizeOptional(input.School)
	major := normalizeOptional(input.Major)
	grade := normalizeOptional(input.Grade)
	currentLocation := normalizeOptional(input.CurrentLocation)
	targetCity := normalizeOptional(input.TargetCity)
	targetPosition := normalizeOptional(input.TargetPosition)
	expectedSalary := normalizeOptional(input.ExpectedSalary)
	jobIntention := normalizeOptional(input.JobIntention)
	projectExperience := normalizeOptional(input.ProjectExperience)
	internshipExperience := normalizeOptional(input.InternshipExperience)
	skills := normalizeOptional(input.Skills)
	certificates := normalizeOptional(input.Certificates)
	nextAction := normalizeOptional(input.NextAction)
	if !validText(requestID, 8, 100) || !validStudentID(studentID) || !validText(name, 1, 80) || input.Version < 1 {
		return preparedUpdate{}, ErrInvalidInput
	}
	if !validOptionalText(phone, 40) || !validEmail(email) || !validOptionalText(wechat, 100) ||
		!validOptionalText(school, 200) || !validOptionalText(major, 200) || !validOptionalText(grade, 100) ||
		!validOptionalText(currentLocation, 200) || !validOptionalText(targetCity, 200) ||
		!validOptionalText(targetPosition, 200) || !validOptionalText(expectedSalary, 200) ||
		!validOptionalText(jobIntention, 4000) || !validOptionalText(projectExperience, 4000) ||
		!validOptionalText(internshipExperience, 4000) || !validOptionalText(skills, 4000) ||
		!validOptionalText(certificates, 4000) || !validOptionalText(nextAction, 500) {
		return preparedUpdate{}, ErrInvalidInput
	}
	var nextFollowUpAt *time.Time
	if input.NextFollowUpAt != nil {
		utc := input.NextFollowUpAt.UTC()
		nextFollowUpAt = &utc
	}
	return preparedUpdate{name: name, phone: phone, email: email, wechat: wechat, school: school,
		major: major, grade: grade, currentLocation: currentLocation, targetCity: targetCity,
		targetPosition: targetPosition, expectedSalary: expectedSalary, jobIntention: jobIntention,
		projectExperience: projectExperience, internshipExperience: internshipExperience,
		skills: skills, certificates: certificates, nextAction: nextAction,
		nextFollowUpAt: nextFollowUpAt, version: input.Version}, nil
}

// --- 快速检查认证投影是否可能进入学生命令 ---
func actorEligible(actor auth.Account) bool {
	return actor.ID != "" && actor.State == "active" && !actor.MustChangePassword && (actor.Role == "owner" || actor.Role == "staff")
}

// --- 验证学生不透明身份形状 ---
func validStudentID(studentID string) bool {
	return len(studentID) >= 15 && len(studentID) <= 83 && len(studentID) > 2 && studentID[:2] == "S-"
}

// --- 验证员工档案不透明身份形状 ---
func validStaffID(staffID string) bool {
	return len(staffID) >= 15 && len(staffID) <= 83 && len(staffID) > 2 && staffID[:2] == "T-"
}

// --- 验证 UTF-8 用户文本字符长度 ---
func validText(value string, minimum int, maximum int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= minimum && length <= maximum
}

// --- 把空白可选文本统一为数据库 null ---
func normalizeOptional(value *string) *string {
	if value == nil {
		return nil
	}
	normalized := norm.NFKC.String(strings.TrimSpace(*value))
	if normalized == "" {
		return nil
	}
	return &normalized
}

// --- 验证可选文本最大长度 ---
func validOptionalText(value *string, maximum int) bool {
	return value == nil || validText(*value, 1, maximum)
}

// --- 验证可选邮箱是单一规范地址 ---
func validEmail(value *string) bool {
	if value == nil {
		return true
	}
	if !validText(*value, 3, 254) || strings.ContainsAny(*value, "<>\r\n") {
		return false
	}
	parsed, parseError := mail.ParseAddress(*value)
	return parseError == nil && parsed.Address == *value
}
