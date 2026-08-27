/*
学生 PostgreSQL 数据包：执行账号复核、对象范围和学生投影 SQL，不决定 HTTP 或页面反馈。
所有方法都在 Commands 创建的明确事务中运行；本文件不提交事务或记录业务正文。
*/
package students

import (
	"context" // 把请求取消传给每条 PostgreSQL 查询。
	"errors"  // 将无行结果收敛为范围隐藏反馈。
	"time"    // 把不透明列表游标恢复为 PostgreSQL 时间边界。

	"github.com/jackc/pgx/v5"        // 使用事务、游标和统一行扫描接口。
	"github.com/jackc/pgx/v5/pgconn" // 将唯一约束收敛为幂等或写入冲突。

	"github.com/confidence-huang/careerpathdesk-backend/internal/assessments" // 将权威测评收窄为共享的四字段安全投影。
)

type store struct {
	database transactionSource // database 只为 Commands 提供事务起点。
}

type currentActor struct {
	id             string  // id 是最新数据库账号身份。
	role           string  // role 决定全局或本人责任范围。
	staffProfileID *string // staffProfileID 是员工唯一责任范围。
}

const studentProjection = `student.id, student.name, student.phone, student.email, student.wechat, student.school, student.major, student.grade, student.current_location, student.target_city, student.target_position, student.expected_salary, student.job_intention, student.project_experience, student.internship_experience, student.skills, student.certificates, student.owner_staff_id, student.next_action, student.next_follow_up_at, student.processing_basis, student.privacy_notice_version, student.privacy_notice_delivered_at, student.version, student.created_at, student.updated_at, assessment.server_score->>'primary_type', assessment.internal_recommendation->>'summary'`
const studentWriteProjection = `id, name, phone, email, wechat, school, major, grade, current_location, target_city, target_position, expected_salary, job_intention, project_experience, internship_experience, skills, certificates, owner_staff_id, next_action, next_follow_up_at, processing_basis, privacy_notice_version, privacy_notice_delivered_at, version, created_at, updated_at, NULL::text, NULL::text` // INSERT/UPDATE 不能在 RETURNING 中连接测评，调用方对已测评写入后重读。

// --- 在事务内恢复最新可用账号范围 ---
func (data *store) requireActor(ctx context.Context, transaction pgx.Tx, actorID string) (currentActor, error) {
	actor := currentActor{id: actorID}
	var state string
	var mustChangePassword bool
	queryError := transaction.QueryRow(ctx, `SELECT role, state, staff_profile_id, must_change_password FROM accounts WHERE id = $1 FOR UPDATE`, actorID).Scan(&actor.role, &state, &actor.staffProfileID, &mustChangePassword)
	if queryError != nil || state != "active" || mustChangePassword || (actor.role != "owner" && actor.role != "staff") || (actor.role == "staff" && actor.staffProfileID == nil) {
		return currentActor{}, ErrForbidden
	}
	return actor, nil
}

// --- 列出老板全量或员工本人责任范围 ---
func (data *store) listStudents(ctx context.Context, transaction pgx.Tx, actor currentActor, limit int, cursor *studentCursor) ([]Student, error) {
	var cursorTime *time.Time
	cursorID := ""
	if cursor != nil { // nil 保留首批语义；后续批次使用稳定复合边界。
		cursorTime = &cursor.UpdatedAt
		cursorID = cursor.ID
	}
	rows, queryError := transaction.Query(ctx, `
		SELECT `+studentProjection+`
		FROM students AS student
		LEFT JOIN assessments AS assessment ON assessment.student_id = student.id
		WHERE ($1::text = 'owner' OR EXISTS (
			SELECT 1 FROM student_staff_assignments AS assignment
			WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $2 AND assignment.ended_at IS NULL
		) OR (student.owner_staff_id = $2 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))
			AND ($3::timestamptz IS NULL OR (student.updated_at, student.id) < ($3::timestamptz, $4::text))
		ORDER BY student.updated_at DESC, student.id DESC
		LIMIT $5`, actor.role, actor.staffProfileID, cursorTime, cursorID, limit)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	students := make([]Student, 0, limit)
	for rows.Next() {
		student, scanError := scanStudent(rows)
		if scanError != nil {
			return nil, ErrWriteFailed
		}
		students = append(students, student)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	for index := range students {
		assignments, assignmentError := data.listActiveAssignments(ctx, transaction, students[index].ID)
		if assignmentError != nil {
			return nil, assignmentError
		}
		students[index].Assignments = assignments
	}
	return students, nil
}

// --- 查找已经提交的同一学生创建意图 ---
func (data *store) findCreateReplay(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, requestDigest [32]byte) (Student, bool, error) {
	var storedDigest []byte
	var resourceID *string
	queryError := transaction.QueryRow(ctx, `SELECT request_digest, resource_id FROM idempotency_records WHERE actor_scope = $1 AND action = 'student.create' AND idempotency_key = $2 FOR UPDATE`, actorID, idempotencyKey).Scan(&storedDigest, &resourceID)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return Student{}, false, nil
	}
	if queryError != nil {
		return Student{}, false, ErrWriteFailed
	}
	if !equalDigest(storedDigest, requestDigest[:]) {
		return Student{}, true, ErrIdempotencyConflict
	}
	if resourceID == nil {
		return Student{}, true, ErrWriteFailed
	}
	student, studentError := data.getStudent(ctx, transaction, currentActor{role: "owner"}, *resourceID, false)
	return student, true, studentError
}

// --- 插入已经准备好的学生主档 ---
func (data *store) insertStudent(ctx context.Context, transaction pgx.Tx, actorID string, ownerStaffID *string, input preparedCreate) (Student, error) {
	row := transaction.QueryRow(ctx, `
		INSERT INTO students (id, name, phone, email, service_stage, job_search_stage, owner_staff_id, source_kind, created_by, updated_by, processing_basis, privacy_notice_version, privacy_notice_delivered_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'staff', $8, $8, $9, $10, $11)
		RETURNING `+studentWriteProjection,
		input.studentID, input.name, input.phone, input.email, input.serviceStage, input.jobSearchStage, ownerStaffID, actorID,
		input.processingBasis, input.privacyNoticeVersion, input.privacyNoticeDeliveredAt,
	)
	student, scanError := scanStudent(row)
	if scanError != nil {
		return Student{}, classifyWriteError(scanError)
	}
	return student, nil
}

// --- 在 SQL 中同时执行身份范围和目标读取 ---
func (data *store) getStudent(ctx context.Context, transaction pgx.Tx, actor currentActor, studentID string, lock bool) (Student, error) {
	lockClause := ""
	if lock {
		lockClause = " FOR UPDATE OF student"
	}
	row := transaction.QueryRow(ctx, `SELECT `+studentProjection+` FROM students AS student LEFT JOIN assessments AS assessment ON assessment.student_id = student.id WHERE student.id = $1 AND ($2::text = 'owner' OR EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $3 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $3 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))`+lockClause, studentID, actor.role, actor.staffProfileID)
	student, scanError := scanStudent(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Student{}, ErrNotFound
	}
	if scanError != nil {
		return Student{}, ErrWriteFailed
	}
	assignments, assignmentError := data.listActiveAssignments(ctx, transaction, student.ID)
	if assignmentError != nil {
		return Student{}, assignmentError
	}
	student.Assignments = assignments
	return student, nil
}

// --- 读取当前协作成员，历史记录仍保留在表中但不进入日常详情 ---
func (data *store) listActiveAssignments(ctx context.Context, transaction pgx.Tx, studentID string) ([]Assignment, error) {
	rows, queryError := transaction.Query(ctx, `SELECT assignment.id, assignment.staff_profile_id, staff.display_name, assignment.assignment_role, assignment.started_at FROM student_staff_assignments AS assignment JOIN staff_profiles AS staff ON staff.id = assignment.staff_profile_id WHERE assignment.student_id = $1 AND assignment.ended_at IS NULL ORDER BY CASE assignment.assignment_role WHEN 'primary' THEN 0 ELSE 1 END, assignment.started_at, assignment.id`, studentID)
	if queryError != nil {
		return nil, ErrWriteFailed
	}
	defer rows.Close()
	assignments := make([]Assignment, 0, 4)
	for rows.Next() {
		assignment := Assignment{}
		if scanError := rows.Scan(&assignment.ID, &assignment.StaffProfileID, &assignment.DisplayName, &assignment.Role, &assignment.StartedAt); scanError != nil {
			return nil, ErrWriteFailed
		}
		assignments = append(assignments, assignment)
	}
	if rows.Err() != nil {
		return nil, ErrWriteFailed
	}
	return assignments, nil
}

// --- 条件写入学生主档并推进版本 ---
func (data *store) updateStudent(ctx context.Context, transaction pgx.Tx, actorID string, studentID string, input preparedUpdate) (Student, error) {
	row := transaction.QueryRow(ctx, `
		UPDATE students
		SET name = $3, phone = $4, email = $5, wechat = $6, school = $7, major = $8, grade = $9,
			current_location = $10, target_city = $11, target_position = $12, expected_salary = $13,
			job_intention = $14, project_experience = $15, internship_experience = $16,
			skills = $17, certificates = $18, next_action = $19, next_follow_up_at = $20,
			version = version + 1, updated_by = $2, updated_at = statement_timestamp()
		WHERE id = $1 AND version = $21
		RETURNING `+studentWriteProjection,
		studentID, actorID, input.name, input.phone, input.email, input.wechat, input.school, input.major,
		input.grade, input.currentLocation, input.targetCity, input.targetPosition, input.expectedSalary,
		input.jobIntention, input.projectExperience, input.internshipExperience, input.skills,
		input.certificates, input.nextAction, input.nextFollowUpAt, input.version,
	)
	student, scanError := scanStudent(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Student{}, ErrVersionConflict
	}
	if scanError != nil {
		return Student{}, ErrWriteFailed
	}
	return student, nil
}

// --- 锁定并验证创建或分配命令选择的目标员工仍可用 ---
func (data *store) requireActiveStaff(ctx context.Context, transaction pgx.Tx, staffID string) error {
	var state string
	if queryError := transaction.QueryRow(ctx, `SELECT state FROM staff_profiles WHERE id = $1 FOR UPDATE`, staffID).Scan(&state); errors.Is(queryError, pgx.ErrNoRows) {
		return ErrNotFound
	} else if queryError != nil {
		return ErrWriteFailed
	}
	if state != "active" {
		return ErrNotFound
	}
	return nil
}

// --- 条件写入学生负责人并推进版本 ---
func (data *store) assignStudent(ctx context.Context, transaction pgx.Tx, actorID string, studentID string, input AssignInput) (Student, error) {
	row := transaction.QueryRow(ctx, `
		UPDATE students
		SET owner_staff_id = $3, version = version + 1, updated_by = $2, updated_at = statement_timestamp()
		WHERE id = $1 AND version = $4
		RETURNING `+studentWriteProjection, studentID, actorID, input.OwnerStaffID, input.Version)
	student, scanError := scanStudent(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Student{}, ErrVersionConflict
	}
	if scanError != nil {
		return Student{}, ErrWriteFailed
	}
	return student, nil
}

// --- 新建一段不会覆盖旧历史的学生协作关系 ---
func (data *store) insertAssignment(ctx context.Context, transaction pgx.Tx, assignmentID string, studentID string, staffID string, role string, actorID string) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO student_staff_assignments (id, student_id, staff_profile_id, assignment_role, created_by_account_id) VALUES ($1, $2, $3, $4, $5)`, assignmentID, studentID, staffID, role, actorID)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	return nil
}

// --- 首次启用协作时把迁移前 owner 缓存固化为主负责人，避免协作者插入后切断原老师范围 ---
func (data *store) ensureLegacyPrimaryAssignment(ctx context.Context, transaction pgx.Tx, assignmentID string, studentID string, staffID string, actorID string) error {
	_, writeError := transaction.Exec(ctx, `
		INSERT INTO student_staff_assignments (id, student_id, staff_profile_id, assignment_role, created_by_account_id)
		SELECT $1, $2, $3, 'primary', $4
		WHERE NOT EXISTS (SELECT 1 FROM student_staff_assignments WHERE student_id = $2)`, assignmentID, studentID, staffID, actorID)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	return nil
}

// --- 交接主负责人：新负责人晋升，原负责人自动转为协作者，所有旧角色段只结束不覆盖 ---
func (data *store) replacePrimaryAssignment(ctx context.Context, transaction pgx.Tx, primaryAssignmentID string, formerPrimaryAssignmentID string, studentID string, previousOwnerStaffID *string, ownerStaffID *string, actorID string) error {
	if previousOwnerStaffID != nil && ownerStaffID != nil && *previousOwnerStaffID == *ownerStaffID {
		var activePrimary bool
		if queryError := transaction.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM student_staff_assignments WHERE student_id = $1 AND staff_profile_id = $2 AND assignment_role = 'primary' AND ended_at IS NULL)`, studentID, *ownerStaffID).Scan(&activePrimary); queryError != nil {
			return ErrWriteFailed
		}
		if activePrimary {
			return nil
		}
		if _, writeError := transaction.Exec(ctx, `UPDATE student_staff_assignments SET ended_at = statement_timestamp(), ended_by_account_id = $3, updated_at = statement_timestamp() WHERE student_id = $1 AND staff_profile_id = $2 AND ended_at IS NULL`, studentID, *ownerStaffID, actorID); writeError != nil {
			return ErrWriteFailed
		}
		return data.insertAssignment(ctx, transaction, primaryAssignmentID, studentID, *ownerStaffID, "primary", actorID)
	}
	if _, writeError := transaction.Exec(ctx, `UPDATE student_staff_assignments SET ended_at = statement_timestamp(), ended_by_account_id = $2, updated_at = statement_timestamp() WHERE student_id = $1 AND ended_at IS NULL AND (assignment_role = 'primary' OR staff_profile_id = $3)`, studentID, actorID, ownerStaffID); writeError != nil {
		return ErrWriteFailed
	}
	if ownerStaffID == nil {
		return nil
	}
	if insertError := data.insertAssignment(ctx, transaction, primaryAssignmentID, studentID, *ownerStaffID, "primary", actorID); insertError != nil {
		return insertError
	}
	if previousOwnerStaffID != nil && *previousOwnerStaffID != *ownerStaffID {
		return data.insertAssignment(ctx, transaction, formerPrimaryAssignmentID, studentID, *previousOwnerStaffID, "collaborator", actorID)
	}
	return nil
}

func (data *store) endCollaborator(ctx context.Context, transaction pgx.Tx, studentID string, staffID string, actorID string) error {
	commandTag, writeError := transaction.Exec(ctx, `UPDATE student_staff_assignments SET ended_at = statement_timestamp(), ended_by_account_id = $3, updated_at = statement_timestamp() WHERE student_id = $1 AND staff_profile_id = $2 AND assignment_role = 'collaborator' AND ended_at IS NULL`, studentID, staffID, actorID)
	if writeError != nil {
		return ErrWriteFailed
	}
	if commandTag.RowsAffected() != 1 {
		return ErrInvalidInput
	}
	return nil
}

func (data *store) touchStudent(ctx context.Context, transaction pgx.Tx, studentID string, actorID string, version int64) (Student, error) {
	row := transaction.QueryRow(ctx, `UPDATE students SET version = version + 1, updated_by = $2, updated_at = statement_timestamp() WHERE id = $1 AND version = $3 RETURNING `+studentWriteProjection, studentID, actorID, version)
	student, scanError := scanStudent(row)
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Student{}, ErrVersionConflict
	}
	if scanError != nil {
		return Student{}, ErrWriteFailed
	}
	return student, nil
}

// --- 写入不含学生正文或联系方式的固定审计 ---
func (data *store) insertAudit(ctx context.Context, transaction pgx.Tx, auditID string, actorID string, action string, studentID string, requestID string, version int64) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata) VALUES ($1, 'account', $2, $3, 'student', $4, 'success', $5, jsonb_build_object('version', $6::bigint))`, auditID, actorID, action, studentID, requestID, version)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 创建审计只保留学生身份、依据和说明版本，不复制姓名、联系方式或自由正文 ---
func (data *store) insertCreateAudit(ctx context.Context, transaction pgx.Tx, auditID string, actorID string, studentID string, requestID string, processingBasis string, privacyNoticeVersion string) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata) VALUES ($1, 'account', $2, 'student.created', 'student', $3, 'success', $4, jsonb_build_object('processing_basis', $5::text, 'privacy_notice_version', $6::text))`, auditID, actorID, studentID, requestID, processingBasis, privacyNoticeVersion)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil
}

// --- 写入学生创建命令的幂等完成事实 ---
func (data *store) insertCreateIdempotency(ctx context.Context, transaction pgx.Tx, actorID string, idempotencyKey string, requestDigest [32]byte, studentID string) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO idempotency_records (actor_scope, action, idempotency_key, request_digest, response_code, response_body, resource_id, expires_at) VALUES ($1, 'student.create', $2, $3, 201, jsonb_build_object('id', $4::text), $4, statement_timestamp() + interval '24 hours')`, actorID, idempotencyKey, requestDigest[:], studentID)
	if writeError != nil {
		return classifyWriteError(writeError)
	}
	return nil
}

// --- 将数据库约束收敛为稳定学生错误 ---
func classifyWriteError(writeError error) error {
	var postgresError *pgconn.PgError
	if errors.As(writeError, &postgresError) {
		if postgresError.Code == "23505" {
			return ErrIdempotencyConflict
		}
		if postgresError.Code == "23503" || postgresError.Code == "23514" {
			return ErrInvalidInput
		}
	}
	return ErrWriteFailed
}

// --- 固定时间比较两个 SHA-256 摘要 ---
func equalDigest(left []byte, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

// --- 扫描固定学生公开投影 ---
func scanStudent(row pgx.Row) (Student, error) {
	student := Student{}
	var primaryType *string // nil/nil 是未测评；只有一个存在代表权威 JSON 已损坏。
	var summary *string
	scanError := row.Scan(
		&student.ID, &student.Name, &student.Phone, &student.Email, &student.Wechat, &student.School,
		&student.Major, &student.Grade, &student.CurrentLocation, &student.TargetCity,
		&student.TargetPosition, &student.ExpectedSalary, &student.JobIntention,
		&student.ProjectExperience, &student.InternshipExperience, &student.Skills, &student.Certificates,
		&student.OwnerStaffID,
		&student.NextAction, &student.NextFollowUpAt, &student.ProcessingBasis,
		&student.PrivacyNoticeVersion, &student.PrivacyNoticeDeliveredAt, &student.Version,
		&student.CreatedAt, &student.UpdatedAt,
		&primaryType, &summary,
	)
	if scanError != nil {
		return Student{}, scanError
	}
	if primaryType == nil && summary == nil {
		return student, nil
	}
	if primaryType == nil || summary == nil {
		return Student{}, ErrWriteFailed
	}
	communicationStyle, valid := assessments.ProjectPublicResult(*primaryType, *summary)
	if !valid { // 未知键、空摘要或超限内容不能暴露为伪结果。
		return Student{}, ErrWriteFailed
	}
	student.CommunicationStyle = &communicationStyle
	return student, nil
}
