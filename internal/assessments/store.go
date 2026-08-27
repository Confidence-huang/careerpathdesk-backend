/*
受邀测评 PostgreSQL 数据包：在调用方事务中锁定并复核能力、学生、签发账号和活动问卷。
本文件不提交事务、不接触原始秘密，也不把学生现有资料返回给表单命令。
调用示例：commands.data.getCapability(ctx, tx, sessionID, digest, now)。
*/
package assessments

import (
	"context"       // 驱动当前请求的参数化 SQL。
	"crypto/subtle" // 以固定时间比较幂等请求摘要。
	"encoding/json" // 解码与首次提交同事务保存的安全回执。
	"errors"        // 区分无行能力与数据库故障。
	"time"          // 比较受限会话和原邀请的半开过期边界。

	"github.com/jackc/pgx/v5"        // 扫描并锁定同一 PostgreSQL 事务内的授权事实。
	"github.com/jackc/pgx/v5/pgconn" // 将约束失败收束为稳定领域错误。
)

type store struct {
	database transactionSource // database 只提供事务起点，提交权归 Commands。
}

type capabilityRecord struct {
	invitationID          string // invitationID 连接完成状态和来源审计。
	studentID             string // studentID 是能力唯一可修改的学生。
	assessmentVersion     string // assessmentVersion 绑定公开问题和私有评分定义。
	invitationVersion     int64  // invitationVersion 供终态条件更新防止静默覆盖。
	invitedStudentVersion int64  // invitedStudentVersion 是签发时冻结的学生版本。
	currentStudentVersion int64  // currentStudentVersion 是本事务锁定的最新版本。
	publicQuestions       []byte // publicQuestions 只在 Form 中解码为学生投影。
	scoringDefinition     []byte // scoringDefinition 仅供 Submit 的服务端评分使用。
}

// --- 动态复核并锁定受限能力 ---
func (data *store) getCapability(requestContext context.Context, transaction pgx.Tx, sessionID string, digest [32]byte, now time.Time) (capabilityRecord, error) {
	record := capabilityRecord{} // 所有能力事实来自下面一条一致快照查询。
	queryError := transaction.QueryRow(requestContext, `
		SELECT invitation.id, invitation.student_id, invitation.assessment_version,
			invitation.version, invitation.student_version, student.version,
			questionnaire.public_questions, questionnaire.scoring_definition
		FROM student_invitations AS invitation
		JOIN students AS student ON student.id = invitation.student_id
		JOIN accounts AS issuer ON issuer.id = invitation.issued_by_account_id
		JOIN assessment_questionnaires AS questionnaire ON questionnaire.version = invitation.assessment_version
		WHERE invitation.restricted_session_id = $1 AND invitation.restricted_session_digest = $2
			AND invitation.state = 'exchanged' AND invitation.restricted_session_expires_at > $3
			AND invitation.expires_at > $3 AND questionnaire.is_active
			AND issuer.state = 'active' AND NOT issuer.must_change_password
			AND (issuer.role = 'owner' OR (
				issuer.role = 'staff' AND issuer.staff_profile_id IS NOT NULL
				AND issuer.staff_profile_id = student.owner_staff_id
			))
		FOR UPDATE OF invitation, student, issuer, questionnaire`, sessionID, digest[:], now).Scan(
		&record.invitationID, &record.studentID, &record.assessmentVersion,
		&record.invitationVersion, &record.invitedStudentVersion, &record.currentStudentVersion,
		&record.publicQuestions, &record.scoringDefinition,
	)
	if errors.Is(queryError, pgx.ErrNoRows) { // 错误秘密、未知身份、终态、过期或失权不可区分。
		return capabilityRecord{}, ErrInvalidCapability
	}
	if queryError != nil { // 数据库故障不是一个可猜测的能力状态。
		return capabilityRecord{}, ErrWriteFailed
	}
	return record, nil // 锁保持到 Form 或 Submit 明确提交/回滚。
}

// --- 串行化同能力同键的网络重试 ---
func (data *store) lockSubmitIntent(requestContext context.Context, transaction pgx.Tx, capabilityID string, idempotencyKey string) error {
	_, lockError := transaction.Exec(requestContext, `SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text, 0))`, capabilityID, idempotencyKey) // 事务级锁自动释放且不建立额外表状态。
	if lockError != nil {                                                                                                                                            // 无法取得重试顺序时不能继续创建业务事实。
		return ErrWriteFailed
	}
	return nil
}

// --- 读取已经提交的最小回执 ---
func (data *store) findSubmitReplay(requestContext context.Context, transaction pgx.Tx, capabilityID string, idempotencyKey string, requestDigest [32]byte) (Receipt, bool, error) {
	var storedDigest []byte // storedDigest 只用于固定时间比较，不包含请求正文。
	var responseBody []byte // responseBody 只能解码为当前安全回执。
	queryError := transaction.QueryRow(requestContext, `
		SELECT request_digest, response_body
		FROM idempotency_records
		WHERE actor_scope = $1 AND action = 'assessment.submit' AND idempotency_key = $2
		FOR UPDATE`, capabilityID, idempotencyKey).Scan(&storedDigest, &responseBody)
	if errors.Is(queryError, pgx.ErrNoRows) { // 首次意图继续执行能力和业务验证。
		return Receipt{}, false, nil
	}
	if queryError != nil { // 无法确定是否已经提交时不能冒险重复写入。
		return Receipt{}, false, ErrWriteFailed
	}
	if len(storedDigest) != len(requestDigest) || subtle.ConstantTimeCompare(storedDigest, requestDigest[:]) != 1 { // 同 key 不同能力秘密或正文明确冲突。
		return Receipt{}, true, ErrIdempotencyConflict
	}
	receipt := Receipt{}
	if json.Unmarshal(responseBody, &receipt) != nil || !receipt.Completed || !validPublicResult(receipt.CommunicationStyle) { // 旧或损坏回执失败关闭，不伪造一个新结果。
		return Receipt{}, true, ErrWriteFailed
	}
	return receipt, true, nil
}

// --- 乐观更新十五字段资料并推进学生版本 ---
func (data *store) updateStudent(requestContext context.Context, transaction pgx.Tx, record capabilityRecord, capabilityID string, fields preparedStudentFields, now time.Time) (int64, error) {
	var studentVersion int64 // RETURNING 保证调用方使用真正写入后的版本。
	queryError := transaction.QueryRow(requestContext, `
		UPDATE students
		SET name = $4,
			phone = COALESCE($5, phone), wechat = COALESCE($6, wechat), school = COALESCE($7, school),
			major = COALESCE($8, major), grade = COALESCE($9, grade), current_location = COALESCE($10, current_location),
			target_city = COALESCE($11, target_city), target_position = COALESCE($12, target_position),
			expected_salary = COALESCE($13, expected_salary), job_intention = COALESCE($14, job_intention),
			project_experience = COALESCE($15, project_experience), internship_experience = COALESCE($16, internship_experience),
			skills = COALESCE($17, skills), certificates = COALESCE($18, certificates), source_kind = 'invitation', updated_by = $2,
			version = version + 1, updated_at = $3
		WHERE id = $1 AND version = $19
		RETURNING version`,
		record.studentID, capabilityID, now, fields.name, fields.phone, fields.wechat, fields.school,
		fields.major, fields.grade, fields.currentLocation, fields.targetCity, fields.targetPosition, fields.expectedSalary,
		fields.jobIntention, fields.projectExperience, fields.internshipExperience, fields.skills, fields.certificates,
		record.currentStudentVersion).Scan(&studentVersion)
	if errors.Is(queryError, pgx.ErrNoRows) { // 锁后仍用版本条件保留显式并发语义。
		return 0, ErrVersionConflict
	}
	if queryError != nil { // 约束或依赖故障必须让整个事务回滚。
		return 0, classifyAssessmentWriteError(queryError)
	}
	return studentVersion, nil
}

// --- 创建或版本化替换学生当前权威测评 ---
func (data *store) saveAssessment(requestContext context.Context, transaction pgx.Tx, assessmentID string, record capabilityRecord, answersBody []byte, scoreBody []byte, recommendationBody []byte, now time.Time) (string, error) {
	var storedAssessmentID string // 已有学生结果更新时保留原对象身份。
	queryError := transaction.QueryRow(requestContext, `
		INSERT INTO assessments (
			id, student_id, questionnaire_version, answers, server_score, internal_recommendation,
			source_invitation_id, version, submitted_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7, 1, $8, $8, $8)
		ON CONFLICT (student_id) DO UPDATE
		SET questionnaire_version = EXCLUDED.questionnaire_version, answers = EXCLUDED.answers,
			server_score = EXCLUDED.server_score, internal_recommendation = EXCLUDED.internal_recommendation,
			source_invitation_id = EXCLUDED.source_invitation_id, version = assessments.version + 1,
			submitted_at = EXCLUDED.submitted_at, updated_at = EXCLUDED.updated_at
		RETURNING id`, assessmentID, record.studentID, record.assessmentVersion, string(answersBody), string(scoreBody), string(recommendationBody), record.invitationID, now).Scan(&storedAssessmentID)
	if queryError != nil { // 答案、评分或来源任一不合法都不能留下学生资料更新。
		return "", classifyAssessmentWriteError(queryError)
	}
	return storedAssessmentID, nil
}

// --- 写入不含答案和资料的学生事件 ---
func (data *store) insertAssessmentEvent(requestContext context.Context, transaction pgx.Tx, eventID string, capabilityID string, studentID string, assessmentID string, assessmentVersion string, studentVersion int64, now time.Time) error {
	_, writeError := transaction.Exec(requestContext, `
		INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload, occurred_at)
		VALUES ($1, $2, 'assessment.submitted', 'invitation', $3,
			jsonb_build_object('assessment_id', $4::text, 'assessment_version', $5::text, 'student_version', $6::bigint), $7)`,
		eventID, studentID, capabilityID, assessmentID, assessmentVersion, studentVersion, now)
	if writeError != nil { // 事件失败必须回滚资料和测评。
		return ErrWriteFailed
	}
	return nil
}

// --- 写入不含答案和资料的邀请审计 ---
func (data *store) insertAssessmentAudit(requestContext context.Context, transaction pgx.Tx, auditID string, capabilityID string, assessmentID string, requestID string, assessmentVersion string, studentVersion int64, now time.Time) error {
	_, writeError := transaction.Exec(requestContext, `
		INSERT INTO audit_events (
			id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at
		) VALUES ($1, 'invitation', $2, 'assessment.submitted', 'assessment', $3, 'success', $4,
			jsonb_build_object('assessment_version', $5::text, 'student_version', $6::bigint), $7)`,
		auditID, capabilityID, assessmentID, requestID, assessmentVersion, studentVersion, now)
	if writeError != nil { // 审计失败不能产生未经追踪的完成事实。
		return ErrWriteFailed
	}
	return nil
}

// --- 保存与业务结果同事务的重复提交事实 ---
func (data *store) insertSubmitIdempotency(requestContext context.Context, transaction pgx.Tx, capabilityID string, idempotencyKey string, requestDigest [32]byte, receipt Receipt, assessmentID string, now time.Time) error {
	responseBody, encodeError := json.Marshal(receipt)
	if encodeError != nil || !receipt.Completed || !validPublicResult(receipt.CommunicationStyle) { // 只保存可安全原样重放的完整响应。
		return ErrWriteFailed
	}
	_, writeError := transaction.Exec(requestContext, `
		INSERT INTO idempotency_records (
			actor_scope, action, idempotency_key, request_digest, response_code,
			response_body, resource_id, created_at, expires_at
		) VALUES ($1, 'assessment.submit', $2, $3, 200, $4::jsonb,
			$5::text, $6::timestamptz, $6::timestamptz + interval '24 hours')`,
		capabilityID, idempotencyKey, requestDigest[:], responseBody, assessmentID, now)
	if writeError != nil { // 唯一键冲突代表同一意图并发或重用。
		return classifyIdempotencyWriteError(writeError)
	}
	return nil
}

// --- 销毁受限会话摘要并进入完成终态 ---
func (data *store) completeInvitation(requestContext context.Context, transaction pgx.Tx, record capabilityRecord, now time.Time) error {
	commandTag, updateError := transaction.Exec(requestContext, `
		UPDATE student_invitations
		SET state = 'completed', restricted_session_digest = NULL, completed_at = $3,
			version = version + 1, updated_at = $3
		WHERE id = $1 AND state = 'exchanged' AND version = $2`, record.invitationID, record.invitationVersion, now)
	if updateError != nil { // 注入故障或约束失败必须回滚完整提交。
		return ErrWriteFailed
	}
	if commandTag.RowsAffected() != 1 { // 终态或版本漂移不能被静默覆盖。
		return ErrInvalidCapability
	}
	return nil
}

// --- 将资料和测评约束失败分类为公开输入或内部写入失败 ---
func classifyAssessmentWriteError(writeError error) error {
	var postgresError *pgconn.PgError
	if errors.As(writeError, &postgresError) && (postgresError.Code == "23503" || postgresError.Code == "23514") { // 外键或检查约束说明提交不符合冻结合同。
		return ErrInvalidInput
	}
	return ErrWriteFailed
}

// --- 将重复提交唯一冲突转换为稳定错误 ---
func classifyIdempotencyWriteError(writeError error) error {
	var postgresError *pgconn.PgError
	if errors.As(writeError, &postgresError) && postgresError.Code == "23505" { // 同能力同动作同 key 只能存在一条。
		return ErrIdempotencyConflict
	}
	return ErrWriteFailed
}
