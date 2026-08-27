/*
运营统计：先从数据库恢复当前账号范围，再以一个 SQL 语句计算团队或本人四项同定义指标。
员工统计按 active 协作关系归属；旧阶段和教练任务不再决定当前产品工作量。
*/
package operations

import (
	"context" // 驱动当前账号复核、单语句聚合和事务提交。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth" // 接收认证模块形成的最小账号投影。
)

// --- 读取团队或本人同定义运营概览 ---
func (commands *Commands) Overview(ctx context.Context, actor auth.Account) (Statistics, error) {
	if actor.Role != "owner" && actor.Role != "staff" { // 未识别角色不进入统计 SQL。
		return Statistics{}, ErrForbidden
	}
	transaction, beginError := commands.database.Begin(ctx)
	if beginError != nil {
		return Statistics{}, ErrOperationFailed
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	current, actorError := requireCurrentActor(ctx, transaction, actor)
	if actorError != nil {
		return Statistics{}, actorError
	}
	statistics := Statistics{}
	queryError := transaction.QueryRow(ctx, `
		WITH scoped_students AS MATERIALIZED (
			SELECT student.id
			FROM students AS student
			WHERE student.closed_at IS NULL AND ($1::text = 'owner' OR EXISTS (SELECT 1 FROM student_staff_assignments AS assignment WHERE assignment.student_id = student.id AND assignment.staff_profile_id = $2 AND assignment.ended_at IS NULL) OR (student.owner_staff_id = $2 AND NOT EXISTS (SELECT 1 FROM student_staff_assignments AS legacy_assignment WHERE legacy_assignment.student_id = student.id)))
		)
		SELECT
			CASE WHEN $1::text = 'owner' THEN 'team' ELSE 'own' END,
			(SELECT count(*)::integer FROM scoped_students),
			(SELECT count(*)::integer FROM follow_up_records AS follow_up
				JOIN scoped_students AS student ON student.id = follow_up.student_id
				WHERE follow_up.overdue_occurrence),
			(SELECT count(*)::integer FROM student_attention_cases AS attention
				JOIN scoped_students AS student ON student.id = attention.student_id
				WHERE attention.status = 'open')`, current.role, current.staffProfileID,
	).Scan(
		&statistics.Scope, &statistics.InServiceStudents, &statistics.OverdueFollowUps,
		&statistics.OpenAttentionCases,
	)
	if queryError != nil {
		return Statistics{}, ErrOperationFailed
	}
	if commitError := transaction.Commit(ctx); commitError != nil {
		return Statistics{}, ErrOperationFailed
	}
	return statistics, nil // 只反馈四个不可识别聚合字段。
}
