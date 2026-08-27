/*
团队计划 PostgreSQL 数据包：集中执行账号复核、唯一计划读取、版本写入和最小审计 SQL。
所有方法都运行在 Commands 明确创建的事务中；本文件不提交事务、不解释 HTTP，也不记录计划正文到审计。
*/
package teamplan

import (
	"context" // 把取消和截止时间传入每条 PostgreSQL 操作。
	"errors"  // 区分无行、版本冲突和普通写入失败。

	"github.com/jackc/pgx/v5" // 执行事务查询并扫描固定投影。
)

type store struct{ database transactionSource } // store 只持有 Commands 提供的事务来源。
type currentActor struct{ id, role string }     // currentActor 是数据库最新账号事实。

const planProjection = `id, title, summary, content, version, updated_at` // 所有读取共享固定公开列顺序。

// --- 在事务内恢复最新活动团队账号 ---
func (data *store) requireActor(ctx context.Context, transaction pgx.Tx, actorID string) (currentActor, error) {
	actor := currentActor{id: actorID} // 保留调用方身份，角色必须来自数据库。
	var state string                   // state 决定账号当前是否仍可用。
	var mustChangePassword bool        // 首次改密账号不能进入正常工作台。
	queryError := transaction.QueryRow(ctx, `SELECT role, state, must_change_password FROM accounts WHERE id=$1 FOR SHARE`, actorID).Scan(&actor.role, &state, &mustChangePassword)
	if queryError != nil || state != "active" || mustChangePassword || (actor.role != "owner" && actor.role != "staff") { // 未知、停用或角色异常统一失败关闭。
		return currentActor{}, ErrForbidden
	}
	return actor, nil // 反馈数据库最新角色供命令继续裁决。
}

// --- 读取唯一团队计划 ---
func (data *store) read(ctx context.Context, transaction pgx.Tx) (Plan, error) {
	plan, scanError := scanPlan(transaction.QueryRow(ctx, `SELECT `+planProjection+` FROM team_plans WHERE id='TP-primary'`)) // 单例身份不接受调用方输入。
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if scanError != nil {
		return Plan{}, ErrWriteFailed
	}
	return plan, nil // 反馈工作台需要的完整计划。
}

// --- 用页面旧版本条件保存唯一计划 ---
func (data *store) update(ctx context.Context, transaction pgx.Tx, actorID string, input preparedUpdate) (Plan, error) {
	row := transaction.QueryRow(ctx, `UPDATE team_plans SET title=$2,summary=$3,content=$4,version=version+1,updated_by=$5,updated_at=statement_timestamp() WHERE id='TP-primary' AND version=$1 RETURNING `+planProjection, input.version, input.title, input.summary, input.content, actorID)
	plan, scanError := scanPlan(row) // 读取数据库实际递增后的版本和时间。
	if errors.Is(scanError, pgx.ErrNoRows) {
		return Plan{}, data.updateMiss(ctx, transaction)
	}
	if scanError != nil {
		return Plan{}, ErrWriteFailed
	}
	return plan, nil // 反馈刚提交事务中的新计划快照。
}

// --- 区分单例缺失与页面版本落后 ---
func (data *store) updateMiss(ctx context.Context, transaction pgx.Tx) error {
	var exists bool // 只读取是否存在，不泄漏计划正文。
	queryError := transaction.QueryRow(ctx, `SELECT true FROM team_plans WHERE id='TP-primary'`).Scan(&exists)
	if errors.Is(queryError, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if queryError != nil {
		return ErrWriteFailed
	}
	return ErrVersionConflict // 单例存在说明唯一失败原因是旧版本。
}

// --- 写入不含标题、摘要或正文的最小审计 ---
func (data *store) insertAudit(ctx context.Context, transaction pgx.Tx, auditID string, actorID string, requestID string, version int64) error {
	_, writeError := transaction.Exec(ctx, `INSERT INTO audit_events (id,actor_kind,actor_id,action,object_type,object_id,outcome,request_id,metadata) VALUES ($1,'account',$2,'team_plan.updated','team_plan','TP-primary','success',$3,jsonb_build_object('version',$4::bigint))`, auditID, actorID, requestID, version)
	if writeError != nil {
		return ErrWriteFailed
	}
	return nil // 反馈审计已与计划处于同一事务。
}

func scanPlan(row pgx.Row) (Plan, error) {
	plan := Plan{} // 按固定投影顺序接收公开字段。
	scanError := row.Scan(&plan.ID, &plan.Title, &plan.Summary, &plan.Content, &plan.Version, &plan.UpdatedAt)
	return plan, scanError // 调用方负责把无行转换为业务失败。
}
