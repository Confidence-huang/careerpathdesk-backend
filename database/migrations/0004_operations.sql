/*
CareerPathDesk 运营 schema：保存一次导出确认，并为固定审计过滤和失效确认维护建立索引。
本文件只定义 digest、绑定关系和查询路径；权限、CSV 内容、确认生成与一致快照编排留给业务命令。
由 Go migration 指令在前三个版本之后以单一 PostgreSQL 事务执行。
*/

-- --- 让一次确认在数据库层绑定同一个账号与会话 ---
ALTER TABLE account_sessions
    ADD CONSTRAINT account_sessions_id_account_unique UNIQUE (id, account_id); -- 复合唯一键让导出确认不能把别人的会话绑定到当前账号。

-- --- 保存不含原始秘密的短期一次导出确认 ---
CREATE TABLE export_confirmations (
    confirmation_digest bytea PRIMARY KEY CHECK (octet_length(confirmation_digest) = 32), -- 只保存 SHA-256，原始确认只在成功签发反馈中出现一次。
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT, -- 账号身份不可因生命周期变化被级联抹除。
    session_id text NOT NULL, -- 会话身份与账号通过下方复合外键共同验证。
    export_type text NOT NULL CHECK (export_type IN ('students', 'follow-ups', 'assessments')), -- 只允许 OpenAPI 已注册的三类导出。
    expires_at timestamptz NOT NULL, -- 到达该 UTC 时刻立即失效，应用不提供额外宽限。
    used_at timestamptz, -- 非空代表确认已经成功消费并永久拒绝重放。
    FOREIGN KEY (session_id, account_id)
        REFERENCES account_sessions(id, account_id) ON DELETE RESTRICT, -- 数据库拒绝跨账号会话误绑。
    CHECK (used_at IS NULL OR used_at < expires_at) -- 成功消费只能发生在精确过期边界之前。
);

CREATE INDEX export_confirmations_active_session_idx
    ON export_confirmations(account_id, session_id, export_type, expires_at)
    WHERE used_at IS NULL; -- 支持当前账号会话的活动确认核对和有界失效处理。

CREATE INDEX export_confirmations_expiry_idx
    ON export_confirmations(expires_at, confirmation_digest); -- 支持按精确时间清理过期确认且只报告计数。

CREATE INDEX export_confirmations_used_idx
    ON export_confirmations(used_at, confirmation_digest)
    WHERE used_at IS NOT NULL; -- 支持维护命令清理已消费确认而不扫描活动记录。

-- --- 为固定审计过滤保留稳定发生时间与 ID 游标 ---
CREATE INDEX audit_events_action_object_cursor_idx
    ON audit_events(action, object_type, occurred_at DESC, id DESC); -- 同时支持 action 单筛选和 action+object_type 组合筛选。

CREATE INDEX audit_events_object_cursor_idx
    ON audit_events(object_type, occurred_at DESC, id DESC); -- object_type 单筛选不能依赖前导 action，因此拥有独立索引。
