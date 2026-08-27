/*
CareerPathDesk 跟进、双状态历史、学生事件与人工关注 schema。
本文件只保存可追溯事实和数据库不变量；48/72 小时、容量、权限与人工结论流程留在业务命令。
由 Go migration 指令在 Foundation 之后以单一 PostgreSQL 事务执行。
*/

-- --- 保存一次联系、回复线程和学生下一步的权威来源 ---
CREATE TABLE follow_up_records (
    id text PRIMARY KEY CHECK (id ~ '^FU-[A-Za-z0-9_-]{12,80}$'), -- 跟进 ID 可辨认但不携带正文或人员信息。
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE, -- 跟进始终服从学生对象范围和生命周期。
    contacted_at timestamptz NOT NULL, -- 可信 UTC 联系时间决定派生下一步和关注窗口。
    channel text NOT NULL CHECK (char_length(btrim(channel)) BETWEEN 1 AND 40), -- 渠道是受控短值而不是联系正文。
    valid_contact boolean NOT NULL DEFAULT false, -- 明确有效联系才重置普通无联系时钟。
    reply_required boolean NOT NULL DEFAULT false, -- 声明当前事实是否等待学生回复。
    reply_thread_id text CHECK (reply_thread_id IS NULL OR reply_thread_id ~ '^RT-[A-Za-z0-9_-]{12,80}$'), -- 线程隔离连续无回复次数。
    student_replied_at timestamptz, -- 明确回复时间只重置所属线程。
    overdue_occurrence boolean NOT NULL DEFAULT false, -- 单调确认的逾期事实参与第三次升级规则。
    next_action text CHECK (next_action IS NULL OR char_length(next_action) <= 500), -- 正文只留在获准业务表。
    next_follow_up_at timestamptz, -- 下次跟进时间与下一步共同派生到学生主档案。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 更新和删除使用显式乐观版本。
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100), -- 保存创建动作的逐人账号身份。
    updated_by text NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 100), -- 保存最近一次修改来源。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一创建事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一修改事实。
    CHECK (NOT reply_required OR reply_thread_id IS NOT NULL), -- 等待回复必须绑定明确事项，禁止跨线程累计。
    CHECK (student_replied_at IS NULL OR reply_thread_id IS NOT NULL) -- 回复事实必须能定位被重置的线程。
);

CREATE INDEX follow_up_records_student_time_idx
    ON follow_up_records(student_id, contacted_at DESC, id DESC); -- 支持范围列表和最新派生事实重建。

CREATE INDEX follow_up_records_reply_thread_idx
    ON follow_up_records(student_id, reply_thread_id, contacted_at, id)
    WHERE reply_thread_id IS NOT NULL; -- 支持逐线程计算连续未回复序列。

CREATE INDEX follow_up_records_overdue_idx
    ON follow_up_records(student_id, contacted_at, id)
    WHERE overdue_occurrence; -- 只扫描已确认逾期事实以判断第三次升级。

-- --- 追加服务或求职阶段的版本化变化与受限撤销事实 ---
CREATE TABLE student_status_history (
    id text PRIMARY KEY CHECK (id ~ '^SH-[A-Za-z0-9_-]{12,80}$'), -- 状态变化拥有独立于学生版本的稳定身份。
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE, -- 历史只能属于一个学生聚合根。
    dimension text NOT NULL CHECK (dimension IN ('service', 'job_search')), -- 两个维度独立排序和撤销。
    from_value text NOT NULL CHECK (char_length(btrim(from_value)) BETWEEN 1 AND 40), -- 保存变化前的受控阶段值。
    to_value text NOT NULL CHECK (char_length(btrim(to_value)) BETWEEN 1 AND 40), -- 保存变化后的受控阶段值。
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 500), -- 人工原因留在获准历史而不进入审计。
    base_student_version bigint NOT NULL CHECK (base_student_version > 0), -- 记录命令接受的学生旧版本。
    student_version bigint NOT NULL CHECK (student_version > 1), -- 记录该变化提交后的学生版本。
    changed_by_account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT, -- 保留逐人历史归属。
    changed_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成变化发生时间。
    undone_by_account_id text REFERENCES accounts(id) ON DELETE RESTRICT, -- 非空时标识执行受限撤销的账号。
    undone_at timestamptz, -- 非空时原记录已由反向变化撤销。
    reverses_status_change_id text UNIQUE REFERENCES student_status_history(id) ON DELETE RESTRICT, -- 反向记录只引用一个原变化。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 撤销原记录时拒绝并发覆盖。
    CHECK (from_value <> to_value), -- 没有实际变化的请求不能污染历史。
    CHECK (student_version = base_student_version + 1), -- 每条变化恰好推进一次学生聚合版本。
    CHECK (
        (undone_at IS NULL AND undone_by_account_id IS NULL)
        OR (undone_at IS NOT NULL AND undone_by_account_id IS NOT NULL)
    ), -- 撤销时间与操作者必须共同出现。
    CHECK (reverses_status_change_id IS NULL OR reverses_status_change_id <> id) -- 反向历史不能引用自身。
);

CREATE INDEX student_status_history_timeline_idx
    ON student_status_history(student_id, dimension, changed_at DESC, id DESC); -- 支持逐维度历史和最新活动变化查询。

-- --- 保存不复制正文的学生业务时间线 ---
CREATE TABLE student_events (
    id text PRIMARY KEY CHECK (id ~ '^EV-[A-Za-z0-9_-]{12,80}$'), -- 事件引用可进入关注证据而不暴露业务内容。
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE, -- 事件始终属于一个受保护学生。
    event_type text NOT NULL CHECK (char_length(btrim(event_type)) BETWEEN 1 AND 80), -- 应用只写固定事件码。
    actor_kind text NOT NULL CHECK (actor_kind IN ('account', 'invitation', 'system')), -- 区分逐人账号、受限能力和确定性系统动作。
    actor_id text NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 100), -- 保留主体引用但不复制身份正文。
    payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'), -- 只保存状态、时间、布尔和对象 ID。
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp() -- 数据库生成或接受可信 UTC 事件时间。
);

CREATE INDEX student_events_timeline_idx
    ON student_events(student_id, occurred_at DESC, id DESC); -- 支持获准学生时间线稳定排序。

CREATE INDEX student_events_type_time_idx
    ON student_events(event_type, occurred_at DESC, id DESC); -- 支持投诉等固定事实的确定性关注扫描。

-- --- 保存需要老板人工判断的最小证据事项 ---
CREATE TABLE student_attention_cases (
    id text PRIMARY KEY CHECK (id ~ '^AC-[A-Za-z0-9_-]{12,80}$'), -- 关注事项身份不携带学生姓名或结论正文。
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE, -- 事项服从学生生命周期和删除前人工门禁。
    rule_code text NOT NULL CHECK (rule_code IN ('no_contact_72h', 'complaint', 'third_followup_overdue', 'student_no_reply')), -- 主规则码提供稳定分类和幂等键。
    trigger_codes text[] NOT NULL, -- 同一开放事项可合并多个同时成立的固定触发码。
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'array' AND jsonb_array_length(evidence) > 0), -- 只保存对象类型与 ID 引用数组。
    evidence_fingerprint bytea NOT NULL CHECK (octet_length(evidence_fingerprint) = 32), -- 去重身份来自规范化证据引用的 SHA-256。
    first_triggered_at timestamptz NOT NULL, -- 保留该事项第一次成立的可信时间。
    last_triggered_at timestamptz NOT NULL, -- 合并新触发时只向后推进最近时间。
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'dismissed')), -- 开放、已结论和已驳回是唯一生命周期。
    conclusion_code text CHECK (conclusion_code IS NULL OR conclusion_code IN ('continue_service', 'contact_student', 'internal_review', 'dismiss')), -- 只允许 OpenAPI 已冻结的人工结论。
    conclusion_reason text CHECK (conclusion_reason IS NULL OR char_length(btrim(conclusion_reason)) BETWEEN 1 AND 500), -- 最小理由留在老板可见事项中。
    concluded_by_account_id text REFERENCES accounts(id) ON DELETE RESTRICT, -- 成功结论保留逐人老板身份。
    concluded_at timestamptz, -- 结论时间与人工结论字段共同进入终态。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 老板结论使用乐观版本且不可静默改写。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成事项创建事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成最近一次合法变化时间。
    UNIQUE (student_id, rule_code, evidence_fingerprint), -- 同一规则与证据集合只形成一个事项。
    CHECK (cardinality(trigger_codes) BETWEEN 1 AND 4), -- 至少一个且最多包含全部四种已确认规则。
    CHECK (rule_code = ANY(trigger_codes)), -- 主规则必须出现在合并触发集合中。
    CHECK (trigger_codes <@ ARRAY['no_contact_72h', 'complaint', 'third_followup_overdue', 'student_no_reply']::text[]), -- 禁止未知自动决策码进入数据库。
    CHECK (last_triggered_at >= first_triggered_at), -- 最近触发时间不能早于事项建立时间。
    CHECK (
        (
            status = 'open'
            AND conclusion_code IS NULL
            AND conclusion_reason IS NULL
            AND concluded_by_account_id IS NULL
            AND concluded_at IS NULL
        )
        OR (
            status = 'resolved'
            AND conclusion_code IN ('continue_service', 'contact_student', 'internal_review')
            AND conclusion_reason IS NOT NULL
            AND concluded_by_account_id IS NOT NULL
            AND concluded_at IS NOT NULL
        )
        OR (
            status = 'dismissed'
            AND conclusion_code = 'dismiss'
            AND conclusion_reason IS NOT NULL
            AND concluded_by_account_id IS NOT NULL
            AND concluded_at IS NOT NULL
        )
    ) -- 人工结论与事项终态必须形成一个不可矛盾的事实包。
);

CREATE INDEX student_attention_cases_owner_queue_idx
    ON student_attention_cases(status, last_triggered_at DESC, id DESC); -- 支持老板按最新触发读取最小事项队列。

CREATE INDEX student_attention_cases_student_state_idx
    ON student_attention_cases(student_id, status, first_triggered_at, id); -- 支持评估时查找开放事项和旧证据终态。

CREATE INDEX student_attention_cases_trigger_codes_idx
    ON student_attention_cases USING gin(trigger_codes); -- 支持按固定触发码统计与运营查询。
