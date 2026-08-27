/*
CareerPathDesk Foundation schema：建立逐人身份、学生、教练任务和最小治理关系。
本文件只定义结构，不创建账号、不写合成业务行，也不读取或转换 v1 数据。
由 Go migration 指令包裹在单一 PostgreSQL 事务中执行。
*/

-- --- 承担学生服务责任的员工档案 ---
CREATE TABLE staff_profiles (
    id text PRIMARY KEY CHECK (id ~ '^T-[A-Za-z0-9_-]{12,80}$'), -- 领域前缀让引用可辨认但仍保持不透明。
    display_name text NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 80), -- 仅保存合法显示名称。
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'inactive')), -- 非活动档案不能获得新学生责任。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 所有修改使用显式乐观版本。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一创建事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp() -- 数据库生成统一修改事实。
);

-- --- 老板与员工的逐人登录身份 ---
CREATE TABLE accounts (
    id text PRIMARY KEY CHECK (id ~ '^A-[A-Za-z0-9_-]{12,80}$'), -- 账号 ID 不承载姓名或联系方式。
    username_normalized text NOT NULL UNIQUE CHECK (char_length(username_normalized) BETWEEN 1 AND 128), -- 规范化登录名负责唯一性。
    username_display text NOT NULL CHECK (char_length(btrim(username_display)) BETWEEN 1 AND 128), -- 显示形式不参与身份比较。
    display_name text NOT NULL CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 80), -- 后台展示的人员名称。
    password_hash text NOT NULL CHECK (char_length(password_hash) BETWEEN 20 AND 512), -- 只保存 Argon2id 编码串。
    role text NOT NULL CHECK (role IN ('owner', 'staff')), -- 后台只有老板和员工两类角色。
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')), -- 账号停用但永不删除。
    staff_profile_id text UNIQUE REFERENCES staff_profiles(id) ON DELETE RESTRICT, -- 员工账号与责任档案一一关联。
    credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0), -- 改密和权限变化使旧会话失效。
    must_change_password boolean NOT NULL DEFAULT true, -- 初始或重置密码只允许进入改密旅程。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 账号管理拒绝静默并发覆盖。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一创建事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一修改事实。
    CHECK (
        (role = 'owner' AND staff_profile_id IS NULL)
        OR (role = 'staff' AND staff_profile_id IS NOT NULL)
    ) -- 老板不冒充员工档案，员工必须有唯一责任档案。
);

-- --- 可撤销且可轮换的一台设备登录事实 ---
CREATE TABLE account_sessions (
    id text PRIMARY KEY CHECK (id ~ '^AS-[A-Za-z0-9_-]{12,80}$'), -- 同时作为访问 JWT 的 sid。
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT, -- 会话必须保留历史账号归属。
    token_family_id text NOT NULL CHECK (char_length(token_family_id) BETWEEN 16 AND 128), -- 刷新重放按完整轮换族撤销。
    refresh_digest bytea NOT NULL UNIQUE CHECK (octet_length(refresh_digest) = 32), -- 只保存 SHA-256，不保存刷新秘密。
    credential_version bigint NOT NULL CHECK (credential_version > 0), -- 每次请求与账号最新版本比较。
    user_agent_summary text NOT NULL DEFAULT '' CHECK (char_length(user_agent_summary) <= 240), -- 只给本人设备页展示截断摘要。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 首次登录时间。
    last_seen_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 用于闲置过期判断。
    idle_expires_at timestamptz NOT NULL, -- 闲置窗口终点。
    absolute_expires_at timestamptz NOT NULL, -- 无论活动与否的最终终点。
    revoked_at timestamptz, -- 非空代表会话进入终态。
    revoke_reason text CHECK (revoke_reason IS NULL OR revoke_reason IN ('logout', 'owner_revoked', 'self_revoked', 'password_changed', 'account_disabled', 'credential_changed', 'refresh_rotated', 'refresh_replayed', 'expired')), -- 固定原因避免日志正文。
    replaced_by_session_id text REFERENCES account_sessions(id) ON DELETE RESTRICT, -- 保留刷新轮换链。
    CHECK (idle_expires_at <= absolute_expires_at), -- 闲置期限不能超过绝对期限。
    CHECK ((revoked_at IS NULL AND revoke_reason IS NULL) OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)) -- 撤销时间和原因必须共同出现。
);

CREATE INDEX account_sessions_account_state_idx
    ON account_sessions(account_id, revoked_at, absolute_expires_at); -- 支持本人设备与批量撤销查询。

-- --- 求职陪跑学生主档案 ---
CREATE TABLE students (
    id text PRIMARY KEY CHECK (id ~ '^S-[A-Za-z0-9_-]{12,80}$'), -- 保持与 v1 一致的不透明前缀语义。
    name text NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 80), -- 用户界面需要的学生名称。
    phone text CHECK (phone IS NULL OR char_length(phone) <= 40), -- 联系方式只在获准对象页返回。
    email text CHECK (email IS NULL OR char_length(email) <= 254), -- 联系邮箱不得进入普通日志或审计。
    service_stage text NOT NULL DEFAULT '待服务' CHECK (service_stage IN ('待服务', '服务中', '暂停服务', '已完成服务', '已退费')), -- 继续使用已确认的服务阶段合同。
    job_search_stage text NOT NULL DEFAULT '未开始' CHECK (job_search_stage IN ('未开始', '简历准备', '投递中', '面试中', '已就业')), -- 继续使用已确认的求职阶段合同。
    owner_staff_id text REFERENCES staff_profiles(id) ON DELETE RESTRICT, -- 当前负责人决定员工对象范围。
    next_action text CHECK (next_action IS NULL OR char_length(next_action) <= 500), -- 保存最小下一步，不复制到审计。
    next_follow_up_at timestamptz, -- 统一 UTC 时间事实驱动提醒。
    source_kind text NOT NULL CHECK (source_kind IN ('staff', 'invitation', 'migration')), -- 区分人工、受邀和未来离线迁移来源。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 学生修改和状态变化拒绝静默覆盖。
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100), -- 保存账号或受限来源标识。
    updated_by text NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 100), -- 保存最近一次可信修改来源。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一创建事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp() -- 数据库生成统一修改事实。
);

CREATE INDEX students_owner_service_idx
    ON students(owner_staff_id, service_stage, id); -- 支持对象范围列表和 15 人容量锁定计算。

-- --- 属于一个学生的可执行教练下一步 ---
CREATE TABLE coaching_tasks (
    id text PRIMARY KEY CHECK (id ~ '^CT-[A-Za-z0-9_-]{12,80}$'), -- 新领域对象使用明确 CT 前缀。
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE, -- 任务不能脱离学生存在。
    assignee_staff_id text REFERENCES staff_profiles(id) ON DELETE RESTRICT, -- 任务负责人可由老板显式选择。
    title text NOT NULL CHECK (char_length(btrim(title)) BETWEEN 1 AND 160), -- 标题是业务正文，不进入审计。
    due_at timestamptz, -- 可选截止时间统一保存为 UTC 事实。
    priority text NOT NULL DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high')), -- 固定三档优先级。
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'done', 'cancelled')), -- 任务只有开放、完成和取消终态。
    completed_at timestamptz, -- 只有完成状态拥有完成时间。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 任务更新拒绝静默覆盖。
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100), -- 保存创建账号身份。
    updated_by text NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 100), -- 保存最近修改账号身份。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一创建事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成统一修改事实。
    CHECK (
        (status = 'done' AND completed_at IS NOT NULL)
        OR (status <> 'done' AND completed_at IS NULL)
    ) -- 完成状态与完成时间必须一致。
);

CREATE INDEX coaching_tasks_student_state_idx
    ON coaching_tasks(student_id, status, due_at, id); -- 支持学生范围内任务列表和逾期查询。

-- --- 不复制业务正文的最小审计事实 ---
CREATE TABLE audit_events (
    id text PRIMARY KEY CHECK (id ~ '^AU-[A-Za-z0-9_-]{12,80}$'), -- 审计 ID 与业务对象 ID 分离。
    actor_kind text NOT NULL CHECK (actor_kind IN ('account', 'invitation', 'system')), -- 区分后台、受限能力和确定性系统动作。
    actor_id text NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 100), -- 保留历史主体标识但不强制级联外键。
    action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 80), -- 只允许应用层固定动作码。
    object_type text NOT NULL CHECK (char_length(object_type) BETWEEN 1 AND 40), -- 记录业务对象种类。
    object_id text NOT NULL CHECK (char_length(object_id) BETWEEN 1 AND 100), -- 记录对象标识但不复制对象内容。
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'conflict', 'failed')), -- 固定最小结果码。
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 8 AND 100), -- 将 HTTP 反馈与命令证据关联。
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'), -- 只允许枚举、计数、版本和引用 ID。
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp() -- 数据库生成不可猜测的发生时间。
);

CREATE INDEX audit_events_cursor_idx
    ON audit_events(occurred_at DESC, id DESC); -- 支持稳定游标而不使用易漂移 offset。

-- --- 创建型命令的请求级重复提交事实 ---
CREATE TABLE idempotency_records (
    actor_scope text NOT NULL CHECK (char_length(actor_scope) BETWEEN 1 AND 100), -- 绑定账号或单学生能力范围。
    action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 80), -- 绑定一个固定业务命令。
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 128), -- 由调用方为一次意图生成。
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32), -- 同 key 不同正文必须冲突。
    response_code integer NOT NULL CHECK (response_code BETWEEN 200 AND 599), -- 保存已经提交的最小 HTTP 结果。
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'), -- 只缓存无敏感内容的最小响应。
    resource_id text CHECK (resource_id IS NULL OR char_length(resource_id) <= 100), -- 可选关联创建出的对象。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 第一次提交时间。
    expires_at timestamptz NOT NULL, -- 到期后由独立维护命令精确清理。
    PRIMARY KEY (actor_scope, action, idempotency_key), -- 同主体同动作的 key 只能产生一个事实。
    CHECK (expires_at > created_at) -- 幂等记录必须拥有正向有效窗口。
);

CREATE INDEX idempotency_records_expiry_idx
    ON idempotency_records(expires_at); -- 支持不输出行内容的到期维护命令。
