-- CAREERPATHDESK_SYNTHETIC_SEED_V1
/*
CareerPathDesk Foundation 合成数据：建立一名老板、两名员工、四名学生和对应主负责人关系。
全部身份、名称、时间和关系均为固定 Synthetic 测试事实；不含联系方式、外部导入或 v1 数据。
该文件只由 synthetic-only Go seed 指令在当前 schema 版本上执行。
*/

-- --- 固定两名承担学生责任的合成员工 ---
INSERT INTO staff_profiles (id, display_name, state, version, created_at, updated_at) VALUES
    ('T-syntheticcoach01', 'Synthetic Coach One', 'active', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
    ('T-syntheticcoach02', 'Synthetic Coach Two', 'active', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
ON CONFLICT (id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    state = EXCLUDED.state,
    version = EXCLUDED.version,
    created_at = EXCLUDED.created_at,
    updated_at = EXCLUDED.updated_at;

-- --- 固定一名老板和两名逐人员工账号 ---
INSERT INTO accounts (
    id, username_normalized, username_display, display_name, password_hash,
    role, state, staff_profile_id, credential_version, must_change_password,
    version, created_at, updated_at
) VALUES
    ('A-syntheticowner01', 'synthetic-owner', 'synthetic-owner', 'Synthetic Owner', '{{SYNTHETIC_PASSWORD_HASH}}', 'owner', 'active', NULL, 1, true, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
    ('A-syntheticstaff01', 'synthetic-staff-one', 'synthetic-staff-one', 'Synthetic Staff One', '{{SYNTHETIC_PASSWORD_HASH}}', 'staff', 'active', 'T-syntheticcoach01', 1, true, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
    ('A-syntheticstaff02', 'synthetic-staff-two', 'synthetic-staff-two', 'Synthetic Staff Two', '{{SYNTHETIC_PASSWORD_HASH}}', 'staff', 'active', 'T-syntheticcoach02', 1, true, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
ON CONFLICT (id) DO UPDATE SET
    username_normalized = EXCLUDED.username_normalized,
    username_display = EXCLUDED.username_display,
    display_name = EXCLUDED.display_name,
    password_hash = EXCLUDED.password_hash,
    role = EXCLUDED.role,
    state = EXCLUDED.state,
    staff_profile_id = EXCLUDED.staff_profile_id,
    credential_version = EXCLUDED.credential_version,
    must_change_password = EXCLUDED.must_change_password,
    version = EXCLUDED.version,
    created_at = EXCLUDED.created_at,
    updated_at = EXCLUDED.updated_at;

-- --- 固定四名不含联系方式的合成学生 ---
INSERT INTO students (
    id, name, phone, email, service_stage, job_search_stage, owner_staff_id,
    next_action, next_follow_up_at, source_kind, version, created_by, updated_by,
    created_at, updated_at, processing_basis, privacy_notice_version,
    privacy_notice_delivered_at, closed_at, retention_due_at
) VALUES
    ('S-syntheticstudent01', 'Synthetic Student Alpha', NULL, NULL, '服务中', '简历准备', 'T-syntheticcoach01', NULL, NULL, 'staff', 1, 'A-syntheticstaff01', 'A-syntheticstaff01', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'service_contract', 'privacy-notice-v1', '2026-01-01T00:00:00Z', NULL, NULL),
    ('S-syntheticstudent02', 'Synthetic Student Beta', NULL, NULL, '服务中', '投递中', 'T-syntheticcoach01', NULL, NULL, 'staff', 1, 'A-syntheticstaff01', 'A-syntheticstaff01', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'service_contract', 'privacy-notice-v1', '2026-01-01T00:00:00Z', NULL, NULL),
    ('S-syntheticstudent03', 'Synthetic Student Gamma', NULL, NULL, '服务中', '面试中', 'T-syntheticcoach02', NULL, NULL, 'staff', 1, 'A-syntheticstaff02', 'A-syntheticstaff02', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'service_contract', 'privacy-notice-v1', '2026-01-01T00:00:00Z', NULL, NULL),
    ('S-syntheticstudent04', 'Synthetic Student Delta', NULL, NULL, '待服务', '未开始', 'T-syntheticcoach02', NULL, NULL, 'staff', 1, 'A-syntheticstaff02', 'A-syntheticstaff02', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'service_contract', 'privacy-notice-v1', '2026-01-01T00:00:00Z', NULL, NULL)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    phone = EXCLUDED.phone,
    email = EXCLUDED.email,
    service_stage = EXCLUDED.service_stage,
    job_search_stage = EXCLUDED.job_search_stage,
    owner_staff_id = EXCLUDED.owner_staff_id,
    next_action = EXCLUDED.next_action,
    next_follow_up_at = EXCLUDED.next_follow_up_at,
    source_kind = EXCLUDED.source_kind,
    processing_basis = EXCLUDED.processing_basis,
    privacy_notice_version = EXCLUDED.privacy_notice_version,
    privacy_notice_delivered_at = EXCLUDED.privacy_notice_delivered_at,
    closed_at = EXCLUDED.closed_at,
    retention_due_at = EXCLUDED.retention_due_at,
    version = EXCLUDED.version,
    created_by = EXCLUDED.created_by,
    updated_by = EXCLUDED.updated_by,
    created_at = EXCLUDED.created_at,
    updated_at = EXCLUDED.updated_at;

-- --- 固定每名学生的当前主负责人；协作者由业务动作追加并保留历史 ---
INSERT INTO student_staff_assignments (
    id, student_id, staff_profile_id, assignment_role, started_at,
    created_by_account_id, created_at, updated_at
) VALUES
    ('SA-a89b8b2b82058e6f94c57d16f6dd28d9', 'S-syntheticstudent01', 'T-syntheticcoach01', 'primary', '2026-01-01T00:00:00Z', 'A-syntheticstaff01', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
    ('SA-974269f47b2a442e84e43297f4560b91', 'S-syntheticstudent02', 'T-syntheticcoach01', 'primary', '2026-01-01T00:00:00Z', 'A-syntheticstaff01', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
    ('SA-46148cd99a008b50a344b9110342303e', 'S-syntheticstudent03', 'T-syntheticcoach02', 'primary', '2026-01-01T00:00:00Z', 'A-syntheticstaff02', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
    ('SA-51d4c84edd4db15c7b754e5dc31709a5', 'S-syntheticstudent04', 'T-syntheticcoach02', 'primary', '2026-01-01T00:00:00Z', 'A-syntheticstaff02', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
ON CONFLICT (id) DO UPDATE SET
    student_id = EXCLUDED.student_id,
    staff_profile_id = EXCLUDED.staff_profile_id,
    assignment_role = EXCLUDED.assignment_role,
    started_at = EXCLUDED.started_at,
    ended_at = NULL,
    ended_by_account_id = NULL,
    created_by_account_id = EXCLUDED.created_by_account_id,
    created_at = EXCLUDED.created_at,
    updated_at = EXCLUDED.updated_at;

-- --- 固定工作台唯一团队计划，正文使用真实换行而不是反斜杠文本 ---
INSERT INTO team_plans (
    id, title, summary, content, version, updated_by, updated_at
) VALUES (
    'TP-primary',
    '本周团队安排',
    '先处理逾期，再推进连续跟进；学生事实仍记录在学生工作区。',
    $team_plan$本周目标：让每名协作中的学生都有明确的下一步。

协作节奏：周一检查待跟进，周三复盘风险，周五整理结果。

团队说明：学生资料、协作成员和跟进记录只在学生工作区维护；人工关注由老板记录最终判断。$team_plan$,
    1,
    'A-syntheticowner01',
    '2026-01-01T00:00:00Z'
)
ON CONFLICT (id) DO UPDATE SET
    title = EXCLUDED.title,
    summary = EXCLUDED.summary,
    content = EXCLUDED.content,
    version = EXCLUDED.version,
    updated_by = EXCLUDED.updated_by,
    updated_at = EXCLUDED.updated_at;
