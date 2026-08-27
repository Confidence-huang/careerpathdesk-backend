/*
CareerPathDesk 隐私与保留 schema：记录学生数据处理依据、告知事实、结案与 180 天到期边界，
并建立不保存身份证件图片的最小隐私请求工作流事实。生产从空库起步；既有回填只允许明确合成学生。
由 Go migration 指令在 schema 7 后以单一 PostgreSQL 事务执行。
*/

-- --- 先以可空列承接已有合成行，不为真实数据伪造默认依据 ---
ALTER TABLE students
    ADD COLUMN processing_basis text,
    ADD COLUMN privacy_notice_version text,
    ADD COLUMN privacy_notice_delivered_at timestamptz,
    ADD COLUMN closed_at timestamptz,
    ADD COLUMN retention_due_at timestamptz;

UPDATE students
SET processing_basis = 'service_contract',
    privacy_notice_version = 'privacy-notice-v1',
    privacy_notice_delivered_at = created_at
WHERE id ~ '^S-synthetic[A-Za-z0-9_-]*$'; -- 只承认仓库和 UAT 明确标记的合成学生。

ALTER TABLE students
    ALTER COLUMN processing_basis SET NOT NULL,
    ALTER COLUMN privacy_notice_version SET NOT NULL,
    ALTER COLUMN privacy_notice_delivered_at SET NOT NULL,
    ADD CONSTRAINT students_processing_basis_check
        CHECK (processing_basis IN ('service_contract', 'student_consent')),
    ADD CONSTRAINT students_privacy_notice_version_check
        CHECK (char_length(btrim(privacy_notice_version)) BETWEEN 1 AND 80),
    ADD CONSTRAINT students_retention_window_check
        CHECK (
            (closed_at IS NULL AND retention_due_at IS NULL)
            OR (
                closed_at IS NOT NULL
                AND retention_due_at IS NOT NULL
                AND retention_due_at = closed_at + interval '180 days'
            )
        );

CREATE INDEX students_retention_due_idx
    ON students(retention_due_at, id)
    WHERE retention_due_at IS NOT NULL; -- dry-run 只扫描已结案且进入保留边界的候选。

-- --- 可审查但最小必要的隐私请求工作流 ---
CREATE TABLE privacy_requests (
    id text PRIMARY KEY CHECK (id ~ '^PR-[A-Za-z0-9_-]{12,80}$'), -- 请求 ID 不承载姓名、联系方式或证件信息。
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE, -- 安全删除学生时不保留可重新识别其人的请求行。
    request_type text NOT NULL CHECK (request_type IN ('access', 'correction', 'deletion', 'consent_withdrawal')), -- 仅接受当前工作流类型。
    status text NOT NULL DEFAULT 'received' CHECK (status IN ('received', 'verifying', 'approved', 'completed', 'refused')), -- 固定状态支持人工核验。
    received_by_account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT, -- 只记录登记员工账号，不复制请求人身份材料。
    resolution_reason_category text CHECK (resolution_reason_category IS NULL OR char_length(btrim(resolution_reason_category)) BETWEEN 1 AND 80), -- 拒绝时使用非敏感原因分类。
    resolution_note text CHECK (resolution_note IS NULL OR char_length(btrim(resolution_note)) BETWEEN 1 AND 500), -- 仅保存必要说明，不放证件、图片或学生档案副本。
    completed_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (
        (status IN ('completed', 'refused') AND completed_at IS NOT NULL)
        OR (status NOT IN ('completed', 'refused') AND completed_at IS NULL)
    ),
    CHECK (
        (status = 'refused' AND resolution_reason_category IS NOT NULL AND resolution_note IS NOT NULL)
        OR (status <> 'refused' AND resolution_reason_category IS NULL AND resolution_note IS NULL)
    )
);

CREATE INDEX privacy_requests_status_created_idx
    ON privacy_requests(status, created_at, id); -- 支持 owner 按工作流状态处理，不索引说明正文。
