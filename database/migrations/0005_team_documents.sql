/*
CareerPathDesk 团队文档 schema：保存共享文档层级和与文档关联的团队任务。
正文只存在业务表中；审计仍只记录对象身份、状态和版本，不复制成员书写内容。
*/

-- --- 保存可分层组织的团队文档 ---
CREATE TABLE team_documents (
    id text PRIMARY KEY,
    parent_id text REFERENCES team_documents(id) ON DELETE RESTRICT,
    icon text NOT NULL DEFAULT '📄' CHECK (char_length(icon) BETWEEN 1 AND 8),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
    summary text NOT NULL DEFAULT '' CHECK (char_length(summary) <= 240),
    content text NOT NULL DEFAULT '' CHECK (char_length(content) <= 20000),
    sort_order integer NOT NULL DEFAULT 0 CHECK (sort_order BETWEEN 0 AND 100000),
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    updated_by text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (parent_id IS NULL OR parent_id <> id)
);

CREATE INDEX team_documents_parent_order_idx
    ON team_documents(parent_id, sort_order, title, id);

-- --- 保存团队计划中的可执行任务 ---
CREATE TABLE team_tasks (
    id text PRIMARY KEY,
    document_id text NOT NULL REFERENCES team_documents(id) ON DELETE RESTRICT,
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 160),
    details text NOT NULL DEFAULT '' CHECK (char_length(details) <= 2000),
    status text NOT NULL DEFAULT 'todo' CHECK (status IN ('todo', 'in_progress', 'done')),
    assignee_staff_id text REFERENCES staff_profiles(id) ON DELETE RESTRICT,
    due_at timestamptz,
    completed_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    updated_by text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK ((status = 'done' AND completed_at IS NOT NULL) OR (status <> 'done' AND completed_at IS NULL))
);

CREATE INDEX team_tasks_document_status_due_idx
    ON team_tasks(document_id, status, due_at NULLS LAST, id);

CREATE INDEX team_tasks_assignee_status_due_idx
    ON team_tasks(assignee_staff_id, status, due_at NULLS LAST, id);
