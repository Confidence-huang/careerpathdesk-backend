/*
CareerPathDesk 团队计划收缩 schema：把重复的文档树与团队任务工作区替换为工作台唯一计划。
升级时只保留旧工作区中的一篇计划正文；学生任务、逾期跟进与人工关注继续来自既有业务表。
*/

-- --- 建立老板可编辑、全团队可读的唯一计划 ---
CREATE TABLE team_plans (
    id text PRIMARY KEY CHECK (id = 'TP-primary'),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 80),
    summary text NOT NULL DEFAULT '' CHECK (char_length(summary) <= 160),
    content text NOT NULL DEFAULT '' CHECK (char_length(content) <= 4000),
    version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_by text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

-- --- 已有合成工作区升级时保留一篇最接近计划的正文 ---
INSERT INTO team_plans (id, title, summary, content, version, updated_by, updated_at)
SELECT
    'TP-primary', title, summary, content, version, updated_by, updated_at
FROM team_documents
ORDER BY
    CASE WHEN id = 'TD-syntheticplan01' THEN 0 ELSE 1 END,
    sort_order,
    id
LIMIT 1
ON CONFLICT (id) DO NOTHING;

-- --- 删除产品不再暴露的第二套任务和文档树 ---
DROP TABLE team_tasks;
DROP TABLE team_documents;
