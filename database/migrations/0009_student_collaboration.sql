/*
CareerPathDesk 学生协作迁移：在保留旧阶段/任务历史的前提下，增加多人协作、完整资料和跟进正文。
本迁移只做向前兼容的 additive 变更；应用切换后旧阶段和教练任务停止产生新事实。
*/

ALTER TABLE students
    ADD COLUMN current_location text
    CHECK (current_location IS NULL OR char_length(current_location) <= 200);

CREATE TABLE student_staff_assignments (
    id text PRIMARY KEY CHECK (id ~ '^SA-[A-Za-z0-9_-]{12,80}$'),
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    staff_profile_id text NOT NULL REFERENCES staff_profiles(id) ON DELETE RESTRICT,
    assignment_role text NOT NULL CHECK (assignment_role IN ('primary', 'collaborator')),
    responsibility_note text CHECK (responsibility_note IS NULL OR char_length(responsibility_note) <= 500),
    started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    ended_at timestamptz,
    created_by_account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    ended_by_account_id text REFERENCES accounts(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (ended_at IS NULL OR ended_at >= started_at),
    CHECK ((ended_at IS NULL AND ended_by_account_id IS NULL) OR (ended_at IS NOT NULL AND ended_by_account_id IS NOT NULL))
);

CREATE UNIQUE INDEX student_staff_assignments_one_active_primary_idx
    ON student_staff_assignments(student_id)
    WHERE assignment_role = 'primary' AND ended_at IS NULL;

CREATE UNIQUE INDEX student_staff_assignments_one_active_member_idx
    ON student_staff_assignments(student_id, staff_profile_id)
    WHERE ended_at IS NULL;

CREATE INDEX student_staff_assignments_staff_scope_idx
    ON student_staff_assignments(staff_profile_id, student_id)
    WHERE ended_at IS NULL;

INSERT INTO student_staff_assignments (
    id, student_id, staff_profile_id, assignment_role, started_at,
    created_by_account_id, created_at, updated_at
)
SELECT
    'SA-' || substr(md5(student.id || ':' || student.owner_staff_id), 1, 32),
    student.id,
    student.owner_staff_id,
    'primary',
    student.created_at,
    COALESCE(
        (SELECT account.id FROM accounts AS account WHERE account.id = student.created_by LIMIT 1),
        (SELECT account.id FROM accounts AS account WHERE account.role = 'owner' ORDER BY account.created_at, account.id LIMIT 1)
    ),
    student.created_at,
    student.updated_at
FROM students AS student
WHERE student.owner_staff_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM accounts WHERE role = 'owner')
ON CONFLICT DO NOTHING;

ALTER TABLE follow_up_records
    ADD COLUMN content text
    CHECK (content IS NULL OR char_length(btrim(content)) BETWEEN 1 AND 4000),
    ADD COLUMN next_staff_id text REFERENCES staff_profiles(id) ON DELETE RESTRICT;

CREATE INDEX follow_up_records_next_staff_time_idx
    ON follow_up_records(next_staff_id, next_follow_up_at, student_id)
    WHERE next_staff_id IS NOT NULL AND next_follow_up_at IS NOT NULL;
