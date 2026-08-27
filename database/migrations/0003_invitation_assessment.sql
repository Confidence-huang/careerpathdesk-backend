/*
CareerPathDesk 学生邀请、固定问卷与权威测评 schema。
本文件把公开十题与私有评分定义分列保存，并用数据库约束封闭一次兑换能力和十题结果形状；
对象范围、秘密生成、答案白名单、评分和跨表原子命令仍由后续业务命令负责。
由 Go migration 指令在前两版之后以单一 PostgreSQL 事务执行。
*/

-- --- 保存版本化问卷的公开投影与服务端私有评分事实 ---
CREATE TABLE assessment_questionnaires (
    version text PRIMARY KEY CHECK (version ~ '^assessment-[0-9]+$'), -- 版本是邀请、表单和测评共同使用的稳定身份。
    public_questions jsonb NOT NULL CHECK (jsonb_typeof(public_questions) = 'array' AND jsonb_array_length(public_questions) = 10), -- 浏览器只能读取十题公开文字与选项。
    scoring_definition jsonb NOT NULL CHECK (jsonb_typeof(scoring_definition) = 'object'), -- 权重、结果材料和人工确认边界永不进入学生投影。
    is_active boolean NOT NULL DEFAULT false, -- 只有当前活动版本可用于新邀请和提交。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp() -- migration 记录该不可变版本进入 schema 的时间。
);

CREATE UNIQUE INDEX assessment_questionnaires_one_active_idx
    ON assessment_questionnaires(is_active) WHERE is_active; -- 任一时刻只有一个版本可成为新提交权威来源。

-- --- 注册 assessment-1 的精确十题公开合同与私有评分材料 ---
INSERT INTO assessment_questionnaires (version, public_questions, scoring_definition, is_active)
VALUES (
    'assessment-1',
    $public_questions$
    [
      {"id":"p1","prompt":"收到简历修改建议时，你更容易接受哪种方式？","options":[
        {"id":"p1-neutral-option-a","label":"直接告诉我哪里错、怎么改、什么时候完成。"},
        {"id":"p1-neutral-option-b","label":"先肯定我的亮点，再告诉我可以优化的地方。"},
        {"id":"p1-neutral-option-c","label":"给我具体标准、参考案例和修改依据。"},
        {"id":"p1-neutral-option-d","label":"私下温和沟通，不要让我太有压力。"}
      ]},
      {"id":"p2","prompt":"如果一周内要推进简历和投递，你更需要什么？","options":[
        {"id":"p2-neutral-option-a","label":"明确目标、截止时间和结果检查。"},
        {"id":"p2-neutral-option-b","label":"有人鼓励我、认可我，让我保持状态。"},
        {"id":"p2-neutral-option-c","label":"给我岗位清单、筛选标准和投递依据。"},
        {"id":"p2-neutral-option-d","label":"给我具体小步骤，节奏不要太急。"}
      ]},
      {"id":"p3","prompt":"面试失败或投递没反馈时，你更容易出现哪种反应？","options":[
        {"id":"p3-neutral-option-a","label":"立刻复盘问题，准备下一轮调整。"},
        {"id":"p3-neutral-option-b","label":"会有点受打击，需要先被鼓励一下。"},
        {"id":"p3-neutral-option-c","label":"会觉得是岗位、HR、学校或环境的问题。"},
        {"id":"p3-neutral-option-d","label":"不太想说，自己先消化。"}
      ]},
      {"id":"p4","prompt":"当职业选择出现不确定时，你更倾向于？","options":[
        {"id":"p4-neutral-option-a","label":"先定一个方向，边做边调整。"},
        {"id":"p4-neutral-option-b","label":"希望有人和我多聊聊，帮我增强信心。"},
        {"id":"p4-neutral-option-c","label":"希望看到数据、案例、利弊分析后再决定。"},
        {"id":"p4-neutral-option-d","label":"希望选择稳妥一点，不要变化太大。"}
      ]},
      {"id":"p5","prompt":"面对老师或顾问的跟进，你更喜欢？","options":[
        {"id":"p5-neutral-option-a","label":"只同步关键结果，不要管太细。"},
        {"id":"p5-neutral-option-b","label":"多一些互动、反馈和认可。"},
        {"id":"p5-neutral-option-c","label":"每一步都有清晰标准和资料依据。"},
        {"id":"p5-neutral-option-d","label":"节奏稳定，沟通温和，不要突然催促。"}
      ]},
      {"id":"p6","prompt":"当别人指出你的问题时，你通常会？","options":[
        {"id":"p6-neutral-option-a","label":"只要说得对，我可以马上改。"},
        {"id":"p6-neutral-option-b","label":"希望对方表达得委婉一点。"},
        {"id":"p6-neutral-option-c","label":"会先追问依据和判断标准。"},
        {"id":"p6-neutral-option-d","label":"容易解释为什么会这样。"}
      ]},
      {"id":"p7","prompt":"小组任务或项目推进时，你更像哪种状态？","options":[
        {"id":"p7-neutral-option-a","label":"我想主导方向，快速推进结果。"},
        {"id":"p7-neutral-option-b","label":"我适合对外表达、带动气氛。"},
        {"id":"p7-neutral-option-c","label":"我适合做资料整理、风险分析和细节检查。"},
        {"id":"p7-neutral-option-d","label":"我适合协调关系、稳定推进。"}
      ]},
      {"id":"p8","prompt":"当你对安排不满意时，你更可能？","options":[
        {"id":"p8-neutral-option-a","label":"直接提出问题并要求调整。"},
        {"id":"p8-neutral-option-b","label":"先吐槽几句，需要别人帮我聚焦解决方案。"},
        {"id":"p8-neutral-option-c","label":"不太表达，但心里会有想法。"},
        {"id":"p8-neutral-option-d","label":"尽量配合，不想制造冲突。"}
      ]},
      {"id":"p9","prompt":"你希望别人怎样帮你推进求职？","options":[
        {"id":"p9-neutral-option-a","label":"给我目标和底线，过程让我自己定。"},
        {"id":"p9-neutral-option-b","label":"多给我正反馈，让我更有动力表现。"},
        {"id":"p9-neutral-option-c","label":"给我详细规则、数据、模板和风险提醒。"},
        {"id":"p9-neutral-option-d","label":"稳定陪伴，逐步推进，不要让我突然承压。"}
      ]},
      {"id":"p10","prompt":"遇到连续不顺时，你最容易？","options":[
        {"id":"p10-neutral-option-a","label":"重新制定计划，继续推进。"},
        {"id":"p10-neutral-option-b","label":"怀疑自己，需要别人帮我恢复信心。"},
        {"id":"p10-neutral-option-c","label":"觉得外部因素影响太大。"},
        {"id":"p10-neutral-option-d","label":"变得消极，经常看到问题。"}
      ]}
    ]
    $public_questions$::jsonb,
    $scoring_definition$
    {
      "core_order":["direct_goal","expressive_feedback","evidence_planning","steady_support"],
      "signal_order":["context_constraints","feedback_support","problem_awareness","reflection_space"],
      "signal_threshold":3,
      "hybrid_rules":[
        {"primary_type":"direct_expressive","left":"direct_goal","right":"expressive_feedback","minimum_score":4,"maximum_gap":1,"secondary_type":"expressive_feedback"},
        {"primary_type":"evidence_steady","left":"evidence_planning","right":"steady_support","minimum_score":4,"maximum_gap":1,"secondary_type":"steady_support"}
      ],
      "option_weights":{
        "p1-neutral-option-a":{"direct_goal":2},
        "p1-neutral-option-b":{"expressive_feedback":1,"feedback_support":1},
        "p1-neutral-option-c":{"evidence_planning":2},
        "p1-neutral-option-d":{"steady_support":1,"feedback_support":1},
        "p2-neutral-option-a":{"direct_goal":2},
        "p2-neutral-option-b":{"expressive_feedback":2},
        "p2-neutral-option-c":{"evidence_planning":2},
        "p2-neutral-option-d":{"steady_support":2},
        "p3-neutral-option-a":{"direct_goal":1,"evidence_planning":1},
        "p3-neutral-option-b":{"feedback_support":2,"expressive_feedback":1},
        "p3-neutral-option-c":{"context_constraints":2},
        "p3-neutral-option-d":{"reflection_space":2},
        "p4-neutral-option-a":{"direct_goal":2},
        "p4-neutral-option-b":{"expressive_feedback":1,"feedback_support":1},
        "p4-neutral-option-c":{"evidence_planning":2},
        "p4-neutral-option-d":{"steady_support":2},
        "p5-neutral-option-a":{"direct_goal":2},
        "p5-neutral-option-b":{"expressive_feedback":2},
        "p5-neutral-option-c":{"evidence_planning":2},
        "p5-neutral-option-d":{"steady_support":2},
        "p6-neutral-option-a":{"direct_goal":2},
        "p6-neutral-option-b":{"feedback_support":2,"steady_support":1},
        "p6-neutral-option-c":{"evidence_planning":2},
        "p6-neutral-option-d":{"context_constraints":2},
        "p7-neutral-option-a":{"direct_goal":2},
        "p7-neutral-option-b":{"expressive_feedback":2},
        "p7-neutral-option-c":{"evidence_planning":2},
        "p7-neutral-option-d":{"steady_support":2},
        "p8-neutral-option-a":{"direct_goal":2},
        "p8-neutral-option-b":{"problem_awareness":2},
        "p8-neutral-option-c":{"reflection_space":2},
        "p8-neutral-option-d":{"steady_support":2},
        "p9-neutral-option-a":{"direct_goal":2},
        "p9-neutral-option-b":{"expressive_feedback":2},
        "p9-neutral-option-c":{"evidence_planning":2},
        "p9-neutral-option-d":{"steady_support":2},
        "p10-neutral-option-a":{"direct_goal":2},
        "p10-neutral-option-b":{"feedback_support":2},
        "p10-neutral-option-c":{"context_constraints":2},
        "p10-neutral-option-d":{"problem_awareness":2}
      },
      "result_material":{
        "direct_goal":{"summary":"更容易响应明确目标、结果标准和时间节点。","advice":["先说明目标和优先级，再共同确认可执行的下一步。","用具体节点复核进展，并保留学生说明实际限制的空间。"]},
        "expressive_feedback":{"summary":"更容易在互动、事实认可和表达空间中保持投入。","advice":["先确认已经完成的事实，再把交流收束到具体行动。","提供可回应的反馈节点，避免只用笼统鼓励代替计划。"]},
        "evidence_planning":{"summary":"更容易依据标准、案例和信息完整度作出决定。","advice":["提供判断标准、参考案例和选择依据。","把信息整理成有限选项，并明确仍需人工核实的部分。"]},
        "steady_support":{"summary":"更容易在稳定节奏、低压力和清晰小步骤中推进。","advice":["把任务拆成可完成的小步骤，并提前说明节奏变化。","用选择题式确认减少突然压力，同时保留学生主动决定。"]},
        "direct_expressive":{"summary":"既重视明确目标，也会从及时互动和反馈中获得推进动力。","advice":["同时给出结果目标和可表达的阶段反馈点。","把展示空间连接到具体交付，避免目标与互动彼此脱节。"]},
        "evidence_steady":{"summary":"既重视充分依据，也更适合按稳定节奏逐步确认。","advice":["先提供必要依据，再按小步骤逐项确认。","避免一次堆入过多信息，并保留比较和复核时间。"]}
      },
      "support_material":{
        "context_constraints":"先确认客观限制，再区分可控行动和需要协调的条件。",
        "feedback_support":"反馈时先确认事实基础，再给出具体且可修改的下一步。",
        "problem_awareness":"先接住已识别的问题，再共同收束到可改变的行动。",
        "reflection_space":"提前给出议题和准备时间，再用明确问题邀请表达。"
      },
      "disclaimer":"结果仅用于帮助顾问准备后续沟通，并须结合实际情况人工确认；不代表固定人格、心理诊断、能力高低或职业适配结论。"
    }
    $scoring_definition$::jsonb,
    true
);

-- --- 扩充邀请允许学生自填但后台仍按对象范围保护的资料列 ---
ALTER TABLE students
    ADD COLUMN wechat text CHECK (wechat IS NULL OR char_length(wechat) <= 100), -- 联系方式只在获准业务页使用。
    ADD COLUMN school text CHECK (school IS NULL OR char_length(school) <= 200), -- 学校是短资料字段，不进入审计。
    ADD COLUMN major text CHECK (major IS NULL OR char_length(major) <= 200), -- 专业由学生自填但不能改变对象范围。
    ADD COLUMN grade text CHECK (grade IS NULL OR char_length(grade) <= 100), -- 年级允许自由短文本而不猜测枚举。
    ADD COLUMN target_city text CHECK (target_city IS NULL OR char_length(target_city) <= 200), -- 目标城市属于求职资料正文。
    ADD COLUMN target_position text CHECK (target_position IS NULL OR char_length(target_position) <= 200), -- 目标岗位不能覆盖求职阶段。
    ADD COLUMN expected_salary text CHECK (expected_salary IS NULL OR char_length(expected_salary) <= 200), -- 薪资意向只保存获准原文。
    ADD COLUMN job_intention text CHECK (job_intention IS NULL OR char_length(job_intention) <= 4000), -- 求职意向允许多行但保持明确上限。
    ADD COLUMN project_experience text CHECK (project_experience IS NULL OR char_length(project_experience) <= 4000), -- 项目经历是受保护正文。
    ADD COLUMN internship_experience text CHECK (internship_experience IS NULL OR char_length(internship_experience) <= 4000), -- 实习经历是受保护正文。
    ADD COLUMN skills text CHECK (skills IS NULL OR char_length(skills) <= 4000), -- 技能由学生自填，评分不读取。
    ADD COLUMN certificates text CHECK (certificates IS NULL OR char_length(certificates) <= 4000); -- 证书资料不进入普通日志。

-- --- 保存一次链接到单学生受限会话的完整生命周期 ---
CREATE TABLE student_invitations (
    id text PRIMARY KEY CHECK (id ~ '^IV-[A-Za-z0-9_-]{12,80}$'), -- 邀请身份可审计但不能恢复原始链接秘密。
    student_id text NOT NULL REFERENCES students(id) ON DELETE CASCADE, -- 能力始终只绑定一个既有学生。
    issued_by_account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT, -- 保留实际签发账号且不允许级联抹除。
    assessment_version text NOT NULL REFERENCES assessment_questionnaires(version) ON DELETE RESTRICT, -- 新邀请只能引用已注册问卷。
    student_version bigint NOT NULL CHECK (student_version > 0), -- 提交前与学生当前版本比较以拒绝静默覆盖。
    state text NOT NULL CHECK (state IN ('pending', 'exchanged', 'completed', 'revoked', 'replaced')), -- 生命周期没有隐式恢复分支。
    invite_digest bytea UNIQUE CHECK (invite_digest IS NULL OR octet_length(invite_digest) = 32), -- 原始链接只保存 SHA-256 且兑换后清空。
    restricted_session_id text UNIQUE CHECK (restricted_session_id IS NULL OR restricted_session_id ~ '^IS-[A-Za-z0-9_-]{12,80}$'), -- 更窄会话拥有独立不透明身份。
    restricted_session_digest bytea UNIQUE CHECK (restricted_session_digest IS NULL OR octet_length(restricted_session_digest) = 32), -- Cookie 原始秘密从不持久化。
    expires_at timestamptz NOT NULL, -- 链接到达该 UTC 时刻立即失效。
    restricted_session_expires_at timestamptz, -- 受限会话不能活得比原邀请更久。
    exchanged_at timestamptz, -- 首次成功兑换时间只能出现在兑换后状态。
    completed_at timestamptz, -- 档案和测评原子提交成功后进入完成终态。
    revoked_at timestamptz, -- 人工或权限变化撤销后销毁全部摘要。
    replaced_at timestamptz, -- 补发保留旧身份但销毁旧能力。
    revoke_reason text CHECK (revoke_reason IS NULL OR revoke_reason IN ('manual', 'owner_changed', 'issuer_disabled', 'student_removed', 'expired')), -- 固定原因不复制业务正文。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 生命周期更新使用显式乐观版本。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成邀请建立事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 每次合法状态变化同步推进。
    CHECK (restricted_session_expires_at IS NULL OR restricted_session_expires_at <= expires_at), -- 更窄能力不能扩大原链接期限。
    CHECK (
        (
            state = 'pending'
            AND invite_digest IS NOT NULL
            AND restricted_session_id IS NULL
            AND restricted_session_digest IS NULL
            AND restricted_session_expires_at IS NULL
            AND exchanged_at IS NULL
            AND completed_at IS NULL
            AND revoked_at IS NULL
            AND replaced_at IS NULL
            AND revoke_reason IS NULL
        )
        OR (
            state = 'exchanged'
            AND invite_digest IS NULL
            AND restricted_session_id IS NOT NULL
            AND restricted_session_digest IS NOT NULL
            AND restricted_session_expires_at IS NOT NULL
            AND exchanged_at IS NOT NULL
            AND completed_at IS NULL
            AND revoked_at IS NULL
            AND replaced_at IS NULL
            AND revoke_reason IS NULL
        )
        OR (
            state = 'completed'
            AND invite_digest IS NULL
            AND restricted_session_id IS NOT NULL
            AND restricted_session_digest IS NULL
            AND restricted_session_expires_at IS NOT NULL
            AND exchanged_at IS NOT NULL
            AND completed_at IS NOT NULL
            AND revoked_at IS NULL
            AND replaced_at IS NULL
            AND revoke_reason IS NULL
        )
        OR (
            state = 'revoked'
            AND invite_digest IS NULL
            AND restricted_session_digest IS NULL
            AND completed_at IS NULL
            AND revoked_at IS NOT NULL
            AND replaced_at IS NULL
            AND revoke_reason IS NOT NULL
        )
        OR (
            state = 'replaced'
            AND invite_digest IS NULL
            AND restricted_session_id IS NULL
            AND restricted_session_digest IS NULL
            AND restricted_session_expires_at IS NULL
            AND exchanged_at IS NULL
            AND completed_at IS NULL
            AND revoked_at IS NULL
            AND replaced_at IS NOT NULL
            AND revoke_reason IS NULL
        )
    ) -- 摘要、时间和终态必须形成一个不可矛盾的能力事实包。
);

CREATE UNIQUE INDEX student_invitations_one_live_student_idx
    ON student_invitations(student_id) WHERE state IN ('pending', 'exchanged'); -- 每名学生最多持有一个尚未终结的能力。

CREATE INDEX student_invitations_student_timeline_idx
    ON student_invitations(student_id, created_at DESC, id DESC); -- 支持获准后台查看历史且不返回任何摘要。

CREATE INDEX student_invitations_expiry_idx
    ON student_invitations(state, expires_at, id) WHERE state IN ('pending', 'exchanged'); -- 支持精确过期判定和未来有界维护。

-- --- 保存十题答案与只由服务器派生的内部结果 ---
CREATE TABLE assessments (
    id text PRIMARY KEY CHECK (id ~ '^AS-[A-Za-z0-9_-]{12,80}$'), -- 测评身份与学生、邀请身份分离。
    student_id text NOT NULL UNIQUE REFERENCES students(id) ON DELETE CASCADE, -- 每名学生最多保留一个当前权威结果。
    questionnaire_version text NOT NULL REFERENCES assessment_questionnaires(version) ON DELETE RESTRICT, -- 答案只能引用可重放的静态定义。
    answers jsonb NOT NULL CHECK (jsonb_typeof(answers) = 'object' AND jsonb_array_length(jsonb_path_query_array(answers, '$.keyvalue()')) = 10), -- PostgreSQL 18 以标准 JSON path 固定十键形状，应用再逐题核对选项。
    server_score jsonb NOT NULL CHECK (jsonb_typeof(server_score) = 'object'), -- 主次结果和分数完全由服务器产生。
    internal_recommendation jsonb NOT NULL CHECK (jsonb_typeof(internal_recommendation) = 'object'), -- 人工确认材料永不进入学生回执。
    source_invitation_id text NOT NULL UNIQUE REFERENCES student_invitations(id) ON DELETE RESTRICT, -- 结果保留产生它的受限能力来源。
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0), -- 后续受控重测或人工修正拒绝静默覆盖。
    submitted_at timestamptz NOT NULL, -- 保存完成命令使用的同一可信 UTC 时间。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 首次结果建立时间以后不改写。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp() -- 当前结果最近一次合法变化时间。
);

CREATE INDEX assessments_questionnaire_time_idx
    ON assessments(questionnaire_version, submitted_at DESC, id DESC); -- 支持未来获准运营统计和一致导出。
