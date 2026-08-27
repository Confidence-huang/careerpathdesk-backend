/*
CareerPathDesk 账号 MFA schema：保存 AES-256-GCM 密文、一次挑战摘要和防重放事实。
原始 TOTP secret、挑战 secret 与恢复码只存在于短期应用内存或一次响应，绝不写入本 schema。
由 Go migration 指令在 schema 6 后以单一 PostgreSQL 事务执行。
*/

-- --- 数组约束把每一项固定为 SHA-256 digest，而不是只验证数组容器类型 ---
CREATE FUNCTION careerpathdesk_all_sha256_digests(digests bytea[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT COALESCE(bool_and(digest IS NOT NULL AND octet_length(digest) = 32), true)
    FROM unnest(digests) AS digest
$$;

-- --- 每个账号最多保存一组已加密 MFA 因素 ---
CREATE TABLE account_mfa (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE RESTRICT, -- 账号生命周期不能级联抹除安全事实。
    encrypted_secret bytea NOT NULL CHECK (octet_length(encrypted_secret) >= 16), -- 只保存带 GCM tag 的密文，不保存 TOTP 原文。
    secret_nonce bytea NOT NULL CHECK (octet_length(secret_nonce) = 12), -- AES-GCM 使用固定 96 位 nonce。
    key_version integer NOT NULL CHECK (key_version > 0), -- 支持明确密钥轮换，不从密文猜测来源。
    confirmed_at timestamptz, -- 空值代表注册尚未由一个有效 TOTP 确认。
    last_accepted_step bigint CHECK (last_accepted_step IS NULL OR last_accepted_step >= 0), -- 拒绝同一 30 秒时间步重放。
    recovery_code_digests bytea[] NOT NULL DEFAULT '{}'::bytea[]
        CHECK (careerpathdesk_all_sha256_digests(recovery_code_digests)), -- 元素仅为 SHA-256 digest；消费时删除命中项。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 数据库生成稳定创建事实。
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 密钥、确认或恢复码变化时由命令显式更新。
    CHECK (confirmed_at IS NOT NULL OR last_accepted_step IS NULL) -- 未完成注册不能宣称已接受验证码。
);

-- --- 密码验证后签发最多五分钟、最多五次尝试的一次 MFA challenge ---
CREATE TABLE mfa_challenges (
    id text PRIMARY KEY CHECK (id ~ '^MC-[A-Za-z0-9_-]{12,80}$'), -- challenge 使用不透明领域身份。
    account_id text NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT, -- 动态账号状态仍由命令层在消费时复核。
    purpose text NOT NULL CHECK (purpose IN ('login', 'enroll', 'recovery')), -- 不允许挑战被复用于其他授权动作。
    secret_digest bytea NOT NULL UNIQUE CHECK (octet_length(secret_digest) = 32), -- 原始 challenge 只进入受限 Cookie。
    expires_at timestamptz NOT NULL, -- 到达边界立即失效。
    remaining_attempts integer NOT NULL DEFAULT 5 CHECK (remaining_attempts BETWEEN 0 AND 5), -- 初始预算为五，失败只可递减。
    consumed_at timestamptz, -- 非空后进入不可逆终态。
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(), -- 与过期时间共同限制最长窗口。
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
    CHECK (consumed_at IS NULL OR consumed_at <= expires_at) -- 成功消费只能发生在有效窗口内。
);

CREATE INDEX mfa_challenges_active_account_purpose_expiry_idx
    ON mfa_challenges(account_id, purpose, expires_at)
    WHERE consumed_at IS NULL; -- 只扫描当前账号、用途仍未消费的短期挑战。
