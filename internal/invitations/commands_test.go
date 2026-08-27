/*
邀请命令合同：通过真实 PostgreSQL 冻结签发、补发、撤销、过期、一次兑换和单学生能力范围。
所有账号、学生、时间与秘密均为 synthetic；测试只调用未来 Commands 公开接口并读取独立随机 schema。
*/
package invitations

import (
	"bytes"         // 比较数据库摘要与 synthetic 秘密的 SHA-256。
	"context"       // 驱动公开邀请命令和测试事实查询。
	"crypto/sha256" // 证明原始邀请与能力秘密从不持久化。
	"errors"        // 比较不泄露对象存在性的稳定领域失败。
	"fmt"           // 生成可辨认但不包含业务数据的 synthetic 身份和秘密。
	"reflect"       // 证明受限能力投影没有后台账号权限字段。
	"testing"       // 组织互相隔离的邀请生命周期行为。
	"time"          // 注入可推进的 UTC 时钟验证精确过期边界。

	"github.com/jackc/pgx/v5" // 将随机测试 schema 连接装配到命令。

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"        // 使用认证模块已验证的账号投影。
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport" // 建立可精确清理的 synthetic PostgreSQL schema。
)

var syntheticInvitationStart = time.Date(2026, time.August, 6, 8, 0, 0, 0, time.UTC) // 所有过期断言共享可信起点。

// --- 老板可邀请任意学生，员工范围外与未知学生共享不存在反馈 ---
func TestIssueInvitationEnforcesActorAndStudentScope(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "invitations") // 范围断言不复用其他邀请事实。
	clock := &syntheticInvitationClock{current: syntheticInvitationStart}
	commands := newInvitationTestCommands(t, connection, clock)

	staffResult, staffError := commands.Issue(
		context.Background(), syntheticInvitationStaffOne(), "R-syntheticinviteissue01", "synthetic-key-invite-issue-01",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	)
	if staffError != nil { // 员工本人负责学生是合法范围。
		t.Fatalf("owned invitation issue failed: %v", staffError)
	}
	if staffResult.StudentID != "S-syntheticstudent01" || staffResult.AssessmentVersion != "assessment-1" || staffResult.Secret == "" || !staffResult.ExpiresAt.Equal(syntheticInvitationStart.Add(24*time.Hour)) {
		t.Fatal("issued invitation omitted its one-time response facts")
	}
	if _, foreignError := commands.Issue(
		context.Background(), syntheticInvitationStaffOne(), "R-syntheticinvitescope01", "synthetic-key-invite-scope-01",
		"S-syntheticstudent03", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	); !errors.Is(foreignError, ErrNotFound) {
		t.Fatalf("foreign student invitation exposed existence: %v", foreignError)
	}
	if _, unknownError := commands.Issue(
		context.Background(), syntheticInvitationStaffOne(), "R-syntheticinvitescope02", "synthetic-key-invite-scope-02",
		"S-syntheticunknown01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	); !errors.Is(unknownError, ErrNotFound) {
		t.Fatalf("unknown student invitation used a different failure: %v", unknownError)
	}
	ownerResult, ownerError := commands.Issue(
		context.Background(), syntheticInvitationOwner(), "R-syntheticinviteowner01", "synthetic-key-invite-owner-01",
		"S-syntheticstudent03", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 48},
	)
	if ownerError != nil || ownerResult.StudentID != "S-syntheticstudent03" { // 老板范围横跨全部现有学生。
		t.Fatalf("owner invitation issue failed: student=%s error=%v", ownerResult.StudentID, ownerError)
	}

	if _, disableError := connection.Exec(context.Background(), `UPDATE accounts SET state = 'disabled' WHERE id = 'A-syntheticstaff01'`); disableError != nil {
		t.Fatal("synthetic staff disable setup failed")
	}
	if _, disabledError := commands.Issue(
		context.Background(), syntheticInvitationStaffOne(), "R-syntheticinvitedisabled", "synthetic-key-invite-disabled",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	); !errors.Is(disabledError, ErrForbidden) {
		t.Fatalf("disabled staff invitation was accepted: %v", disabledError)
	}
}

// --- 邀请绝对期限只接受计划冻结的 1..72 小时 ---
func TestIssueInvitationRejectsHoursBeyondFrozenAbsoluteLifetime(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "invitations") // 通过真实公开命令证明边界先于任何持久化动作。
	clock := &syntheticInvitationClock{current: syntheticInvitationStart}
	commands := newInvitationTestCommands(t, connection, clock)
	actor := syntheticInvitationStaffOne()

	accepted, acceptedError := commands.Issue(
		context.Background(), actor, "R-syntheticinvitehours72", "synthetic-key-invite-hours-72",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 72},
	)
	if acceptedError != nil || !accepted.ExpiresAt.Equal(syntheticInvitationStart.Add(72*time.Hour)) {
		t.Fatalf("72-hour invitation boundary was rejected: expires_at=%s error=%v", accepted.ExpiresAt, acceptedError)
	}

	rejectedHours := []int{73, 168} // 一小时越界和旧七天选项都必须共享同一公开失败。
	for _, hours := range rejectedHours {
		t.Run(fmt.Sprintf("%d hours", hours), func(t *testing.T) {
			_, issueError := commands.Issue(
				context.Background(), actor, fmt.Sprintf("R-syntheticinvitehours%d", hours), fmt.Sprintf("synthetic-key-invite-hours-%d", hours),
				"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: hours},
			)
			if !errors.Is(issueError, ErrInvalidInput) {
				t.Fatalf("%d-hour invitation exceeded the frozen maximum without rejection: %v", hours, issueError)
			}
		})
	}
}

// --- 补发原子替换旧邀请，数据库只保存新秘密摘要 ---
func TestReissueInvitationReplacesPriorDigestAndKeepsMinimalEvidence(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "invitations") // 同一学生的两次签发形成明确替换顺序。
	clock := &syntheticInvitationClock{current: syntheticInvitationStart}
	commands := newInvitationTestCommands(t, connection, clock)
	actor := syntheticInvitationStaffOne()

	first, firstError := commands.Issue(
		context.Background(), actor, "R-syntheticinvitereissue1", "synthetic-key-invite-reissue-01",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	)
	if firstError != nil {
		t.Fatalf("first synthetic invitation failed: %v", firstError)
	}
	clock.current = clock.current.Add(time.Minute)
	second, secondError := commands.Issue(
		context.Background(), actor, "R-syntheticinvitereissue2", "synthetic-key-invite-reissue-02",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 48},
	)
	if secondError != nil {
		t.Fatalf("replacement synthetic invitation failed: %v", secondError)
	}
	if first.ID == second.ID || first.Secret == second.Secret || second.Secret == "" {
		t.Fatal("replacement invitation reused one-time identity material")
	}

	var firstState string  // 旧邀请保留可审计身份但不再持有可兑换摘要。
	var firstDigest []byte // NULL 扫描为 nil，原始秘密不能继续有效。
	var firstReplacedAt *time.Time
	if queryError := connection.QueryRow(context.Background(), `SELECT state, invite_digest, replaced_at FROM student_invitations WHERE id = $1`, first.ID).Scan(&firstState, &firstDigest, &firstReplacedAt); queryError != nil {
		t.Fatal("synthetic replaced invitation query failed")
	}
	var secondState string  // 最新邀请是该学生唯一 pending 能力。
	var secondDigest []byte // bytea 必须恰好等于原始秘密的 SHA-256。
	if queryError := connection.QueryRow(context.Background(), `SELECT state, invite_digest FROM student_invitations WHERE id = $1`, second.ID).Scan(&secondState, &secondDigest); queryError != nil {
		t.Fatal("synthetic active invitation query failed")
	}
	secondExpectedDigest := sha256.Sum256([]byte(second.Secret))
	if firstState != "replaced" || firstDigest != nil || firstReplacedAt == nil || secondState != "pending" || !bytes.Equal(secondDigest, secondExpectedDigest[:]) {
		t.Fatalf("invitation replacement facts diverged: first_state=%s first_digest=%t replaced_at=%t second_state=%s second_digest_match=%t", firstState, firstDigest != nil, firstReplacedAt != nil, secondState, bytes.Equal(secondDigest, secondExpectedDigest[:]))
	}

	var activeCount int       // 一个学生在补发后只能保留一个可兑换邀请。
	var eventCount int        // 每次签发都形成一个最小学生事件。
	var minimalEventCount int // 事件禁止复制秘密或邀请 URL。
	var auditCount int        // 每次签发都形成一个逐人审计。
	var minimalAuditCount int // 审计只保存引用和非敏感版本事实。
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_invitations WHERE student_id = 'S-syntheticstudent01' AND state = 'pending'`).Scan(&activeCount); queryError != nil {
		t.Fatal("synthetic active invitation count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE payload ? 'invitation_id' AND payload ? 'assessment_version' AND NOT payload ? 'secret' AND NOT payload ? 'invitation_url') FROM student_events WHERE student_id = 'S-syntheticstudent01' AND event_type = 'invitation.issued'`).Scan(&eventCount, &minimalEventCount); queryError != nil {
		t.Fatal("synthetic invitation event query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*), count(*) FILTER (WHERE metadata ? 'assessment_version' AND NOT metadata ? 'secret' AND NOT metadata ? 'invitation_url') FROM audit_events WHERE actor_id = $1 AND action = 'invitation.issued' AND object_type = 'invitation'`, actor.ID).Scan(&auditCount, &minimalAuditCount); queryError != nil {
		t.Fatal("synthetic invitation audit query failed")
	}
	if activeCount != 1 || eventCount != 2 || minimalEventCount != 2 || auditCount != 2 || minimalAuditCount != 2 {
		t.Fatalf("invitation evidence diverged: active=%d events=%d minimal_events=%d audits=%d minimal_audits=%d", activeCount, eventCount, minimalEventCount, auditCount, minimalAuditCount)
	}
}

// --- 撤销遵守对象范围并同时销毁原邀请与已兑换能力 ---
func TestRevokeInvitationHidesObjectsAndInvalidatesCapability(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "invitations") // 撤销前后均在同一真实事务模型中验证。
	clock := &syntheticInvitationClock{current: syntheticInvitationStart}
	commands := newInvitationTestCommands(t, connection, clock)
	issued, issueError := commands.Issue(
		context.Background(), syntheticInvitationStaffTwo(), "R-syntheticinviterevoke1", "synthetic-key-invite-revoke-01",
		"S-syntheticstudent03", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	)
	if issueError != nil {
		t.Fatalf("synthetic invitation for revoke failed: %v", issueError)
	}
	session, exchangeError := commands.Exchange(context.Background(), "R-syntheticinviteexchange1", issued.Secret)
	if exchangeError != nil {
		t.Fatalf("synthetic invitation exchange before revoke failed: %v", exchangeError)
	}

	if foreignError := commands.Revoke(context.Background(), syntheticInvitationStaffOne(), "R-syntheticinvitescope03", issued.ID); !errors.Is(foreignError, ErrNotFound) {
		t.Fatalf("foreign invitation revoke exposed existence: %v", foreignError)
	}
	if unknownError := commands.Revoke(context.Background(), syntheticInvitationStaffOne(), "R-syntheticinvitescope04", "IV-syntheticunknown01"); !errors.Is(unknownError, ErrNotFound) {
		t.Fatalf("unknown invitation revoke used a different failure: %v", unknownError)
	}
	if _, resolveError := commands.Resolve(context.Background(), session.ID, session.Secret); resolveError != nil { // 越权撤销不得产生副作用。
		t.Fatalf("foreign revoke invalidated capability: %v", resolveError)
	}
	if revokeError := commands.Revoke(context.Background(), syntheticInvitationOwner(), "R-syntheticinviterevoke2", issued.ID); revokeError != nil {
		t.Fatalf("owner invitation revoke failed: %v", revokeError)
	}
	if _, resolveError := commands.Resolve(context.Background(), session.ID, session.Secret); !errors.Is(resolveError, ErrInvalidCapability) {
		t.Fatalf("revoked invitation capability remained valid: %v", resolveError)
	}
	if _, replayError := commands.Exchange(context.Background(), "R-syntheticinviteexchange2", issued.Secret); !errors.Is(replayError, ErrInvalidInvitation) {
		t.Fatalf("revoked invitation used a distinguishable exchange failure: %v", replayError)
	}

	var state string        // 撤销保留生命周期事实。
	var inviteDigest []byte // 原邀请摘要不再需要保留。
	var sessionDigest []byte
	var revokedAt *time.Time
	if queryError := connection.QueryRow(context.Background(), `SELECT state, invite_digest, restricted_session_digest, revoked_at FROM student_invitations WHERE id = $1`, issued.ID).Scan(&state, &inviteDigest, &sessionDigest, &revokedAt); queryError != nil {
		t.Fatal("synthetic revoked invitation query failed")
	}
	if state != "revoked" || inviteDigest != nil || sessionDigest != nil || revokedAt == nil {
		t.Fatalf("invitation revoke left live material: state=%s invite_digest=%t session_digest=%t revoked_at=%t", state, inviteDigest != nil, sessionDigest != nil, revokedAt != nil)
	}
}

// --- 首次兑换销毁原摘要并创建单学生能力，后续重放统一拒绝 ---
func TestExchangeInvitationConsumesOnceAndNarrowsCapability(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "invitations") // 兑换与摘要检查共享一个 synthetic schema。
	clock := &syntheticInvitationClock{current: syntheticInvitationStart}
	commands := newInvitationTestCommands(t, connection, clock)
	issued, issueError := commands.Issue(
		context.Background(), syntheticInvitationStaffOne(), "R-syntheticinviteconsume1", "synthetic-key-invite-consume-01",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	)
	if issueError != nil {
		t.Fatalf("synthetic invitation for exchange failed: %v", issueError)
	}
	session, exchangeError := commands.Exchange(context.Background(), "R-syntheticinviteconsume2", issued.Secret)
	if exchangeError != nil {
		t.Fatalf("first synthetic invitation exchange failed: %v", exchangeError)
	}
	if session.ID == "" || session.Secret == "" || session.Secret == issued.Secret || session.StudentID != issued.StudentID || session.AssessmentVersion != issued.AssessmentVersion || session.ExpiresAt.After(issued.ExpiresAt) {
		t.Fatal("exchange did not return a narrower one-student session")
	}
	if _, replayError := commands.Exchange(context.Background(), "R-syntheticinviteconsume3", issued.Secret); !errors.Is(replayError, ErrInvalidInvitation) {
		t.Fatalf("invitation replay was not rejected safely: %v", replayError)
	}
	if _, unknownError := commands.Exchange(context.Background(), "R-syntheticinviteconsume4", "synthetic-unknown-invitation-secret-material-0001"); !errors.Is(unknownError, ErrInvalidInvitation) {
		t.Fatalf("unknown invitation secret used a different failure: %v", unknownError)
	}

	var state string         // 已兑换邀请保留明确终态。
	var inviteDigest []byte  // 原链接摘要必须销毁，防止再次匹配。
	var sessionDigest []byte // 新会话只持久化摘要。
	var exchangedAt *time.Time
	if queryError := connection.QueryRow(context.Background(), `SELECT state, invite_digest, restricted_session_digest, exchanged_at FROM student_invitations WHERE id = $1`, issued.ID).Scan(&state, &inviteDigest, &sessionDigest, &exchangedAt); queryError != nil {
		t.Fatal("synthetic exchanged invitation query failed")
	}
	expectedSessionDigest := sha256.Sum256([]byte(session.Secret))
	if state != "exchanged" || inviteDigest != nil || !bytes.Equal(sessionDigest, expectedSessionDigest[:]) || exchangedAt == nil {
		t.Fatalf("invitation exchange facts diverged: state=%s invite_digest=%t session_digest_match=%t exchanged_at=%t", state, inviteDigest != nil, bytes.Equal(sessionDigest, expectedSessionDigest[:]), exchangedAt != nil)
	}

	scope, resolveError := commands.Resolve(context.Background(), session.ID, session.Secret)
	if resolveError != nil || scope.StudentID != "S-syntheticstudent01" || scope.AssessmentVersion != "assessment-1" || scope.InvitationID != issued.ID {
		t.Fatalf("restricted capability resolved unexpected scope: student=%s assessment=%s invitation=%s error=%v", scope.StudentID, scope.AssessmentVersion, scope.InvitationID, resolveError)
	}
	if _, wrongSecretError := commands.Resolve(context.Background(), session.ID, "synthetic-wrong-capability-secret-material-0001"); !errors.Is(wrongSecretError, ErrInvalidCapability) {
		t.Fatalf("wrong capability secret used unsafe feedback: %v", wrongSecretError)
	}
	scopeType := reflect.TypeOf(scope)
	for _, forbiddenField := range []string{"AccountID", "Role", "StaffProfileID", "CredentialVersion"} { // 邀请能力不能升级成后台账号。
		if _, found := scopeType.FieldByName(forbiddenField); found {
			t.Fatalf("restricted capability exposed backend field %s", forbiddenField)
		}
	}

	var eventCount int // 兑换形成一个不含秘密的学生事件。
	var auditCount int // 兑换形成一个 invitation 主体的最小审计。
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_events WHERE student_id = $1 AND event_type = 'invitation.exchanged' AND actor_kind = 'invitation' AND NOT payload ? 'secret'`, issued.StudentID).Scan(&eventCount); queryError != nil {
		t.Fatal("synthetic exchange event query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE actor_kind = 'invitation' AND actor_id = $1 AND action = 'invitation.exchanged' AND object_id = $2 AND NOT metadata ? 'secret'`, session.ID, issued.ID).Scan(&auditCount); queryError != nil {
		t.Fatal("synthetic exchange audit query failed")
	}
	if eventCount != 1 || auditCount != 1 {
		t.Fatalf("invitation exchange evidence diverged: events=%d audits=%d", eventCount, auditCount)
	}
}

// --- 精确过期、替换和未知秘密共享相同公开失败 ---
func TestExpiredAndReplacedInvitationSecretsAreIndistinguishable(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "invitations") // 两个终态在同一 schema 内仍不可被公开区分。
	clock := &syntheticInvitationClock{current: syntheticInvitationStart}
	commands := newInvitationTestCommands(t, connection, clock)
	actor := syntheticInvitationStaffOne()

	expired, expiredIssueError := commands.Issue(
		context.Background(), actor, "R-syntheticinviteexpiry01", "synthetic-key-invite-expiry-01",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 1},
	)
	if expiredIssueError != nil {
		t.Fatalf("synthetic expiring invitation failed: %v", expiredIssueError)
	}
	clock.current = expired.ExpiresAt // 有效期采用半开区间，到期瞬间已经无效。
	if _, expiredError := commands.Exchange(context.Background(), "R-syntheticinviteexpiry02", expired.Secret); !errors.Is(expiredError, ErrInvalidInvitation) {
		t.Fatalf("exactly expired invitation remained valid: %v", expiredError)
	}

	clock.current = syntheticInvitationStart
	replaced, firstIssueError := commands.Issue(
		context.Background(), actor, "R-syntheticinvitereplaced1", "synthetic-key-invite-replaced-01",
		"S-syntheticstudent02", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	)
	if firstIssueError != nil {
		t.Fatalf("synthetic replaceable invitation failed: %v", firstIssueError)
	}
	if _, replacementError := commands.Issue(
		context.Background(), actor, "R-syntheticinvitereplaced2", "synthetic-key-invite-replaced-02",
		"S-syntheticstudent02", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	); replacementError != nil {
		t.Fatalf("synthetic replacement invitation failed: %v", replacementError)
	}
	if _, replacedError := commands.Exchange(context.Background(), "R-syntheticinvitereplaced3", replaced.Secret); !errors.Is(replacedError, ErrInvalidInvitation) {
		t.Fatalf("replaced invitation used a distinguishable failure: %v", replacedError)
	}
}

// --- 负责人变化同时失效未兑换邀请和已经兑换的能力 ---
func TestOwnerChangeInvalidatesInvitationAndRestrictedSession(t *testing.T) {
	tests := []struct {
		name     string // name 区分变化发生在兑换前或兑换后。
		exchange bool   // exchange 为 true 时验证更窄会话也动态重验负责人。
	}{
		{name: "pending invitation", exchange: false},
		{name: "restricted session", exchange: true},
	}

	for _, test := range tests { // 两种生命周期各自使用独立随机 schema。
		t.Run(test.name, func(t *testing.T) {
			connection := testsupport.OpenDatabase(t, "invitations")
			clock := &syntheticInvitationClock{current: syntheticInvitationStart}
			commands := newInvitationTestCommands(t, connection, clock)
			issued, issueError := commands.Issue(
				context.Background(), syntheticInvitationStaffOne(), "R-syntheticinviteownerchg1", "synthetic-key-invite-ownerchg",
				"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
			)
			if issueError != nil {
				t.Fatalf("synthetic owner-change invitation failed: %v", issueError)
			}
			var session CapabilitySession
			if test.exchange {
				var exchangeError error
				session, exchangeError = commands.Exchange(context.Background(), "R-syntheticinviteownerchg2", issued.Secret)
				if exchangeError != nil {
					t.Fatalf("synthetic owner-change exchange failed: %v", exchangeError)
				}
			}
			if _, transferError := connection.Exec(context.Background(), `
				WITH ended AS (
					UPDATE student_staff_assignments SET ended_at = $1, ended_by_account_id = 'A-syntheticowner01', updated_at = $1
					WHERE student_id = 'S-syntheticstudent01' AND ended_at IS NULL RETURNING student_id
				), inserted AS (
					INSERT INTO student_staff_assignments (id, student_id, staff_profile_id, assignment_role, started_at, created_by_account_id)
					SELECT 'SA-syntheticinviteowner02', student_id, 'T-syntheticcoach02', 'primary', $1, 'A-syntheticowner01' FROM ended LIMIT 1
					RETURNING student_id
				)
				UPDATE students SET owner_staff_id = 'T-syntheticcoach02', version = version + 1, updated_by = 'A-syntheticowner01', updated_at = $1
				WHERE id = (SELECT student_id FROM inserted)`, clock.current); transferError != nil {
				t.Fatalf("synthetic student owner-change setup failed: %v", transferError)
			}
			if test.exchange {
				if _, resolveError := commands.Resolve(context.Background(), session.ID, session.Secret); !errors.Is(resolveError, ErrInvalidCapability) {
					t.Fatalf("owner change left restricted session valid: %v", resolveError)
				}
				return
			}
			if _, exchangeError := commands.Exchange(context.Background(), "R-syntheticinviteownerchg3", issued.Secret); !errors.Is(exchangeError, ErrInvalidInvitation) {
				t.Fatalf("owner change left pending invitation valid: %v", exchangeError)
			}
		})
	}
}

// --- 补发审计失败必须保留原邀请且回滚所有新事实 ---
func TestReissueInvitationRollsBackReplacementOnAuditFailure(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "invitations") // 故障只安装在当前 synthetic schema。
	clock := &syntheticInvitationClock{current: syntheticInvitationStart}
	commands := newInvitationTestCommands(t, connection, clock)
	actor := syntheticInvitationStaffOne()
	original, issueError := commands.Issue(
		context.Background(), actor, "R-syntheticinviterollback1", "synthetic-key-invite-rollback-01",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 24},
	)
	if issueError != nil {
		t.Fatalf("synthetic original invitation failed: %v", issueError)
	}
	originalExpectedDigest := sha256.Sum256([]byte(original.Secret))
	if _, setupError := connection.Exec(context.Background(), `
		CREATE FUNCTION reject_synthetic_invitation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'invitation.issued' THEN
				RAISE EXCEPTION 'synthetic invitation audit rejection';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_synthetic_invitation_audit BEFORE INSERT ON audit_events
			FOR EACH ROW EXECUTE FUNCTION reject_synthetic_invitation_audit()`); setupError != nil {
		t.Fatal("synthetic invitation failure setup failed")
	}

	clock.current = clock.current.Add(time.Minute)
	if _, replacementError := commands.Issue(
		context.Background(), actor, "R-syntheticinviterollback2", "synthetic-key-invite-rollback-02",
		"S-syntheticstudent01", IssueInput{AssessmentVersion: "assessment-1", ExpiresInHours: 48},
	); !errors.Is(replacementError, ErrWriteFailed) {
		t.Fatalf("injected invitation audit failure was not safe: %v", replacementError)
	}

	var invitationCount int // 失败补发不能留下第二条邀请。
	var originalState string
	var originalDigest []byte
	var issueEventCount int // 只保留首次成功签发的事件。
	var issueAuditCount int // 只保留首次成功签发的审计。
	var failedIdempotencyCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_invitations WHERE student_id = 'S-syntheticstudent01'`).Scan(&invitationCount); queryError != nil {
		t.Fatal("synthetic rolled-back invitation count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT state, invite_digest FROM student_invitations WHERE id = $1`, original.ID).Scan(&originalState, &originalDigest); queryError != nil {
		t.Fatal("synthetic original invitation after rollback query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM student_events WHERE student_id = 'S-syntheticstudent01' AND event_type = 'invitation.issued'`).Scan(&issueEventCount); queryError != nil {
		t.Fatal("synthetic rolled-back invitation event count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'invitation.issued' AND object_type = 'invitation'`).Scan(&issueAuditCount); queryError != nil {
		t.Fatal("synthetic rolled-back invitation audit count failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE actor_scope = $1 AND action = 'invitation.issue' AND idempotency_key = 'synthetic-key-invite-rollback-02'`, actor.ID).Scan(&failedIdempotencyCount); queryError != nil {
		t.Fatal("synthetic rolled-back invitation idempotency count failed")
	}
	if invitationCount != 1 || originalState != "pending" || !bytes.Equal(originalDigest, originalExpectedDigest[:]) || issueEventCount != 1 || issueAuditCount != 1 || failedIdempotencyCount != 0 {
		t.Fatalf("failed replacement left partial facts: invitations=%d original_state=%s original_digest_match=%t events=%d audits=%d failed_idempotency=%d", invitationCount, originalState, bytes.Equal(originalDigest, originalExpectedDigest[:]), issueEventCount, issueAuditCount, failedIdempotencyCount)
	}
}

// --- 测试装配只暴露可推进时钟、身份和一次性秘密能力 ---
type syntheticInvitationClock struct {
	current time.Time // current 由过期测试显式推进，业务命令只读取。
}

func (clock *syntheticInvitationClock) Now() time.Time {
	return clock.current // 单一时间来源避免事务内边界漂移。
}

func newInvitationTestCommands(t *testing.T, connection *pgx.Conn, clock *syntheticInvitationClock) *Commands {
	t.Helper()         // 装配失败归因到调用行为测试。
	identityCount := 0 // 事件、审计、邀请和能力会话身份保持唯一。
	secretCount := 0   // 每次签发或兑换取得不同 synthetic 原始秘密。
	commands, createError := NewCommands(
		connection,
		clock.Now,
		func(prefix string) (string, error) {
			identityCount++
			return fmt.Sprintf("%s-syntheticinvitation%02d", prefix, identityCount), nil
		},
		func() (string, error) {
			secretCount++
			return fmt.Sprintf("synthetic-invitation-secret-material-%032d", secretCount), nil
		},
	)
	if createError != nil {
		t.Fatalf("invitation commands failed to initialize: %v", createError)
	}
	return commands // 行为测试只学习 Commands 深模块公开接口。
}

func syntheticInvitationOwner() auth.Account {
	return auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
}

func syntheticInvitationStaffOne() auth.Account {
	staffProfileID := "T-syntheticcoach01"
	return auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
}

func syntheticInvitationStaffTwo() auth.Account {
	staffProfileID := "T-syntheticcoach02"
	return auth.Account{ID: "A-syntheticstaff02", Role: "staff", State: "active", StaffProfileID: &staffProfileID}
}
