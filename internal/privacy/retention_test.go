package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport"
)

func TestRetentionDryRunSelectsOnlyExpiredUnblockedStudents(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "privacy_retention")
	asOf := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	commands, constructionError := NewRetentionCommands(connection, func() time.Time { return asOf })
	if constructionError != nil {
		t.Fatalf("retention commands unavailable: %v", constructionError)
	}

	insertRetentionStudent(t, connection, "S-syntheticretention01", asOf.Add(-181*24*time.Hour), false)
	insertRetentionStudent(t, connection, "S-syntheticretention02", asOf.Add(-179*24*time.Hour), false)
	insertRetentionStudent(t, connection, "S-syntheticretention03", asOf.Add(-181*24*time.Hour), true)

	summary, dryRunError := commands.DryRun(context.Background(), asOf)
	if dryRunError != nil {
		t.Fatalf("retention dry-run failed: %v", dryRunError)
	}
	if summary.EligibleCount != 2 || len(summary.AnonymousIDs) != 2 || summary.AnonymousIDs[0] == "S-syntheticretention01" || summary.Digest == "" {
		t.Fatalf("dry-run did not expose only an anonymous eligible summary: %#v", summary)
	}
	if summary.BlockedCount != 0 {
		t.Fatalf("legacy archived task incorrectly blocked retention: %#v", summary)
	}
}

func TestRetentionExecuteRequiresOwnerExactSummaryAndDeletesSafely(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "privacy_retention")
	asOf := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	executedAt := asOf.Add(time.Hour)
	commands, _ := NewRetentionCommands(connection, func() time.Time { return executedAt })
	studentID := "S-syntheticretention04"
	insertRetentionStudent(t, connection, studentID, asOf.Add(-181*24*time.Hour), false)

	summary, dryRunError := commands.DryRun(context.Background(), asOf)
	if dryRunError != nil {
		t.Fatalf("retention dry-run failed: %v", dryRunError)
	}
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active"}
	if _, executeError := commands.Execute(context.Background(), staff, asOf, summary.Digest); !errors.Is(executeError, ErrForbidden) {
		t.Fatalf("staff executed deletion: %v", executeError)
	}
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	var historicalAuditBefore int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE object_id = $1`, studentID).Scan(&historicalAuditBefore); queryError != nil || historicalAuditBefore != 1 {
		t.Fatalf("historical audit setup diverged: count=%d err=%v", historicalAuditBefore, queryError)
	}
	if _, executeError := commands.Execute(context.Background(), owner, asOf, "wrong-digest"); !errors.Is(executeError, ErrConfirmationMismatch) {
		t.Fatalf("mismatched retention summary was accepted: %v", executeError)
	}
	executed, executeError := commands.Execute(context.Background(), owner, asOf, summary.Digest)
	if executeError != nil || executed.DeletedCount != 1 {
		t.Fatalf("retention execution failed: %#v %v", executed, executeError)
	}

	var studentCount, businessCount, anonymousAuditCount, deletionAuditCount, directAuditCount, scrubbedHistoricalAuditCount, exactDeletionTimeCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM students WHERE id = $1`, studentID).Scan(&studentCount); queryError != nil {
		t.Fatal("deleted student query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM coaching_tasks WHERE student_id = $1) + (SELECT count(*) FROM student_events WHERE student_id = $1)`, studentID).Scan(&businessCount); queryError != nil {
		t.Fatal("deleted business facts query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE object_type = 'deleted_student' AND object_id LIKE 'ANON-%'), count(*) FILTER (WHERE action = 'student.retention_deleted'), count(*) FILTER (WHERE object_id = $1) FROM audit_events`, studentID).Scan(&anonymousAuditCount, &deletionAuditCount, &directAuditCount); queryError != nil {
		t.Fatal("retention audit query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action IN ('student.updated', 'student.synthetic_event') AND object_type = 'deleted_student' AND object_id LIKE 'ANON-%' AND metadata = '{}'::jsonb`).Scan(&scrubbedHistoricalAuditCount); queryError != nil {
		t.Fatal("retention historical audit scrub query failed")
	}
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action = 'student.retention_deleted' AND occurred_at = $1`, executedAt).Scan(&exactDeletionTimeCount); queryError != nil {
		t.Fatal("retention execution timestamp query failed")
	}
	if studentCount != 0 || businessCount != 0 || anonymousAuditCount != 3 || deletionAuditCount != 1 || directAuditCount != 0 || scrubbedHistoricalAuditCount != 2 || exactDeletionTimeCount != 1 {
		t.Fatalf("safe deletion left identifiable business facts: students=%d business=%d anonymous_audit=%d deletion_audit=%d direct_audit=%d scrubbed_history=%d exact_time=%d", studentCount, businessCount, anonymousAuditCount, deletionAuditCount, directAuditCount, scrubbedHistoricalAuditCount, exactDeletionTimeCount)
	}
}

func TestRetentionBlocksCurrentInvitationAndAttentionWorkflowsButArchivesLegacyTasks(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "privacy_retention")
	asOf := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	commands, _ := NewRetentionCommands(connection, func() time.Time { return asOf })
	closedAt := asOf.Add(-181 * 24 * time.Hour)
	insertRetentionStudent(t, connection, "S-syntheticblocktask01", closedAt, true)
	insertRetentionStudent(t, connection, "S-syntheticblockinvite1", closedAt, false)
	insertRetentionStudent(t, connection, "S-syntheticblockattention", closedAt, false)
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO student_invitations (id, student_id, issued_by_account_id, assessment_version, student_version, state, invite_digest, expires_at)
		VALUES ('IV-syntheticblockinvite1', 'S-syntheticblockinvite1', 'A-syntheticstaff01', 'assessment-1', 1, 'pending', decode(repeat('ab', 32), 'hex'), $1)`, asOf.Add(24*time.Hour)); insertError != nil {
		t.Fatalf("active invitation blocker setup failed: %v", insertError)
	}
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO student_attention_cases (id, student_id, rule_code, trigger_codes, evidence, evidence_fingerprint, first_triggered_at, last_triggered_at, status)
		VALUES ('AC-syntheticblockattention', 'S-syntheticblockattention', 'complaint', ARRAY['complaint'], '[{"object_type":"student_event","object_id":"EV-syntheticblockattention"}]'::jsonb, decode(repeat('cd', 32), 'hex'), $1, $1, 'open')`, asOf.Add(-time.Hour)); insertError != nil {
		t.Fatalf("open attention blocker setup failed: %v", insertError)
	}

	summary, dryRunError := commands.DryRun(context.Background(), asOf)
	if dryRunError != nil || summary.EligibleCount != 1 || summary.BlockedCount != 2 || len(summary.AnonymousIDs) != 1 {
		t.Fatalf("current workflow blockers or legacy task archive handling diverged: %#v %v", summary, dryRunError)
	}
}

func TestBackupRetentionExpiresNaturallyAfterThirtyDays(t *testing.T) {
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	if got := BackupExpiresAt(createdAt); !got.Equal(createdAt.Add(30 * 24 * time.Hour)) {
		t.Fatalf("backup expiry is not exactly 30 days: %s", got)
	}
}

func TestRetentionExpiresAuditEventsAtExactlyThreeHundredSixtyFiveDays(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "audit_retention")
	asOf := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	commands, constructionError := NewRetentionCommands(connection, func() time.Time { return asOf })
	if constructionError != nil {
		t.Fatalf("retention commands unavailable: %v", constructionError)
	}

	for _, fixture := range []struct {
		id         string
		occurredAt time.Time
	}{
		{id: "AU-syntheticauditexpired01", occurredAt: asOf.Add(-365 * 24 * time.Hour)},
		{id: "AU-syntheticauditexpired02", occurredAt: asOf.Add(-366 * 24 * time.Hour)},
		{id: "AU-syntheticauditretained01", occurredAt: asOf.Add(-365*24*time.Hour + time.Second)},
	} {
		if _, insertError := connection.Exec(context.Background(), `
			INSERT INTO audit_events (
				id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at
			) VALUES ($1, 'system', 'synthetic-audit-retention', 'retention.synthetic', 'maintenance',
				'synthetic-audit-retention', 'success', 'R-syntheticauditretention', '{}'::jsonb, $2)`,
			fixture.id, fixture.occurredAt); insertError != nil {
			t.Fatalf("audit retention fixture unavailable: %v", insertError)
		}
	}

	summary, dryRunError := commands.DryRun(context.Background(), asOf)
	if dryRunError != nil {
		t.Fatalf("audit retention dry-run failed: %v", dryRunError)
	}
	if summary.ExpiredAuditCount != 2 || summary.DeletedAuditCount != 0 {
		t.Fatalf("audit retention dry-run boundary diverged: %#v", summary)
	}

	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	executed, executeError := commands.Execute(context.Background(), owner, asOf, summary.Digest)
	if executeError != nil || executed.ExpiredAuditCount != 2 || executed.DeletedAuditCount != 2 {
		t.Fatalf("audit retention execution failed: %#v %v", executed, executeError)
	}

	var expiredCount, retainedCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT count(*) FILTER (WHERE id IN ('AU-syntheticauditexpired01', 'AU-syntheticauditexpired02')),
		       count(*) FILTER (WHERE id = 'AU-syntheticauditretained01')
		FROM audit_events`).Scan(&expiredCount, &retainedCount); queryError != nil {
		t.Fatalf("audit retention result unavailable: %v", queryError)
	}
	if expiredCount != 0 || retainedCount != 1 {
		t.Fatalf("audit retention boundary was not enforced: expired=%d retained=%d", expiredCount, retainedCount)
	}
}

func TestRetentionRejectsSameCountDifferentExpiredAuditSet(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "audit_retention")
	asOf := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	commands, constructionError := NewRetentionCommands(connection, func() time.Time { return asOf })
	if constructionError != nil {
		t.Fatalf("retention commands unavailable: %v", constructionError)
	}

	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO audit_events (
			id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at
		) VALUES ('AU-syntheticauditsetbefore', 'system', 'synthetic-audit-retention', 'retention.synthetic',
			'maintenance', 'synthetic-audit-retention', 'success', 'R-syntheticauditretention', '{}'::jsonb, $1)`,
		asOf.Add(-AuditRetention)); insertError != nil {
		t.Fatalf("original audit set fixture unavailable: %v", insertError)
	}
	dryRun, dryRunError := commands.DryRun(context.Background(), asOf)
	if dryRunError != nil {
		t.Fatalf("retention dry-run failed: %v", dryRunError)
	}

	if _, deleteError := connection.Exec(context.Background(), `DELETE FROM audit_events WHERE id = 'AU-syntheticauditsetbefore'`); deleteError != nil {
		t.Fatalf("original audit set fixture could not be replaced: %v", deleteError)
	}
	if _, replacementError := connection.Exec(context.Background(), `
		INSERT INTO audit_events (
			id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at
		) VALUES ('AU-syntheticauditsetafter', 'system', 'synthetic-audit-retention', 'retention.synthetic',
			'maintenance', 'synthetic-audit-retention', 'success', 'R-syntheticauditretention', '{}'::jsonb, $1)`,
		asOf.Add(-AuditRetention)); replacementError != nil {
		t.Fatalf("replacement audit set fixture unavailable: %v", replacementError)
	}

	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	if _, executeError := commands.Execute(context.Background(), owner, asOf, dryRun.Digest); !errors.Is(executeError, ErrConfirmationMismatch) {
		t.Fatalf("same-count replacement audit set accepted stale confirmation: %v", executeError)
	}
	var replacementCount int
	if queryError := connection.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE id = 'AU-syntheticauditsetafter'`).Scan(&replacementCount); queryError != nil || replacementCount != 1 {
		t.Fatalf("replacement audit was deleted by stale confirmation: count=%d err=%v", replacementCount, queryError)
	}
}

func TestRetentionAuditDeleteFailureRollsBackStudentAndAuditDeletion(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "audit_retention")
	asOf := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	commands, constructionError := NewRetentionCommands(connection, func() time.Time { return asOf })
	if constructionError != nil {
		t.Fatalf("retention commands unavailable: %v", constructionError)
	}
	studentID := "S-syntheticretentionrollback"
	insertRetentionStudent(t, connection, studentID, asOf.Add(-181*24*time.Hour), false)
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO audit_events (
			id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata, occurred_at
		) VALUES ('AU-syntheticauditrollback', 'system', 'synthetic-audit-retention', 'retention.synthetic',
			'maintenance', 'synthetic-audit-retention', 'success', 'R-syntheticauditretention', '{}'::jsonb, $1)`,
		asOf.Add(-AuditRetention)); insertError != nil {
		t.Fatalf("rollback audit fixture unavailable: %v", insertError)
	}

	dryRun, dryRunError := commands.DryRun(context.Background(), asOf)
	if dryRunError != nil {
		t.Fatalf("retention dry-run failed: %v", dryRunError)
	}
	if _, triggerError := connection.Exec(context.Background(), `
		CREATE FUNCTION synthetic_reject_audit_delete() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'synthetic audit delete failure';
		END
		$$;
		CREATE TRIGGER synthetic_reject_audit_delete
			BEFORE DELETE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION synthetic_reject_audit_delete()`); triggerError != nil {
		t.Fatalf("audit rollback trigger unavailable: %v", triggerError)
	}
	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), `
			DROP TRIGGER IF EXISTS synthetic_reject_audit_delete ON audit_events;
			DROP FUNCTION IF EXISTS synthetic_reject_audit_delete()`)
	})

	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	if _, executeError := commands.Execute(context.Background(), owner, asOf, dryRun.Digest); !errors.Is(executeError, ErrWriteFailed) {
		t.Fatalf("audit delete failure was not closed safely: %v", executeError)
	}
	var studentCount, auditCount, deletionAuditCount int
	if queryError := connection.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM students WHERE id = $1),
		       (SELECT count(*) FROM audit_events WHERE id = 'AU-syntheticauditrollback'),
		       (SELECT count(*) FROM audit_events WHERE action = 'student.retention_deleted' AND object_id = $2)`,
		studentID, anonymousSubjectID(studentID)).Scan(&studentCount, &auditCount, &deletionAuditCount); queryError != nil {
		t.Fatalf("rollback result unavailable: %v", queryError)
	}
	if studentCount != 1 || auditCount != 1 || deletionAuditCount != 0 {
		t.Fatalf("audit delete failure left a partial transaction: student=%d audit=%d deletion_audit=%d", studentCount, auditCount, deletionAuditCount)
	}
}

func insertRetentionStudent(t *testing.T, connection *pgx.Conn, studentID string, closedAt time.Time, withOpenTask bool) {
	t.Helper()
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO students (
			id, name, service_stage, job_search_stage, owner_staff_id, source_kind,
			created_by, updated_by, processing_basis, privacy_notice_version,
			privacy_notice_delivered_at, closed_at, retention_due_at
		) VALUES ($1, 'Synthetic Retention Student', '已完成服务', '未开始',
			'T-syntheticcoach01', 'staff', 'A-syntheticstaff01', 'A-syntheticstaff01',
			'service_contract', 'privacy-notice-v1', $2::timestamptz, $2::timestamptz, $2::timestamptz + interval '180 days')`, studentID, closedAt); insertError != nil {
		t.Fatalf("retention student setup failed: %v", insertError)
	}
	if withOpenTask {
		if _, insertError := connection.Exec(context.Background(), `
			INSERT INTO coaching_tasks (id, student_id, assignee_staff_id, title, status, created_by, updated_by)
			VALUES ('CT-syntheticretention01', $1, 'T-syntheticcoach01', 'Synthetic Open Retention Task', 'open', 'A-syntheticstaff01', 'A-syntheticstaff01')`, studentID); insertError != nil {
			t.Fatalf("retention blocker setup failed: %v", insertError)
		}
	}
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata)
		VALUES ('AU-' || encode(sha256(convert_to($1::text, 'UTF8')), 'hex'), 'account', 'A-syntheticstaff01', 'student.updated', 'student', $1::text, 'success', 'R-syntheticretentionaudit', '{"student_version":2}'::jsonb)`, studentID); insertError != nil {
		t.Fatalf("retention audit setup failed: %v", insertError)
	}
	if _, insertError := connection.Exec(context.Background(), `
		WITH inserted_event AS (
			INSERT INTO student_events (id, student_id, event_type, actor_kind, actor_id, payload, occurred_at)
			VALUES ('EV-' || encode(sha256(convert_to('event-' || $1::text, 'UTF8')), 'hex'), $1, 'synthetic.retention', 'account', 'A-syntheticstaff01', '{"student_version":2}'::jsonb, $2)
			RETURNING id
		)
		INSERT INTO audit_events (id, actor_kind, actor_id, action, object_type, object_id, outcome, request_id, metadata)
		SELECT 'AU-' || encode(sha256(convert_to('audit-event-' || $1::text, 'UTF8')), 'hex'), 'account', 'A-syntheticstaff01', 'student.synthetic_event', 'student_event', id, 'success', 'R-syntheticretentionaudit', '{"event_kind":"synthetic"}'::jsonb
		FROM inserted_event`, studentID, closedAt); insertError != nil {
		t.Fatalf("retention child audit setup failed: %v", insertError)
	}
	if _, insertError := connection.Exec(context.Background(), `
		WITH original AS (
			INSERT INTO student_status_history (id, student_id, dimension, from_value, to_value, reason, base_student_version, student_version, changed_by_account_id, changed_at, undone_by_account_id, undone_at, version)
			VALUES ('SH-' || encode(sha256(convert_to('original-' || $1::text, 'UTF8')), 'hex'), $1, 'service', '服务中', '暂停服务', 'Synthetic retention original', 1, 2, 'A-syntheticstaff01', $2, 'A-syntheticstaff01', $2, 2)
			RETURNING id
		)
		INSERT INTO student_status_history (id, student_id, dimension, from_value, to_value, reason, base_student_version, student_version, changed_by_account_id, changed_at, reverses_status_change_id)
		SELECT 'SH-' || encode(sha256(convert_to('reverse-' || $1::text, 'UTF8')), 'hex'), $1, 'service', '暂停服务', '服务中', 'Synthetic retention reverse', 2, 3, 'A-syntheticstaff01', $2, id FROM original`, studentID, closedAt.Add(-time.Hour)); insertError != nil {
		t.Fatalf("retention undo-chain setup failed: %v", insertError)
	}
	if _, insertError := connection.Exec(context.Background(), `
		INSERT INTO student_status_history (id, student_id, dimension, from_value, to_value, reason, base_student_version, student_version, changed_by_account_id, changed_at, reverses_status_change_id)
		VALUES (
			'SH-' || encode(sha256(convert_to('second-reverse-' || $1::text, 'UTF8')), 'hex'), $1, 'service', '服务中', '暂停服务',
			'Synthetic retention second reverse', 3, 4, 'A-syntheticstaff01', $2,
			'SH-' || encode(sha256(convert_to('reverse-' || $1::text, 'UTF8')), 'hex')
		)`, studentID, closedAt.Add(-30*time.Minute)); insertError != nil {
		t.Fatalf("retention repeated undo-chain setup failed: %v", insertError)
	}
}
