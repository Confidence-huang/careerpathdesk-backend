package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/confidence-huang/careerpathdesk-backend/internal/accounts"
	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate"
)

func TestBootstrapRejectsExistingStaffAndWeakPassword(t *testing.T) {
	connection := openBootstrapDatabase(t)
	passwordHash, hashError := auth.HashPassword("Synthetic-Existing-Staff!")
	if hashError != nil {
		t.Fatal("existing staff fixture password unavailable")
	}
	if _, insertError := connection.Exec(t.Context(), `INSERT INTO staff_profiles (id, display_name) VALUES ('T-existingstaff01', 'Synthetic Staff')`); insertError != nil {
		t.Fatal("existing staff profile fixture unavailable")
	}
	if _, insertError := connection.Exec(t.Context(), `
		INSERT INTO accounts (
			id, username_normalized, username_display, display_name, password_hash, role, state,
			staff_profile_id, credential_version, must_change_password, version
		) VALUES (
			'A-existingstaff01', 'existing.staff', 'existing.staff', 'Synthetic Staff', $1,
			'staff', 'active', 'T-existingstaff01', 1, true, 1
		)`, passwordHash); insertError != nil {
		t.Fatal("existing staff fixture unavailable")
	}
	commands, constructionError := New(connection, sequenceIdentity("A-rejectedowner001", "AU-rejectedowner01"))
	if constructionError != nil {
		t.Fatal("bootstrap construction failed")
	}
	_, existingError := commands.Bootstrap(t.Context(), Input{Username: "owner", DisplayName: "Owner", Password: "Temporary-Owner-Password-2026!"})
	if !errors.Is(existingError, ErrAlreadyInitialized) {
		t.Fatalf("existing staff did not permanently close bootstrap: %v", existingError)
	}

	emptyConnection := openBootstrapDatabase(t)
	emptyCommands, constructionError := New(emptyConnection, sequenceIdentity("A-rejectedowner002", "AU-rejectedowner02"))
	if constructionError != nil {
		t.Fatal("bootstrap construction failed")
	}
	_, weakError := emptyCommands.Bootstrap(t.Context(), Input{Username: "owner", DisplayName: "Owner", Password: "thirteen-char"})
	if !errors.Is(weakError, ErrInvalidInput) {
		t.Fatalf("weak bootstrap password was accepted: %v", weakError)
	}
	var accountCount int
	if queryError := emptyConnection.QueryRow(t.Context(), `SELECT count(*) FROM accounts`).Scan(&accountCount); queryError != nil || accountCount != 0 {
		t.Fatalf("weak bootstrap left account facts: count=%d error=%v", accountCount, queryError)
	}
}

func TestBootstrapRequiresExactCurrentSchemaLedger(t *testing.T) {
	connection := openBootstrapDatabase(t)
	if _, deleteError := connection.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=8`); deleteError != nil {
		t.Fatal("schema mismatch fixture unavailable")
	}
	commands, constructionError := New(connection, sequenceIdentity("A-schemaowner0001", "AU-schemaowner001"))
	if constructionError != nil {
		t.Fatal("bootstrap construction failed")
	}
	_, bootstrapError := commands.Bootstrap(t.Context(), Input{Username: "owner", DisplayName: "Owner", Password: "Temporary-Owner-Password-2026!"})
	if !errors.Is(bootstrapError, ErrSchemaMismatch) {
		t.Fatalf("schema mismatch was accepted: %v", bootstrapError)
	}
}

func TestConcurrentBootstrapCommitsExactlyOneOwner(t *testing.T) {
	firstConnection := openBootstrapDatabase(t)
	secondConnection := openBootstrapPeer(t, firstConnection)
	first, firstConstructionError := New(firstConnection, sequenceIdentity("A-concurrentowner1", "AU-concurrentown01"))
	second, secondConstructionError := New(secondConnection, sequenceIdentity("A-concurrentowner2", "AU-concurrentown02"))
	if firstConstructionError != nil || secondConstructionError != nil {
		t.Fatal("bootstrap construction failed")
	}
	input := Input{Username: "owner", DisplayName: "Owner", Password: "Temporary-Owner-Password-2026!"}
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, commands := range []*Commands{first, second} {
		group.Add(1)
		go func(current *Commands) {
			defer group.Done()
			<-start
			_, bootstrapError := current.Bootstrap(context.Background(), input)
			results <- bootstrapError
		}(commands)
	}
	close(start)
	group.Wait()
	close(results)
	successes := 0
	alreadyInitialized := 0
	for bootstrapError := range results {
		if bootstrapError == nil {
			successes++
		} else if errors.Is(bootstrapError, ErrAlreadyInitialized) {
			alreadyInitialized++
		} else {
			t.Fatalf("unexpected concurrent bootstrap result: %v", bootstrapError)
		}
	}
	if successes != 1 || alreadyInitialized != 1 {
		t.Fatalf("concurrent bootstrap results diverged: success=%d closed=%d", successes, alreadyInitialized)
	}
	var accountCount int
	if queryError := firstConnection.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE role='owner'`).Scan(&accountCount); queryError != nil || accountCount != 1 {
		t.Fatalf("concurrent bootstrap did not leave one owner: count=%d error=%v", accountCount, queryError)
	}
}

func TestBootstrapCreatesOnlyForcedChangeOwnerWithMinimalAudit(t *testing.T) {
	connection := openBootstrapDatabase(t)
	identities := []string{"A-bootstrapowner01", "AU-bootstrapowner1"}
	commands, constructionError := New(connection, func(prefix string) (string, error) {
		identity := identities[0]
		identities = identities[1:]
		return identity, nil
	})
	if constructionError != nil {
		t.Fatalf("bootstrap construction failed: %v", constructionError)
	}
	input := Input{Username: " Initial.Owner ", DisplayName: "Initial Owner", Password: "Temporary-Owner-Password-2026!"}
	result, bootstrapError := commands.Bootstrap(context.Background(), input)
	if bootstrapError != nil {
		t.Fatalf("owner bootstrap failed: %v", bootstrapError)
	}
	if result.AccountID != "A-bootstrapowner01" {
		t.Fatalf("unexpected bootstrap result: %#v", result)
	}

	var usernameNormalized string
	var usernameDisplay string
	var displayName string
	var passwordHash string
	var role string
	var state string
	var staffProfileID *string
	var credentialVersion int64
	var mustChangePassword bool
	var version int64
	queryError := connection.QueryRow(t.Context(), `
		SELECT username_normalized, username_display, display_name, password_hash, role, state,
		       staff_profile_id, credential_version, must_change_password, version
		FROM accounts WHERE id=$1`, result.AccountID).Scan(
		&usernameNormalized, &usernameDisplay, &displayName, &passwordHash, &role, &state,
		&staffProfileID, &credentialVersion, &mustChangePassword, &version,
	)
	if queryError != nil {
		t.Fatal("bootstrapped owner was not persisted")
	}
	if usernameNormalized != "initial.owner" || usernameDisplay != "Initial.Owner" || displayName != "Initial Owner" || role != "owner" || state != "active" || staffProfileID != nil || credentialVersion != 1 || !mustChangePassword || version != 1 {
		t.Fatalf("bootstrapped owner facts diverged: %q %q %q %q %q %#v %d %t %d", usernameNormalized, usernameDisplay, displayName, role, state, staffProfileID, credentialVersion, mustChangePassword, version)
	}
	if !auth.VerifyPassword(passwordHash, input.Password) {
		t.Fatal("bootstrap did not use the established Argon2id password boundary")
	}

	var auditCount int
	auditError := connection.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events
		WHERE action='account.bootstrap_owner' AND actor_kind='system' AND actor_id='bootstrap-owner'
		  AND object_type='account' AND object_id=$1 AND outcome='success'
		  AND request_id='bootstrap-owner' AND metadata='{}'::jsonb`, result.AccountID).Scan(&auditCount)
	if auditError != nil || auditCount != 1 {
		t.Fatalf("minimal bootstrap audit was not persisted: count=%d error=%v", auditCount, auditError)
	}
	var leakedInputCount int
	if leakError := connection.QueryRow(t.Context(), `
		SELECT count(*) FROM audit_events
		WHERE action='account.bootstrap_owner'
		  AND (metadata::text LIKE '%' || $1 || '%' OR metadata::text LIKE '%' || $2 || '%'
		       OR metadata::text LIKE '%' || $3 || '%')`, input.Username, input.DisplayName, input.Password).Scan(&leakedInputCount); leakError != nil || leakedInputCount != 0 {
		t.Fatalf("bootstrap audit retained operator input: count=%d error=%v", leakedInputCount, leakError)
	}
}

func TestBootstrapOwnerCanProvisionFirstStaffAccountInEmptySchema(t *testing.T) {
	connection := openBootstrapDatabase(t)
	bootstrapCommands, constructionError := New(connection, sequenceIdentity("A-firstowner00001", "AU-firstowneraudit1"))
	if constructionError != nil {
		t.Fatal("bootstrap construction failed")
	}
	ownerResult, bootstrapError := bootstrapCommands.Bootstrap(t.Context(), Input{
		Username: "first.owner", DisplayName: "Synthetic First Owner", Password: "Temporary-Owner-Password-2026!",
	})
	if bootstrapError != nil {
		t.Fatalf("empty-schema owner bootstrap failed: %v", bootstrapError)
	}
	if _, updateError := connection.Exec(t.Context(), `UPDATE accounts SET must_change_password = false WHERE id = $1`, ownerResult.AccountID); updateError != nil {
		t.Fatal("synthetic first owner activation failed")
	}
	accountCommands, accountConstructionError := accounts.NewCommands(
		connection,
		func() time.Time { return time.Date(2026, time.August, 9, 3, 0, 0, 0, time.UTC) },
		sequenceIdentity("A-firststaff00001", "AU-firststaffaudit1", "T-firststaff00001"),
	)
	if accountConstructionError != nil {
		t.Fatal("first staff account commands failed to initialize")
	}
	created, createError := accountCommands.Create(t.Context(), auth.Account{
		ID: ownerResult.AccountID, Role: "owner", State: "active",
	}, "R-firststaffcreate01", "synthetic-key-first-staff-01", accounts.CreateInput{
		Username: "first.staff", DisplayName: "Synthetic First Staff", Role: "staff",
		InitialPassword: "Temporary-Staff-Password-2026!",
	})
	if createError != nil || created.StaffProfileID == nil {
		t.Fatalf("bootstrapped owner could not provision first staff: account=%#v error=%v", created, createError)
	}

	var ownerCount int
	var staffCount int
	var profileCount int
	var createAuditCount int
	var idempotencyCount int
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE role = 'owner'`).Scan(&ownerCount); queryError != nil {
		t.Fatal("first owner count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM accounts WHERE role = 'staff' AND staff_profile_id = $1`, *created.StaffProfileID).Scan(&staffCount); queryError != nil {
		t.Fatal("first staff count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM staff_profiles WHERE id = $1 AND state = 'active' AND display_name = 'Synthetic First Staff'`, *created.StaffProfileID).Scan(&profileCount); queryError != nil {
		t.Fatal("first staff profile count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action = 'account.created' AND object_id = $1`, created.ID).Scan(&createAuditCount); queryError != nil {
		t.Fatal("first staff audit count failed")
	}
	if queryError := connection.QueryRow(t.Context(), `SELECT count(*) FROM idempotency_records WHERE resource_id = $1 AND action = 'account.create'`, created.ID).Scan(&idempotencyCount); queryError != nil {
		t.Fatal("first staff idempotency count failed")
	}
	if ownerCount != 1 || staffCount != 1 || profileCount != 1 || createAuditCount != 1 || idempotencyCount != 1 {
		t.Fatalf("empty-schema first staff facts diverged: owner=%d staff=%d profile=%d audit=%d idempotency=%d", ownerCount, staffCount, profileCount, createAuditCount, idempotencyCount)
	}
}

func openBootstrapDatabase(t *testing.T) *pgx.Conn {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL"))
	passwordFile := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE"))
	if databaseURL == "" || passwordFile == "" {
		t.Fatal("explicit synthetic test database configuration is required")
	}
	passwordBytes, readError := os.ReadFile(passwordFile)
	if readError != nil {
		t.Fatal("synthetic database password file unavailable")
	}
	connectionConfig, parseError := pgx.ParseConfig(databaseURL)
	if parseError != nil {
		t.Fatal("synthetic database URL is invalid")
	}
	connectionConfig.Password = strings.TrimSpace(string(passwordBytes))
	connection, connectError := pgx.ConnectConfig(context.Background(), connectionConfig)
	if connectError != nil {
		t.Fatal("synthetic database connection failed")
	}
	randomIdentity := make([]byte, 8)
	if _, randomError := rand.Read(randomIdentity); randomError != nil {
		t.Fatal("synthetic schema identity unavailable")
	}
	schemaName := "bootstrap_" + hex.EncodeToString(randomIdentity)
	quotedSchema := pgx.Identifier{schemaName}.Sanitize()
	if _, createError := connection.Exec(t.Context(), "CREATE SCHEMA "+quotedSchema); createError != nil {
		t.Fatal("synthetic schema creation failed")
	}
	if _, searchPathError := connection.Exec(t.Context(), "SET search_path TO "+quotedSchema); searchPathError != nil {
		t.Fatal("synthetic schema selection failed")
	}
	migrations, loadError := migrate.Load(os.DirFS("../../../database/migrations"))
	if loadError != nil {
		t.Fatalf("product migrations failed to load: %v", loadError)
	}
	if applyError := migrate.Apply(t.Context(), connection, migrations); applyError != nil {
		t.Fatalf("product migrations failed: %v", applyError)
	}
	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "SET search_path TO public")
		_, _ = connection.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		_ = connection.Close(context.Background())
	})
	return connection
}

func openBootstrapPeer(t *testing.T, first *pgx.Conn) *pgx.Conn {
	t.Helper()
	var searchPath string
	if queryError := first.QueryRow(t.Context(), `SHOW search_path`).Scan(&searchPath); queryError != nil {
		t.Fatal("synthetic schema identity unavailable")
	}
	databaseURL := strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_URL"))
	passwordBytes, readError := os.ReadFile(strings.TrimSpace(os.Getenv("CAREERPATH_TEST_DATABASE_PASSWORD_FILE")))
	if readError != nil {
		t.Fatal("synthetic database password file unavailable")
	}
	connectionConfig, parseError := pgx.ParseConfig(databaseURL)
	if parseError != nil {
		t.Fatal("synthetic database URL is invalid")
	}
	connectionConfig.Password = strings.TrimSpace(string(passwordBytes))
	peer, connectError := pgx.ConnectConfig(t.Context(), connectionConfig)
	if connectError != nil {
		t.Fatal("synthetic peer connection failed")
	}
	if _, searchPathError := peer.Exec(t.Context(), "SET search_path TO "+searchPath); searchPathError != nil {
		_ = peer.Close(t.Context())
		t.Fatal("synthetic peer schema selection failed")
	}
	t.Cleanup(func() { _ = peer.Close(context.Background()) })
	return peer
}

func sequenceIdentity(identities ...string) func(string) (string, error) {
	return func(prefix string) (string, error) {
		if len(identities) == 0 {
			return "", errors.New("synthetic identity unavailable")
		}
		identity := identities[0]
		identities = identities[1:]
		return identity, nil
	}
}
