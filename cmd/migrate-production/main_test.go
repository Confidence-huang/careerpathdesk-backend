package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate"
)

const testReleaseSHA = "0123456789abcdef0123456789abcdef01234567"

func TestProductionMigrationRequiresExplicitFrozenArguments(t *testing.T) {
	options, parseError := parseProductionArguments([]string{
		"--migration-dir=/opt/careerpathdesk-production/releases/test/database/migrations",
		"--expected-release-sha=" + testReleaseSHA,
	})
	if parseError != nil || options.migrationDirectory == "" || options.expectedReleaseSHA != testReleaseSHA {
		t.Fatalf("valid production migration arguments failed: %#v %v", options, parseError)
	}

	invalid := [][]string{
		{},
		{"--migration-dir=/tmp/migrations"},
		{"--expected-release-sha=" + testReleaseSHA},
		{"--migration-dir=relative/database/migrations", "--expected-release-sha=" + testReleaseSHA},
		{"--migration-dir=/tmp/database/migrations", "--expected-release-sha=main"},
		{"--migration-dir=/tmp/database/migrations", "--expected-release-sha=" + testReleaseSHA, "--seed"},
		{"--migration-dir=/tmp/database/migrations", "--expected-release-sha=" + testReleaseSHA, "--down=7"},
	}
	for _, arguments := range invalid {
		if _, invalidError := parseProductionArguments(arguments); !errors.Is(invalidError, errInvalidProductionMigrationArguments) {
			t.Fatalf("unsafe arguments were accepted: %#v (%v)", arguments, invalidError)
		}
	}
}

func TestProductionMigrationVerifiesExactReleaseRootIdentity(t *testing.T) {
	releaseRoot := t.TempDir()
	migrationDirectory := filepath.Join(releaseRoot, "database", "migrations")
	if createError := os.MkdirAll(migrationDirectory, 0o755); createError != nil {
		t.Fatal("release fixture unavailable")
	}
	identityPath := filepath.Join(releaseRoot, "RELEASE-SHA")
	if writeError := os.WriteFile(identityPath, []byte(testReleaseSHA+"\n"), 0o644); writeError != nil {
		t.Fatal("release identity fixture unavailable")
	}
	if verifyError := verifyReleaseIdentity(migrationDirectory, testReleaseSHA); verifyError != nil {
		t.Fatalf("exact release identity was rejected: %v", verifyError)
	}

	if writeError := os.WriteFile(identityPath, []byte(" "+testReleaseSHA+"\n"), 0o644); writeError != nil {
		t.Fatal("release identity fixture unavailable")
	}
	if verifyError := verifyReleaseIdentity(migrationDirectory, testReleaseSHA); !errors.Is(verifyError, errReleaseIdentityMismatch) {
		t.Fatalf("whitespace-mutated release identity was accepted: %v", verifyError)
	}

	if removeError := os.Remove(identityPath); removeError != nil {
		t.Fatal("release identity fixture unavailable")
	}
	targetPath := filepath.Join(releaseRoot, "identity-target")
	if writeError := os.WriteFile(targetPath, []byte(testReleaseSHA+"\n"), 0o644); writeError != nil {
		t.Fatal("release identity fixture unavailable")
	}
	if linkError := os.Symlink(targetPath, identityPath); linkError != nil {
		t.Fatal("release identity symlink fixture unavailable")
	}
	if verifyError := verifyReleaseIdentity(migrationDirectory, testReleaseSHA); !errors.Is(verifyError, errReleaseIdentityMismatch) {
		t.Fatalf("symlink release identity was accepted: %v", verifyError)
	}
}

func TestProductionMigrationRejectsSymlinkedReleaseRoot(t *testing.T) {
	parent := t.TempDir()
	realReleaseRoot := filepath.Join(parent, "real-release")
	if createError := os.MkdirAll(filepath.Join(realReleaseRoot, "database", "migrations"), 0o755); createError != nil {
		t.Fatal("release fixture unavailable")
	}
	if writeError := os.WriteFile(filepath.Join(realReleaseRoot, "RELEASE-SHA"), []byte(testReleaseSHA+"\n"), 0o644); writeError != nil {
		t.Fatal("release identity fixture unavailable")
	}
	linkedReleaseRoot := filepath.Join(parent, "linked-release")
	if linkError := os.Symlink(realReleaseRoot, linkedReleaseRoot); linkError != nil {
		t.Fatal("release symlink fixture unavailable")
	}
	linkedMigrations := filepath.Join(linkedReleaseRoot, "database", "migrations")
	if verifyError := verifyReleaseIdentity(linkedMigrations, testReleaseSHA); !errors.Is(verifyError, errReleaseIdentityMismatch) {
		t.Fatalf("symlink release root was accepted: %v", verifyError)
	}
}

func TestProductionMigrationRejectsSyntheticRuntimeBeforeConnection(t *testing.T) {
	environment := map[string]string{
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:5432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/does/not/matter",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}
	_, migrateError := migrateProduction([]string{
		"--migration-dir=/opt/careerpathdesk-production/releases/test/database/migrations",
		"--expected-release-sha=" + testReleaseSHA,
	}, func(name string) string { return environment[name] })
	if !errors.Is(migrateError, errProductionMigrationOnly) {
		t.Fatalf("synthetic runtime reached production migration: %v", migrateError)
	}
}

func TestProductionMigrationRejectsWrongProductionDatabaseBeforeReleaseRead(t *testing.T) {
	environment := map[string]string{
		"CAREERPATH_RUNTIME_MODE":            "production",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:5432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/does/not/matter",
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}
	_, migrateError := migrateProduction([]string{
		"--migration-dir=/does/not/exist/database/migrations",
		"--expected-release-sha=" + testReleaseSHA,
	}, func(name string) string { return environment[name] })
	if !errors.Is(migrateError, config.ErrUnsafeProductionDatabase) {
		t.Fatalf("wrong production database reached release or PostgreSQL operations: %v", migrateError)
	}
}

func TestProductionMigrationAcceptsOnlyExactSchemaNineForwardSet(t *testing.T) {
	exact := make([]migrate.Migration, 9)
	for index := range exact {
		exact[index].Version = int64(index + 1)
	}
	if validationError := validateProductionMigrations(exact); validationError != nil {
		t.Fatalf("exact schema 9 migration set was rejected: %v", validationError)
	}
	missing := append([]migrate.Migration(nil), exact[:8]...)
	if validationError := validateProductionMigrations(missing); !errors.Is(validationError, errProductionMigrationSetMismatch) {
		t.Fatalf("incomplete migration set was accepted: %v", validationError)
	}
	extra := append(append([]migrate.Migration(nil), exact...), migrate.Migration{Version: 10})
	if validationError := validateProductionMigrations(extra); !errors.Is(validationError, errProductionMigrationSetMismatch) {
		t.Fatalf("unreviewed migration set was accepted: %v", validationError)
	}
}
