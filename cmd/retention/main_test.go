package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionArgumentsOnlyAcceptFrozenModes(t *testing.T) {
	asOf := "2026-08-08T00:00:00Z"
	dryRun, parseError := parseArguments([]string{"--mode=dry-run", "--as-of=" + asOf})
	if parseError != nil || dryRun.mode != "dry-run" || !dryRun.asOf.Equal(time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("valid dry-run arguments failed: %#v %v", dryRun, parseError)
	}
	if _, parseError := parseArguments([]string{"--mode=execute", "--confirmation-file=/run/confirmation", "--force"}); parseError == nil {
		t.Fatal("retention command accepted --force")
	}
	if _, parseError := parseArguments([]string{"--mode=execute", "--as-of=" + asOf, "--confirmation-file=/run/confirmation"}); parseError == nil {
		t.Fatal("execute accepted an operator-controlled as-of outside the confirmation")
	}
}

func TestRetentionConfirmationRequiresFresh0600ExactSummary(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	path := filepath.Join(directory, "retention-confirmation")
	body := []byte(`{"owner_account_id":"A-syntheticowner01","as_of":"2026-08-08T00:00:00Z","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	if writeError := os.WriteFile(path, body, 0o600); writeError != nil {
		t.Fatal("confirmation fixture unavailable")
	}
	if timeError := os.Chtimes(path, now.Add(-5*time.Minute), now.Add(-5*time.Minute)); timeError != nil {
		t.Fatal("confirmation fixture timestamp unavailable")
	}
	confirmation, readError := readConfirmation(path, now)
	if readError != nil || confirmation.ownerAccountID != "A-syntheticowner01" || confirmation.digest == "" {
		t.Fatalf("fresh protected confirmation failed: %#v %v", confirmation, readError)
	}
	if chmodError := os.Chmod(path, 0o640); chmodError != nil {
		t.Fatal("confirmation fixture permissions unavailable")
	}
	if _, readError := readConfirmation(path, now); readError == nil {
		t.Fatal("group-readable confirmation was accepted")
	}
	if chmodError := os.Chmod(path, 0o600); chmodError != nil {
		t.Fatal("confirmation fixture permissions unavailable")
	}
	if timeError := os.Chtimes(path, now.Add(-11*time.Minute), now.Add(-11*time.Minute)); timeError != nil {
		t.Fatal("confirmation fixture timestamp unavailable")
	}
	if _, readError := readConfirmation(path, now); readError == nil {
		t.Fatal("stale confirmation was accepted")
	}
	freshPath := filepath.Join(directory, "fresh-confirmation")
	if writeError := os.WriteFile(freshPath, body, 0o600); writeError != nil {
		t.Fatal("fresh confirmation fixture unavailable")
	}
	if timeError := os.Chtimes(freshPath, now.Add(-time.Minute), now.Add(-time.Minute)); timeError != nil {
		t.Fatal("fresh confirmation fixture timestamp unavailable")
	}
	symlinkPath := filepath.Join(directory, "confirmation-link")
	if symlinkError := os.Symlink(freshPath, symlinkPath); symlinkError != nil {
		t.Fatal("confirmation symlink fixture unavailable")
	}
	if _, readError := readConfirmation(symlinkPath, now); readError == nil {
		t.Fatal("symlink confirmation was accepted")
	}
}
