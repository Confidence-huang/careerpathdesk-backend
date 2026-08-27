package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapOwnerArgumentsAreExactProtectedFileInputs(t *testing.T) {
	options, parseError := parseBootstrapOwnerArguments([]string{
		"--username-file=/run/careerpathdesk-production/bootstrap-owner-username",
		"--display-name-file=/run/careerpathdesk-production/bootstrap-owner-display-name",
		"--password-file=/run/careerpathdesk-production/bootstrap-owner-password",
	})
	if parseError != nil || options.usernameFile == "" || options.displayNameFile == "" || options.passwordFile == "" {
		t.Fatalf("valid bootstrap arguments failed: %#v %v", options, parseError)
	}
	invalid := [][]string{
		{},
		{"--username-file=/run/u", "--display-name-file=/run/d"},
		{"--username-file=relative", "--display-name-file=/run/d", "--password-file=/run/p"},
		{"--username-file=/run/u", "--display-name-file=/run/d", "--password-file=/run/p"},
		{"--username-file=/run/u", "--display-name-file=/run/d", "--password-file=/run/p", "--force"},
	}
	for _, arguments := range invalid {
		if _, invalidError := parseBootstrapOwnerArguments(arguments); !errors.Is(invalidError, errInvalidBootstrapArguments) {
			t.Fatalf("unsafe bootstrap arguments were accepted: %#v (%v)", arguments, invalidError)
		}
	}
}

func TestBootstrapOwnerFilesRequireOwner0600RegularNoFollow(t *testing.T) {
	directory := t.TempDir()
	protectedPath := filepath.Join(directory, "protected")
	if writeError := os.WriteFile(protectedPath, []byte("one-time-value\n"), 0o600); writeError != nil {
		t.Fatal("protected fixture unavailable")
	}
	currentUID := uint32(os.Geteuid())
	value, readError := readBootstrapValue(protectedPath, currentUID)
	if readError != nil || value != "one-time-value" {
		t.Fatalf("protected bootstrap value failed: %q %v", value, readError)
	}
	if _, readError := readBootstrapValue(protectedPath, currentUID+1); !errors.Is(readError, errInvalidBootstrapFile) {
		t.Fatalf("wrong-owner bootstrap value was accepted: %v", readError)
	}
	if chmodError := os.Chmod(protectedPath, 0o640); chmodError != nil {
		t.Fatal("permission fixture unavailable")
	}
	if _, readError := readBootstrapValue(protectedPath, currentUID); !errors.Is(readError, errInvalidBootstrapFile) {
		t.Fatalf("broad bootstrap file was accepted: %v", readError)
	}
	if chmodError := os.Chmod(protectedPath, 0o600); chmodError != nil {
		t.Fatal("permission fixture unavailable")
	}
	linkPath := filepath.Join(directory, "linked")
	if linkError := os.Symlink(protectedPath, linkPath); linkError != nil {
		t.Fatal("symlink fixture unavailable")
	}
	if _, readError := readBootstrapValue(linkPath, currentUID); !errors.Is(readError, errInvalidBootstrapFile) {
		t.Fatalf("symlink bootstrap file was accepted: %v", readError)
	}
}

func TestBootstrapOwnerRejectsSyntheticRuntimeWithoutReadingInputs(t *testing.T) {
	secretMarker := "must-not-appear-in-error"
	environment := map[string]string{
		"CAREERPATH_RUNTIME_MODE":            "synthetic",
		"CAREERPATH_DATABASE_URL":            "postgres://careerpathdesk@127.0.0.1:5432/careerpathdesk_synthetic?sslmode=disable",
		"CAREERPATH_DATABASE_PASSWORD_FILE":  "/does/not/matter/" + secretMarker,
		"CAREERPATH_EXPECTED_SCHEMA_VERSION": "9",
	}
	_, bootstrapError := runBootstrapOwner([]string{
		"--username-file=" + bootstrapUsernamePath,
		"--display-name-file=" + bootstrapDisplayNamePath,
		"--password-file=" + bootstrapPasswordPath,
	}, func(name string) string { return environment[name] }, 0)
	if !errors.Is(bootstrapError, errBootstrapProductionOnly) {
		t.Fatalf("synthetic runtime reached owner input files: %v", bootstrapError)
	}
	if strings.Contains(bootstrapError.Error(), secretMarker) {
		t.Fatal("bootstrap error exposed input content")
	}
}
