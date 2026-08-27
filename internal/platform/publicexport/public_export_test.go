/*
Package publicexport freezes repository-level facts that contributors and Go tooling observe.
Run with: go test ./internal/platform/publicexport -count=1
*/
package publicexport

import (
	"os"      // Read the exact module metadata shipped in the repository.
	"strings" // Match the one approved public module declaration.
	"testing" // Express the public repository contract.
)

// --- Publish one canonical Go module path ---

func TestModuleUsesPublicGitHubIdentity(t *testing.T) {
	goModule, readError := os.ReadFile("../../../go.mod") // The package sits three directories below the repository root.
	if readError != nil {
		t.Fatalf("read public go.mod: %v", readError)
	}

	if !strings.HasPrefix(string(goModule), "module github.com/confidence-huang/careerpathdesk-backend\n") {
		t.Fatal("go.mod does not publish the CareerPathDesk GitHub module path")
	}
}
