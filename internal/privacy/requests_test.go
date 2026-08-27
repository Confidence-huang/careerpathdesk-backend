package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport"
)

func TestPrivacyRequestRegistrationAndOwnerResolution(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "privacy_requests")
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	sequence := 0
	commands, constructionError := NewRequestCommands(connection, func() time.Time { return now }, func(prefix string) (string, error) {
		sequence++
		return prefix + "-syntheticprivacyrequest" + string(rune('a'+sequence)), nil
	})
	if constructionError != nil {
		t.Fatalf("privacy request commands unavailable: %v", constructionError)
	}
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: stringPointer("T-syntheticcoach01")}
	created, createError := commands.Create(context.Background(), staff, "R-syntheticprivacycreate01", "synthetic-privacy-create-key-01", CreateRequestInput{StudentID: "S-syntheticstudent01", RequestType: "deletion"})
	if createError != nil || created.Status != "received" || created.ReceivedByAccountID != staff.ID {
		t.Fatalf("staff could not register scoped privacy request: %#v %v", created, createError)
	}
	replayed, replayError := commands.Create(context.Background(), staff, "R-syntheticprivacycreate02", "synthetic-privacy-create-key-01", CreateRequestInput{StudentID: "S-syntheticstudent01", RequestType: "deletion"})
	if replayError != nil || replayed.ID != created.ID {
		t.Fatalf("privacy request retry did not replay once: %#v %v", replayed, replayError)
	}
	if _, conflictError := commands.Create(context.Background(), staff, "R-syntheticprivacycreate03", "synthetic-privacy-create-key-01", CreateRequestInput{StudentID: "S-syntheticstudent01", RequestType: "access"}); !errors.Is(conflictError, ErrIdempotencyConflict) {
		t.Fatalf("privacy request idempotency conflict was accepted: %v", conflictError)
	}
	if _, completeError := commands.Complete(context.Background(), staff, "R-syntheticprivacycomplete01", created.ID, CompleteRequestInput{Decision: "completed", Version: created.Version}); !errors.Is(completeError, ErrForbidden) {
		t.Fatalf("staff completed privacy request: %v", completeError)
	}

	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	requests, listError := commands.List(context.Background(), owner)
	if listError != nil || len(requests) != 1 || requests[0].ID != created.ID {
		t.Fatalf("owner request queue diverged: %#v %v", requests, listError)
	}
	completed, completeError := commands.Complete(context.Background(), owner, "R-syntheticprivacycomplete02", created.ID, CompleteRequestInput{Decision: "completed", Version: created.Version})
	if completeError != nil || completed.Status != "completed" || completed.CompletedAt == nil {
		t.Fatalf("owner completion failed: %#v %v", completed, completeError)
	}
}

func TestPrivacyRequestRefusalRequiresNonSensitiveReason(t *testing.T) {
	connection := testsupport.OpenDatabase(t, "privacy_requests")
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	sequence := 0
	commands, _ := NewRequestCommands(connection, func() time.Time { return now }, func(prefix string) (string, error) {
		sequence++
		return prefix + "-syntheticprivacyrefusal" + string(rune('a'+sequence)), nil
	})
	staff := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: stringPointer("T-syntheticcoach01")}
	created, createError := commands.Create(context.Background(), staff, "R-syntheticprivacyrefuse01", "synthetic-privacy-refuse-key-01", CreateRequestInput{StudentID: "S-syntheticstudent01", RequestType: "access"})
	if createError != nil {
		t.Fatalf("privacy request setup failed: %v", createError)
	}
	owner := auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	if _, refusalError := commands.Complete(context.Background(), owner, "R-syntheticprivacyrefuse02", created.ID, CompleteRequestInput{Decision: "refused", Version: created.Version}); !errors.Is(refusalError, ErrInvalidInput) {
		t.Fatalf("refusal without category and note was accepted: %v", refusalError)
	}
	refused, refusalError := commands.Complete(context.Background(), owner, "R-syntheticprivacyrefuse03", created.ID, CompleteRequestInput{Decision: "refused", ReasonCategory: "identity_not_verified", Note: "Request identity could not be verified.", Version: created.Version})
	if refusalError != nil || refused.Status != "refused" || refused.ReasonCategory == nil || refused.Note == nil {
		t.Fatalf("classified refusal failed: %#v %v", refused, refusalError)
	}
}

func stringPointer(value string) *string { return &value }
