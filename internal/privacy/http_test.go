package privacy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/httpx"
	"github.com/confidence-huang/careerpathdesk-backend/internal/testsupport"
)

func TestPrivacyRequestHTTPRegistersStaffAndResolvesAsOwner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	connection := testsupport.OpenDatabase(t, "privacy_http")
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	sequence := 0
	commands, _ := NewRequestCommands(connection, func() time.Time { return now }, func(prefix string) (string, error) {
		sequence++
		return prefix + "-syntheticprivacyhttp" + string(rune('a'+sequence)), nil
	})
	actor := auth.Account{ID: "A-syntheticstaff01", Role: "staff", State: "active", StaffProfileID: stringPointer("T-syntheticcoach01")}
	entry, constructionError := NewHTTP(commands, func(*gin.Context) (auth.Account, error) { return actor, nil })
	if constructionError != nil {
		t.Fatalf("privacy HTTP unavailable: %v", constructionError)
	}
	router := gin.New()
	router.Use(httpx.Foundation(func() (string, error) { return "R-syntheticprivacyhttp01", nil }))
	entry.Register(router.Group("/api/v2"))

	create := httptest.NewRequest(http.MethodPost, "/api/v2/privacy-requests", strings.NewReader(`{"student_id":"S-syntheticstudent01","request_type":"deletion"}`))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "synthetic-privacy-http-key-01")
	createRecorder := httptest.NewRecorder()
	router.ServeHTTP(createRecorder, create)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("staff privacy request HTTP failed: status=%d body=%s", createRecorder.Code, createRecorder.Body.String())
	}

	actor = auth.Account{ID: "A-syntheticowner01", Role: "owner", State: "active"}
	listRecorder := httptest.NewRecorder()
	router.ServeHTTP(listRecorder, httptest.NewRequest(http.MethodGet, "/api/v2/privacy-requests", nil))
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), "syntheticprivacyhttp") {
		t.Fatalf("owner privacy queue HTTP failed: status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
}
