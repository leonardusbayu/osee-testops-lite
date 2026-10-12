package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/sessions"
	"osee-testops-lite/internal/testfixtures"
	"strings"
	"testing"
	"time"
)

// Exercise current real PostgreSQL schedule state through the source-composed participant HTTP portal.
func TestSessionPortalReadsRescheduleAndKeepsStaffControlsLocked(t *testing.T) {
	store := portalStore(t)
	genuine := testfixtures.NewStaff(t, store, core.RoleAdmin)
	staff, staffCookie := genuine.Principal.UserID, &http.Cookie{Name: auth.SessionCookieName, Value: genuine.Session.Token}
	_, participant, cookie := portalIdentity(t, store, "participant", "synthetic-schedule@example.invalid")
	authority := genuine.Authority
	service := sessions.NewService(authority)
	actor := genuine.Principal
	req := httptest.NewRequest("POST", localOrigin+"/internal-sessions-test", nil)
	req.Header.Set("Origin", localOrigin)
	req.AddCookie(staffCookie)
	csrf, err := authority.RequestCSRF(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	var updated core.Session
	handler := authority.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond)
		created, err := service.Create(r.Context(), actor, core.SessionCommand{StartsAt: start, CutoffAt: start.Add(-time.Hour), Capacity: 10, AssignedStaffID: staff, GuideReference: "synthetic-guide", MeetingReference: "synthetic-meeting"})
		if err != nil {
			t.Fatalf("expected source session creation: %v", err)
		}
		registration, _ := core.NewID()
		if _, err = store.Pool.Exec(r.Context(), "insert into registrations(id,participant_id,session_id,registration_state) values($1,$2,$3,'CONFIRMED')", registration, participant, created.ID); err != nil {
			t.Fatal(err)
		}
		updated, err = service.Reschedule(r.Context(), actor, created.ID, core.SessionChange{ExpectedVersion: 1, StartsAt: start.Add(24 * time.Hour), CutoffAt: start.Add(23 * time.Hour), AssignedStaffID: staff, GuideReference: "synthetic-guide-v2", MeetingReference: "synthetic-meeting-v2", Reason: "Synthetic HTTP schedule readback"})
		if err != nil {
			t.Fatalf("expected source reschedule: %v", err)
		}
		w.WriteHeader(204)
	}))
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 204 {
		t.Fatalf("synthetic staff test adapter denied: %d", out.Code)
	}
	portal, err := LocalRouter(store, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	for _, hx := range []bool{false, true} {
		page := portalRead(portal, "/portal?view=schedule", cookie, hx)
		body := html.UnescapeString(page.Body.String())
		if page.Code != 200 || !strings.Contains(body, updated.StartsAt.In(wib).Format("Mon, 02 Jan 2006")) || !strings.Contains(body, updated.StartsAt.In(wib).Format("15:04")+" WIB") || !strings.Contains(body, "Host not ready") {
			t.Error("expected current rescheduled WIB schedule in real participant response")
		}
		if strings.Contains(body, "synthetic-meeting") {
			t.Error("internal meeting reference leaked into participant access")
		}
	}
	for _, path := range []string{"/sessions", "/admin/sessions", "/staff/sessions", "/api/sessions"} {
		request := httptest.NewRequest("POST", localOrigin+path, strings.NewReader("role=owner&mfa=true"))
		request.AddCookie(staffCookie)
		request.Header.Set("Origin", localOrigin)
		request.Header.Set("X-CSRF-Token", csrf)
		denied := httptest.NewRecorder()
		portal.ServeHTTP(denied, request)
		if denied.Code != 404 && denied.Code != 405 && denied.Code != 403 {
			t.Errorf("staff mutation route unexpectedly active: %s status %d", path, denied.Code)
		}
	}
}
