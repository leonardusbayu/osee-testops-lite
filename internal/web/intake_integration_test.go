package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/intake"
	"strings"
	"testing"
	"time"
)

func TestIntakePortalReadsOwnSeparateDraftAttemptsWithoutActivatingRoutes(t *testing.T) {
	store := portalStore(t)
	_, participant, cookie := portalIdentity(t, store, "participant", "synthetic-intake@example.invalid")
	session, _ := core.NewID()
	if _, err := store.Pool.Exec(context.Background(), "insert into sessions(id,starts_at,cutoff_at,capacity) values($1,now()+interval '2 days',now()+interval '1 day',20)", session); err != nil {
		t.Fatal(err)
	}
	authority := auth.NewService(store, nil)
	service := intake.NewService(authority)
	req := httptest.NewRequest("POST", localOrigin+"/internal-intake-test", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", localOrigin)
	csrf, err := authority.RequestCSRF(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	var attempts []core.ID
	consent := false
	handler := authority.RequireIntake(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, suffix := range []string{"first", "second"} {
			registration, err := service.Submit(r.Context(), core.IntakeCommand{EventReference: suffix, OrderReference: suffix, SessionID: session, ScheduleVersion: 1, ProductReference: "synthetic-test", ParticipantID: participant, Name: "Synthetic Participant", Email: "new-contact@example.invalid", CommunicationConsent: &consent, ConsentVersion: "synthetic-consent", ConsentedAt: time.Now().UTC().Add(-time.Minute)})
			if err != nil {
				t.Fatalf("expected source-composed intake: %v", err)
			}
			attempts = append(attempts, registration.ID)
		}
		w.WriteHeader(204)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 204 || len(attempts) != 2 || attempts[0] == attempts[1] {
		t.Fatal("intake boundary did not persist separate own attempts")
	}
	portal, err := LocalRouter(store, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	for _, hx := range []bool{false, true} {
		page := portalRead(portal, "/portal?view=attempts", cookie, hx)
		if page.Code != 200 {
			t.Fatalf("own attempts unavailable: %d", page.Code)
		}
		for _, attempt := range attempts {
			if !strings.Contains(page.Body.String(), string(attempt)[:8]) {
				t.Fatal("real own attempt absent from participant response")
			}
		}
		if !strings.Contains(page.Body.String(), "Draft") || strings.Contains(page.Body.String(), "Confirmed") {
			t.Fatal("draft intake must not display confirmed registration")
		}
	}
	for _, path := range []string{"/intake", "/api/intake", "/partner/webhook", "/forms/import"} {
		request := httptest.NewRequest("POST", localOrigin+path, strings.NewReader("role=owner&partner_id=forged"))
		request.AddCookie(cookie)
		request.Header.Set("Origin", localOrigin)
		out := httptest.NewRecorder()
		portal.ServeHTTP(out, request)
		if out.Code != 404 && out.Code != 405 && out.Code != 403 {
			t.Errorf("unapproved ingress exposed: %s %d", path, out.Code)
		}
	}
}
