package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"github.com/jackc/pgx/v5/pgtype"
	"html/template"
	"net/http"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/demo"
	"strings"
	"time"
	_ "time/tzdata"
)

//go:embed ui/*
var uiFiles embed.FS
var uiTemplates = template.Must(template.New("ui").ParseFS(uiFiles, "ui/*.html"))
var wib = func() *time.Location {
	location, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		panic("required display timezone unavailable")
	}
	return location
}()

const portalCSP = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"

type portalAttempt struct {
	ID                                                                 core.ID
	Reference, Registration, Attendance, Result, Date, Time, Readiness string
	Scheduled, Ready                                                   bool
}
type portalData struct {
	View, Title, Email, CSRF, Error string
	Demo                            bool
	Attempts                        []portalAttempt
	Total, Scheduled, Released      int
}

func newPortalRouter(store *db.Store, origin string, enableDemo bool) (http.Handler, error) {
	if store == nil || store.Pool == nil {
		return nil, auth.ErrUnavailable
	}
	service := auth.NewService(store, nil)
	var issue func(context.Context) (string, error)
	if enableDemo {
		issue = func(ctx context.Context) (string, error) { return demo.Issue(ctx, store) }
	}
	gateway, err := auth.NewParticipantHandler(service, origin, uiTemplates.Lookup("login.html"), issue)
	if err != nil {
		return nil, err
	}
	health := foundationRouter(portalSchemaPinger{store: store, demo: enableDemo}, false)
	mux := http.NewServeMux()
	mux.Handle("/auth/", gateway)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = uiTemplates.ExecuteTemplate(w, "welcome.html", struct{ Demo bool }{enableDemo})
	})
	mux.HandleFunc("GET /assets/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		kind := ""
		switch name {
		case "app.css":
			kind = "text/css; charset=utf-8"
		case "favicon.svg":
			kind = "image/svg+xml"
		case "app.js", "htmx.min.js":
			kind = "text/javascript; charset=utf-8"
		default:
			http.NotFound(w, r)
			return
		}
		data, err := uiFiles.ReadFile("ui/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", kind)
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /portal", func(w http.ResponseWriter, r *http.Request) {
		participant, err := service.Resolve(r.Context(), r)
		if err != nil {
			portalFailure(w, r, err)
			return
		}
		if participant.Role != core.RoleParticipant {
			portalFailure(w, r, auth.ErrForbidden)
			return
		}
		view := "overview"
		values := r.URL.Query()
		for key := range values {
			if key != "view" {
				portalFailure(w, r, auth.ErrForbidden)
				return
			}
		}
		if v, exists := values["view"]; exists {
			if len(v) != 1 {
				renderUIError(w, r, 400, "Choose a page", "Use the portal navigation to choose a valid page.")
				return
			}
			view = v[0]
		}
		titles := map[string]string{"overview": "Your overview", "attempts": "My attempts", "schedule": "Your schedule", "results": "Your results", "help": "Help & next steps"}
		title, valid := titles[view]
		if !valid {
			renderUIError(w, r, 400, "Choose a page", "Use the portal navigation to choose a valid page.")
			return
		}
		data, err := readPortal(r.Context(), store, r, participant)
		if err != nil {
			portalFailure(w, r, err)
			return
		}
		data.View = view
		data.Title = title
		data.CSRF, err = service.RequestCSRF(r)
		if err != nil {
			portalFailure(w, r, err)
			return
		}
		templateName := "portal.html"
		if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true" {
			templateName = "panel"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = uiTemplates.ExecuteTemplate(w, templateName, data)
	})
	mux.Handle("/health/", health)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", portalCSP)
		w.Header().Add("Vary", "HX-Request")
		w.Header().Add("Vary", "HX-History-Restore-Request")
		internalProbe := r.TLS == nil && r.Host == "localhost" && (r.URL.Path == "/health/live" || r.URL.Path == "/health/ready")
		if (r.Host != strings.TrimPrefix(origin, "http://") || r.TLS != nil) && !internalProbe {
			http.Error(w, "forbidden", 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}
func readPortal(ctx context.Context, store *db.Store, r *http.Request, p core.Principal) (portalData, error) {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil {
		return portalData{}, auth.ErrUnauthenticated
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	// Recheck current session/role/binding in the same query snapshot as all owned rows.
	rows, err := store.Pool.Query(ctx, `SELECT left(coalesce(p.email,''),254),
 EXISTS(SELECT 1 FROM development_fixtures d WHERE d.name='participant-demo' AND d.kind='local-synthetic' AND d.participant_id=p.id AND d.principal_id=a.id),
 coalesce(r.id::text,''),coalesce(r.registration_state,''),coalesce(r.attendance_state,''),coalesce(r.result_state,''),s.starts_at,coalesce(s.host_ready,false)
 FROM participants p JOIN auth_principals a ON a.participant_id=p.id AND a.role='participant' AND a.enabled
 JOIN auth_sessions proof ON proof.principal_id=a.id AND proof.token_hash=$3 AND proof.revoked_at IS NULL AND proof.created_at<=now() AND proof.expires_at>now()
 LEFT JOIN registrations r ON r.participant_id=p.id LEFT JOIN sessions s ON s.id=r.session_id
 WHERE p.id=$1 AND a.id=$2 ORDER BY s.starts_at ASC NULLS LAST,r.created_at DESC LIMIT 100`, p.ParticipantID, p.UserID, hash[:])
	if err != nil {
		return portalData{}, auth.ErrUnavailable
	}
	defer rows.Close()
	var data portalData
	found := false
	for rows.Next() {
		var id, registration, attendance, result string
		var start pgtype.Timestamptz
		var ready bool
		if err = rows.Scan(&data.Email, &data.Demo, &id, &registration, &attendance, &result, &start, &ready); err != nil {
			return portalData{}, auth.ErrUnavailable
		}
		found = true
		if id == "" {
			continue
		}
		attempt := portalAttempt{ID: core.ID(id), Reference: strings.ToUpper(id[:8]), Registration: statusLabel(registration), Attendance: statusLabel(attendance), Result: statusLabel(result), Scheduled: start.Valid, Ready: ready, Readiness: "Host not ready"}
		if ready {
			attempt.Readiness = "Host ready"
		}
		if start.Valid {
			attempt.Date = start.Time.In(wib).Format("Mon, 02 Jan 2006")
			attempt.Time = start.Time.In(wib).Format("15:04") + " WIB"
			data.Scheduled++
		} else {
			attempt.Date = "Not scheduled"
			attempt.Time = "A session hasn't been assigned yet"
		}
		if result == "RELEASED" {
			data.Released++
		}
		data.Attempts = append(data.Attempts, attempt)
		data.Total++
	}
	if err = rows.Err(); err != nil {
		return portalData{}, auth.ErrUnavailable
	}
	if !found {
		return portalData{}, auth.ErrUnauthenticated
	}
	return data, nil
}
func statusLabel(raw string) string {
	switch raw {
	case "DRAFT":
		return "Draft"
	case "ELIGIBLE":
		return "Eligible"
	case "CONFIRMED":
		return "Confirmed"
	case "CANCELLED":
		return "Cancelled"
	case "NOT_CHECKED_IN":
		return "Not checked in"
	case "CHECKED_IN":
		return "Checked in"
	case "ATTENDANCE_VERIFIED":
		return "Attendance verified"
	case "COMPLETED":
		return "Completed"
	case "NO_SHOW":
		return "No show"
	case "NOT_RECEIVED":
		return "Not received"
	case "VALIDATED":
		return "Validated"
	case "HOLD":
		return "On hold"
	case "APPROVED":
		return "Approved"
	case "RELEASED":
		return "Released"
	default:
		return "Unavailable"
	}
}
func portalFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, auth.ErrUnauthenticated) {
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/auth/login?expired=1")
			w.WriteHeader(401)
			return
		}
		http.Redirect(w, r, "/auth/login?expired=1", 303)
		return
	}
	if errors.Is(err, auth.ErrForbidden) {
		renderUIError(w, r, 403, "This page isn't available", "You can only view your own participant portal. Staff and partner tools are not enabled here.")
		return
	}
	renderUIError(w, r, 503, "Temporarily unavailable", "We couldn't load your portal. Your records have not been changed. Try again shortly.")
}
func renderUIError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	name := "error.html"
	if r.Header.Get("HX-Request") == "true" {
		name = "error-panel"
	}
	_ = uiTemplates.ExecuteTemplate(w, name, struct{ Title, Message string }{title, message})
}

type portalSchemaPinger struct {
	store *db.Store
	demo  bool
}

func (p portalSchemaPinger) Ping(ctx context.Context) error {
	if err := (authSchemaPinger{store: p.store}).Ping(ctx); err != nil {
		return err
	}
	var ready bool
	if err := p.store.Pool.QueryRow(ctx, "select exists(select 1 from schema_versions where version=3) AND to_regclass('development_fixtures') IS NOT NULL").Scan(&ready); err != nil || !ready {
		return errors.New("portal schema unavailable")
	}
	if p.demo {
		if _, err := demo.Principal(ctx, p.store); err != nil {
			return errors.New("demo fixture unavailable")
		}
	}
	return nil
}
