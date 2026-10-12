package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"osee-testops-lite/internal/core"
)

const loginStateCookieName = "osee_completion_r1_login_state"
const staffChallengeCookieName = "osee_completion_r1_challenge"
const loginStateLifetime = 10 * time.Minute
const maxLoginBody = 2048

type localHandler struct {
	service      *Service
	origin, host string
	secure       bool
	limiter      *loginLimiter
	page         *template.Template
	demo         func(context.Context) (string, error)
}

// NewHandler is an explicit local candidate, not a production or proxy configuration.
func NewHandler(s *Service, origin string) (http.Handler, error) {
	return newLocalHandler(s, origin, nil, nil)
}
func newLocalHandler(s *Service, origin string, page *template.Template, demo func(context.Context) (string, error)) (http.Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || s == nil || s.store == nil {
		return nil, ErrUnavailable
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !loopback(u.Hostname()) || u.String() != origin {
		return nil, ErrForbidden
	}
	h := &localHandler{service: s, origin: origin, host: u.Host, secure: u.Scheme == "https", limiter: newLoginLimiter(1024), page: page, demo: demo}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", h.loginPage)
	mux.HandleFunc("POST /auth/login", h.login)
	if demo != nil {
		mux.HandleFunc("POST /auth/demo", h.login)
	}
	if page != nil {
		mux.Handle("POST /auth/signout", s.require(http.HandlerFunc(h.logout), "session"))
	}
	mux.Handle("GET /auth/me", s.require(http.HandlerFunc(h.me), "session"))
	mux.Handle("POST /auth/logout", s.require(http.HandlerFunc(h.logout), "session"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if h.page != nil {
			w.Header().Set("Referrer-Policy", "same-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		}
		if r.Host != h.host || requestOrigin(r) != h.origin {
			http.Error(w, "forbidden", 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
func sameOrigin(r *http.Request) bool {
	u, err := url.Parse(requestOrigin(r))
	return err == nil && loopback(u.Hostname()) && r.Header.Get("Origin") == requestOrigin(r) && r.Header.Get("Sec-Fetch-Site") != "cross-site"
}
func errorResponse(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	if errors.Is(err, ErrUnauthenticated) {
		status = http.StatusUnauthorized
	}
	if errors.Is(err, ErrForbidden) {
		status = http.StatusForbidden
	}
	http.Error(w, http.StatusText(status), status)
}
func (s *Service) sessionCSRF(token string) string {
	mac := hmac.New(sha256.New, s.csrfKey[:])
	mac.Write([]byte("session-csrf:" + token))
	return hex.EncodeToString(mac.Sum(nil))
}
func parseBoundedForm(w http.ResponseWriter, r *http.Request) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		http.Error(w, "invalid form", 400)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err = r.ParseForm(); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			http.Error(w, "request too large", 413)
		} else {
			http.Error(w, "invalid form", 400)
		}
		return false
	}
	return true
}
func (s *Service) validSessionCSRF(w http.ResponseWriter, r *http.Request, token string) bool {
	if !sameOrigin(r) {
		http.Error(w, "forbidden", 403)
		return false
	}
	values := r.Header.Values("X-CSRF-Token")
	if len(values) > 1 {
		http.Error(w, "forbidden", 403)
		return false
	}
	supplied := ""
	if len(values) == 1 {
		supplied = values[0]
	} else {
		if !parseBoundedForm(w, r) {
			return false
		}
		if len(r.PostForm["csrf"]) == 1 {
			supplied = r.PostForm.Get("csrf")
		}
	}
	if supplied == "" || !hmac.Equal([]byte(supplied), []byte(s.sessionCSRF(token))) {
		http.Error(w, "forbidden", 403)
		return false
	}
	return true
}
func (s *Service) require(next http.Handler, kind string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Resolve(r.Context(), r)
		if err != nil {
			errorResponse(w, err)
			return
		}
		if (kind == "staff" && !staff(p)) || (kind == "participant" && p.Role != core.RoleParticipant) {
			errorResponse(w, ErrForbidden)
			return
		}
		token, err := uniqueCookie(r, SessionCookieName)
		if err != nil {
			errorResponse(w, err)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !s.validSessionCSRF(w, r, token) {
			return
		}
		hash, err := tokenDigest(token)
		if err != nil {
			errorResponse(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), proofContextKey{}, sessionProof{service: s, hash: hash})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Service) RequireStaff(next http.Handler) http.Handler { return s.require(next, "staff") }
func (s *Service) RequireParticipant(next http.Handler) http.Handler {
	return s.require(next, "participant")
}

// AuthorizeParticipant re-resolves current authority; caller-supplied principals are not accepted.
// Partner cohorts are deliberately unavailable until a verified cohort mapping exists.
func (s *Service) AuthorizeParticipant(ctx context.Context, id core.ID) error {
	proof, err := s.proof(ctx)
	if err != nil {
		return err
	}
	if _, err = core.ParseID(string(id)); err != nil {
		return ErrForbidden
	}
	if s.store == nil {
		return ErrUnavailable
	}
	p, err := s.resolveHash(ctx, s.store.Pool, proof.hash, false)
	if err != nil {
		return err
	}
	if p.Role == core.RoleParticipant && p.ParticipantID == id {
		return nil
	}
	if staff(p) {
		return nil
	}
	return ErrForbidden
}

var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>OSEE local invitation sign-in</title></head><body><main><h1>Participant invitation sign-in</h1><p>Local candidate only. Invite delivery is not configured. Live email and MFA verification are not implemented.</p><p>Only trusted synthetic fixtures exercise this sign-in. A student number, shared contact or chat request is not a credential.</p><form method="post" action="/auth/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="token">Short-lived invitation code</label><input id="token" name="token" type="password" autocomplete="one-time-code" required maxlength="43"><button type="submit">Sign in</button></form></main></body></html>`))

func (h *localHandler) signState(payload string) string {
	mac := hmac.New(sha256.New, h.service.csrfKey[:])
	mac.Write([]byte("login-state:" + payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (h *localHandler) validState(state string) bool {
	parts := strings.Split(state, ".")
	if len(parts) != 3 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	deadline := time.Unix(expires, 0)
	if !deadline.After(now) || deadline.After(now.Add(loginStateLifetime+time.Second)) {
		return false
	}
	if _, err = tokenDigest(parts[1]); err != nil {
		return false
	}
	return hmac.Equal([]byte(state), []byte(h.signState(parts[0]+"."+parts[1])))
}
func (h *localHandler) cookie(name, value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", Expires: expires, MaxAge: maxAge, HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode}
}
func (h *localHandler) loginPage(w http.ResponseWriter, r *http.Request) {
	h.renderLogin(w, r, http.StatusOK, "")
}
func (h *localHandler) renderLogin(w http.ResponseWriter, r *http.Request, status int, message string) {
	nonce, err := newSecret()
	if err != nil {
		errorResponse(w, err)
		return
	}
	expires := time.Now().UTC().Add(loginStateLifetime)
	state := h.signState(strconv.FormatInt(expires.Unix(), 10) + "." + nonce)
	http.SetCookie(w, h.cookie(loginStateCookieName, state, expires, int(loginStateLifetime/time.Second)))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if h.page != nil {
		_ = h.page.Execute(w, struct {
			CSRF               string
			Demo               bool
			Error              string
			Expired, SignedOut bool
		}{state, h.demo != nil, message, r.URL.Query().Get("expired") == "1", r.URL.Query().Get("signedout") == "1"})
		return
	}
	if err = loginTemplate.Execute(w, struct{ CSRF string }{state}); err != nil {
		return
	}
}
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unavailable"
	}
	return ip.String()
}
func (h *localHandler) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		errorResponse(w, ErrForbidden)
		return
	}
	if !parseBoundedForm(w, r) {
		return
	}
	state, err := uniqueCookie(r, loginStateCookieName)
	if err != nil || len(r.PostForm["csrf"]) != 1 || !hmac.Equal([]byte(state), []byte(r.PostForm.Get("csrf"))) || !h.validState(state) {
		errorResponse(w, ErrForbidden)
		return
	}
	if !h.limiter.allow(peerIP(r), time.Now().UTC()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts", 429)
		return
	}
	if r.URL.Path == "/auth/demo" {
		for key, values := range r.PostForm {
			if key != "csrf" || len(values) != 1 {
				errorResponse(w, ErrForbidden)
				return
			}
		}
	} else if len(r.PostForm["token"]) != 1 {
		h.loginFailure(w, r, ErrUnauthenticated)
		return
	}
	previous := ""
	found := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == SessionCookieName {
			previous = cookie.Value
			found++
		}
	}
	if found > 1 {
		errorResponse(w, ErrForbidden)
		return
	}
	code := r.PostForm.Get("token")
	if r.URL.Path == "/auth/demo" {
		code, err = h.demo(r.Context())
		if err != nil {
			h.loginFailure(w, r, err)
			return
		}
	}
	session, err := h.service.consumeInvite(r.Context(), code, previous)
	if err != nil {
		h.loginFailure(w, r, err)
		return
	}
	http.SetCookie(w, h.cookie(SessionCookieName, session.token, session.expiresAt, int(sessionLifetime/time.Second)))
	http.SetCookie(w, h.cookie(loginStateCookieName, "", time.Unix(1, 0), -1))
	landing := "/auth/me"
	if h.page != nil {
		landing = "/portal"
	}
	http.Redirect(w, r, landing, http.StatusSeeOther)
}
func (h *localHandler) me(w http.ResponseWriter, r *http.Request) {
	p, err := h.service.Resolve(r.Context(), r)
	if err != nil {
		errorResponse(w, err)
		return
	}
	token, err := uniqueCookie(r, SessionCookieName)
	if err != nil {
		errorResponse(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Principal core.Principal `json:"principal"`
		CSRF      string         `json:"csrf"`
	}{p, h.service.sessionCSRF(token)})
}
func (h *localHandler) logout(w http.ResponseWriter, r *http.Request) {
	token, err := uniqueCookie(r, SessionCookieName)
	if err != nil {
		errorResponse(w, err)
		return
	}
	if err = h.service.revoke(r.Context(), token); err != nil {
		errorResponse(w, err)
		return
	}
	http.SetCookie(w, h.cookie(SessionCookieName, "", time.Unix(1, 0), -1))
	if h.page != nil && r.URL.Path == "/auth/signout" {
		http.Redirect(w, r, "/auth/login?signedout=1", http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type loginBucket struct {
	start    time.Time
	attempts int
}
type loginLimiter struct {
	mu       sync.Mutex
	capacity int
	buckets  map[string]loginBucket
}

func newLoginLimiter(capacity int) *loginLimiter {
	return &loginLimiter{capacity: capacity, buckets: make(map[string]loginBucket)}
}
func (l *loginLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, bucket := range l.buckets {
		if !now.Before(bucket.start.Add(time.Minute)) {
			delete(l.buckets, key)
		}
	}
	bucket, exists := l.buckets[ip]
	if !exists {
		if len(l.buckets) >= l.capacity {
			return false
		}
		bucket = loginBucket{start: now}
	}
	if bucket.attempts >= 10 {
		return false
	}
	bucket.attempts++
	l.buckets[ip] = bucket
	return true
}
