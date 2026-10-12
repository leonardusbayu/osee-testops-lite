package auth

import (
	"context"
	"html/template"
	"net/http"
)

// NewParticipantHandler is an opt-in presentation adapter; defaults retain the JSON API.
func NewParticipantHandler(s *Service, origin string, page *template.Template, demo func(context.Context) (string, error)) (http.Handler, error) {
	return newLocalHandler(s, origin, page, demo)
}

func (s *Service) RequestCSRF(r *http.Request) (string, error) {
	if _, err := s.Resolve(r.Context(), r); err != nil {
		return "", err
	}
	token, err := uniqueCookie(r, SessionCookieName)
	if err != nil {
		return "", err
	}
	return s.sessionCSRF(token), nil
}
func (h *localHandler) loginFailure(w http.ResponseWriter, r *http.Request, err error) {
	if h.page == nil {
		errorResponse(w, err)
		return
	}
	status := http.StatusServiceUnavailable
	message := "Sign-in is temporarily unavailable. Try again shortly."
	if err == ErrUnauthenticated {
		status = http.StatusUnauthorized
		message = "That invitation is invalid or expired. Ask your organiser for a new code."
	}
	if err == ErrForbidden {
		status = http.StatusForbidden
		message = "This sign-in request could not be verified. Refresh the page and try again."
	}
	h.renderLogin(w, r, status, message)
}
