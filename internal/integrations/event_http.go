package integrations

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

func eventReply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (gateway *EventGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		eventReply(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || (r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity") {
		eventReply(w, http.StatusUnsupportedMediaType, map[string]string{"error": "json_required"})
		return
	}
	for _, name := range []string{"X-OSEE-Source", "X-OSEE-Timestamp", "X-OSEE-Signature"} {
		if len(r.Header.Values(name)) != 1 {
			eventReply(w, http.StatusUnauthorized, map[string]string{"error": "authentication_failed"})
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxEventBytes))
	if err != nil {
		code := http.StatusBadRequest
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			code = http.StatusRequestEntityTooLarge
		}
		eventReply(w, code, map[string]string{"error": "invalid_body"})
		return
	}
	receipt, err := gateway.Receive(r.Context(), r.Header.Get("X-OSEE-Source"), r.Header.Get("X-OSEE-Timestamp"), r.Header.Get("X-OSEE-Signature"), body)
	if err != nil {
		status, reason := http.StatusServiceUnavailable, "integration_event_unavailable"
		switch {
		case errors.Is(err, ErrEventUnauthorized):
			status, reason = http.StatusUnauthorized, "authentication_failed"
		case errors.Is(err, ErrEventInvalid):
			status, reason = http.StatusBadRequest, "invalid_event"
		case errors.Is(err, ErrEventTooLarge):
			status, reason = http.StatusRequestEntityTooLarge, "event_too_large"
		case errors.Is(err, ErrEventConflict):
			status, reason = http.StatusConflict, "event_identity_conflict"
		}
		eventReply(w, status, map[string]string{"error": reason})
		return
	}
	status := http.StatusAccepted
	if receipt.Replayed {
		status = http.StatusOK
	}
	eventReply(w, status, receipt)
}
