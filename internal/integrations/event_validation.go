package integrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"unicode/utf8"

	"osee-testops-lite/internal/core"
)

type normalizedEvent struct {
	Source   string          `json:"source"`
	EventID  string          `json:"event_id"`
	Kind     string          `json:"kind"`
	ObjectID core.ID         `json:"object_id"`
	Payload  json.RawMessage `json:"payload"`
}

var eventReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

func decodeEvent(source string, body []byte) (normalizedEvent, string, error) {
	var event normalizedEvent
	if !utf8.Valid(body) || uniqueJSON(body) != nil {
		return event, "", ErrEventInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&event) != nil || event.Source != source || !eventReference.MatchString(event.EventID) || len(event.Payload) > 24*1024 {
		return event, "", ErrEventInvalid
	}
	if _, err := core.ParseID(string(event.ObjectID)); err != nil || event.ObjectID == "00000000-0000-0000-0000-000000000000" {
		return event, "", ErrEventInvalid
	}
	allowed := false
	for _, kind := range eventKinds[source] {
		if event.Kind == kind {
			allowed = true
			break
		}
	}
	if !allowed {
		return event, "", ErrEventInvalid
	}
	var payload map[string]any
	decoder = json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.UseNumber()
	if decoder.Decode(&payload) != nil || payload == nil {
		return event, "", ErrEventInvalid
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return event, "", ErrEventInvalid
	}
	event.Payload = canonical
	canonical, err = json.Marshal(event)
	if err != nil {
		return event, "", ErrEventInvalid
	}
	hash := sha256.Sum256(canonical)
	return event, hex.EncodeToString(hash[:]), nil
}

// Reject duplicate keys and excessive nesting before JSON decoding can discard evidence.
func uniqueJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return ErrEventInvalid
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrEventInvalid
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return ErrEventInvalid
				}
				if depth == 0 && name != "source" && name != "event_id" && name != "kind" && name != "object_id" && name != "payload" {
					return ErrEventInvalid
				}
				seen[name] = true
				if walk(depth+1) != nil {
					return ErrEventInvalid
				}
			}
		case '[':
			for decoder.More() {
				if walk(depth+1) != nil {
					return ErrEventInvalid
				}
			}
		default:
			return ErrEventInvalid
		}
		_, err = decoder.Token()
		if err != nil {
			return ErrEventInvalid
		}
		return nil
	}
	if walk(0) != nil {
		return ErrEventInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrEventInvalid
	}
	return nil
}
