package integrations

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrLynkInvalid      = errors.New("invalid LYNK financial observation")
	ErrLynkUnauthorized = errors.New("LYNK signature verification failed")
)

// LynkPaymentObservation is only a vendor-digest-checked financial tuple for a
// configured IDR merchant. NetAmountIDR is the seller's grandTotal after fees,
// not the advertised exam price, gross amount, participant allocation or paid
// seat. No unsigned currency, customer, item, status or timestamp is returned.
//
// LYNK's delimiter-free concatenation does not authenticate field boundaries.
// A trusted provider-reference mapping must constrain the tuple before any
// allocation. This observation is not independent proof of settled payment.
type LynkPaymentObservation struct {
	RefID        string `json:"ref_id"`
	MessageID    string `json:"message_id"`
	NetAmountIDR int64  `json:"net_amount_idr"`
}

// VerifyLynkPayment implements the vendor's X-Lynk-Signature contract:
// SHA256(decimal grandTotal + refId + message_id + merchant key), not HMAC and
// not a signature over the complete JSON payload. Comparison is constant-time.
// Current merchant-linked reference:
// https://documenter.getpostman.com/view/43601478/2sBXc8o3kn
//
// This pure verifier has no HTTP route, persistence or business side effect.
// It accepts a replay with the same signed tuple; it cannot verify freshness
// from the unsigned createdAt field. Durable event/transaction deduplication,
// an authenticated queue and a trusted reference map are required separately
// before a live payment receiver can be mounted. Envelope success markers are
// format checks only, because the vendor digest does not cover them.
// A native LYNK callback must commit its durable receipt before HTTP 200; the
// internal normalized-event gateway's HTTP 202 is not the provider callback.
func VerifyLynkPayment(body []byte, signature string, merchantKey []byte) (LynkPaymentObservation, error) {
	var empty LynkPaymentObservation
	if len(body) == 0 || len(body) > 64*1024 || !utf8.Valid(body) || len(merchantKey) == 0 || len(merchantKey) > 4096 || !utf8.Valid(merchantKey) || lynkUniqueJSON(body) != nil {
		return empty, ErrLynkInvalid
	}
	var payload struct {
		Event string `json:"event"`
		Data  struct {
			Action      string `json:"message_action"`
			Code        string `json:"message_code"`
			MessageID   string `json:"message_id"`
			MessageData struct {
				RefID  string `json:"refId"`
				Totals struct {
					GrandTotal json.RawMessage `json:"grandTotal"`
				} `json:"totals"`
			} `json:"message_data"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Event != "payment.received" || payload.Data.Action != "SUCCESS" || payload.Data.Code != "0" || !lynkReference(payload.Data.MessageID) || !lynkReference(payload.Data.MessageData.RefID) {
		return empty, ErrLynkInvalid
	}
	amountText := string(payload.Data.MessageData.Totals.GrandTotal)
	if len(amountText) == 0 || len(amountText) > 10 || amountText[0] < '1' || amountText[0] > '9' {
		return empty, ErrLynkInvalid
	}
	for _, digit := range amountText {
		if digit < '0' || digit > '9' {
			return empty, ErrLynkInvalid
		}
	}
	amount, err := strconv.ParseInt(amountText, 10, 64)
	// Application intake bound, not a claimed provider/account limit. It covers
	// the requested 100-seat session totals and requires review if exceeded.
	if err != nil || amount < 1 || amount > 1_000_000_000 {
		return empty, ErrLynkInvalid
	}
	if len(signature) != sha256.Size*2 {
		return empty, ErrLynkUnauthorized
	}
	supplied, err := hex.DecodeString(signature)
	if err != nil {
		return empty, ErrLynkUnauthorized
	}
	digest := sha256.New()
	_, _ = io.WriteString(digest, amountText)
	_, _ = io.WriteString(digest, payload.Data.MessageData.RefID)
	_, _ = io.WriteString(digest, payload.Data.MessageID)
	_, _ = digest.Write(merchantKey)
	if subtle.ConstantTimeCompare(digest.Sum(nil), supplied) != 1 {
		return empty, ErrLynkUnauthorized
	}
	return LynkPaymentObservation{RefID: payload.Data.MessageData.RefID, MessageID: payload.Data.MessageID, NetAmountIDR: amount}, nil
}

func lynkReference(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 33 || character > 126 {
			return false
		}
	}
	return true
}

// Reject all duplicate keys, including escaped equivalents in unsigned data,
// before json.Unmarshal can choose a conflicting interpretation. The entire
// bounded payload is checked; ignored customer/items fields do not evade it.
func lynkUniqueJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var walk func(int, string) error
	walk = func(depth int, path string) error {
		if depth > 16 {
			return ErrLynkInvalid
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrLynkInvalid
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
				canonicalKey := strings.ToLower(name)
				if err != nil || !ok || seen[canonicalKey] || !lynkCanonicalField(path, name) {
					return ErrLynkInvalid
				}
				seen[canonicalKey] = true
				if walk(depth+1, path+"."+name) != nil {
					return ErrLynkInvalid
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrLynkInvalid
			}
		case '[':
			for decoder.More() {
				if walk(depth+1, path+"[]") != nil {
					return ErrLynkInvalid
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrLynkInvalid
			}
		default:
			return ErrLynkInvalid
		}
		return nil
	}
	if walk(0, "") != nil {
		return ErrLynkInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrLynkInvalid
	}
	return nil
}

// encoding/json matches struct tags case-insensitively. Only canonical vendor
// names may supply the verified tuple; case aliases cannot override its fields.
func lynkCanonicalField(path, name string) bool {
	var names []string
	switch path {
	case "":
		names = []string{"event", "data"}
	case ".data":
		names = []string{"message_action", "message_code", "message_id", "message_data"}
	case ".data.message_data":
		names = []string{"refId", "totals"}
	case ".data.message_data.totals":
		names = []string{"grandTotal"}
	}
	for _, canonical := range names {
		if strings.EqualFold(name, canonical) && name != canonical {
			return false
		}
	}
	return true
}
