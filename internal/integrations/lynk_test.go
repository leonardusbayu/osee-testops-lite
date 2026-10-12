package integrations

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const lynkFixtureSignature = "b12e4829e9e0e7dc1bc946ee26d6f5fe9edd04bcb1c084ec7f5bfe91b80636bd"
const lynkFixtureKey = "synthetic-merchant-key-for-unit-tests"
const lynkFixtureBody = `{"event":"payment.received","data":{"message_action":"SUCCESS","message_code":"0","message_id":"API_CALL_1744270275143115_4624014","message_data":{"refId":"0123456789abcdef0123456789abcdef","createdAt":"2025-04-10T14:30:45","customer":{"email":"fixture@example.invalid","name":"Synthetic Person","phone":"0000000000"},"items":[{"price":75000,"qty":1,"uuid":"synthetic-product","title":"Synthetic test"}],"currency":"IDR","totals":{"grandTotal":72000,"convenienceFee":-3000,"totalPrice":75000}}}}`

// Current merchant-linked docs include questions as an opaque JSON string and
// voucher/shipping/addon extras. All identity/contact/upload values here are
// synthetic; the verifier never fetches the example.invalid URL.
const lynkCurrentFixtureBody = `{
  "event":"payment.received",
  "data":{
    "message_action":"SUCCESS","message_code":"0",
    "message_data":{
      "createdAt":"2026-10-09T13:30:00",
      "customer":{"email":"fixture@example.invalid","name":"Synthetic Person","phone":"0000000000"},
      "items":[{
        "addons":[{"id":"synthetic-addon","name":"Synthetic extra","price":"50,000"}],
        "appointment_data":{},"pafId":"","price":25000,"public_affiliate_content":{},"qty":1,
        "questions":"{\"Synthetic question\":\"Synthetic answer\",\"Synthetic file\":\"https://example.invalid/upload/never-fetch\"}",
        "stock":1,"title":"Synthetic product","uuid":"synthetic-product"
      }],
      "refId":"0123456789abcdef0123456789abcdef",
      "shippingAddress":"Synthetic destination","shippingInfo":"Synthetic courier",
      "totals":{"affiliate":0,"convenienceFee":-3000,"discount":0,"grandTotal":72000,"totalAddon":50000,"totalItem":1,"totalPrice":25000,"totalShipping":0},
      "voucherCode":"SYNTHETIC_VOUCHER","voucherQuantity":999
    },
    "message_desc":"","message_id":"API_CALL_1744270275143115_4624014","message_title":""
  }
}`

func TestLynkCurrentDocumentedUnsignedExtrasRemainUntrusted(t *testing.T) {
	want := LynkPaymentObservation{RefID: "0123456789abcdef0123456789abcdef", MessageID: "API_CALL_1744270275143115_4624014", NetAmountIDR: 72000}
	for _, change := range [][2]string{
		{"unchanged-fixture-marker", "unchanged-fixture-marker"},
		{"Synthetic answer", "Forged answer"},
		{"https://example.invalid/upload/never-fetch", "https://example.invalid/forged-file"},
		{"Synthetic destination", "Forged shipping destination"},
		{"Synthetic courier", "Forged shipping info"},
		{"SYNTHETIC_VOUCHER", "FORGED_VOUCHER"},
		{`"voucherQuantity":999`, `"voucherQuantity":"unlimited"`},
		{`"voucherQuantity":999`, `"voucherQuantity":""`},
		{`"price":"50,000"`, `"price":"999,999"`},
		{`"price":25000`, `"price":999999`},
	} {
		body := strings.ReplaceAll(lynkCurrentFixtureBody, change[0], change[1])
		got, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey))
		if err != nil || got != want {
			t.Fatal("current unsigned extras changed the financial tuple")
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(encoded, &fields) != nil || len(fields) != 3 || fields["ref_id"] == nil || fields["message_id"] == nil || fields["net_amount_idr"] == nil {
			t.Fatal("unsigned current payload fields escaped the projection")
		}
	}
}

func TestLynkVerifiesDocumentedDigestAndReturnsOnlyFinancialTuple(t *testing.T) {
	observation, err := VerifyLynkPayment([]byte(lynkFixtureBody), lynkFixtureSignature, []byte(lynkFixtureKey))
	if err != nil {
		t.Fatalf("valid documented signature rejected: %v", err)
	}
	if observation.RefID != "0123456789abcdef0123456789abcdef" || observation.MessageID != "API_CALL_1744270275143115_4624014" || observation.NetAmountIDR != 72000 {
		t.Fatal("wrong authenticated financial tuple")
	}
	body, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 3 || fields["ref_id"] == nil || fields["message_id"] == nil || fields["net_amount_idr"] == nil {
		t.Fatal("output exposes unsigned payload fields")
	}
	for _, private := range []string{"Synthetic Person", "example.invalid", "synthetic-product", "75000", "createdAt", "currency", "settled", "paid"} {
		if strings.Contains(string(body), private) {
			t.Fatal("output trusts unsigned customer/product/status data")
		}
	}
}

func TestLynkUnsignedIdentityItemsAndTimestampCannotChangeOutput(t *testing.T) {
	original, err := VerifyLynkPayment([]byte(lynkFixtureBody), lynkFixtureSignature, []byte(lynkFixtureKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{"fixture@example.invalid", "attacker@example.invalid"}, {"Synthetic Person", "Forged Identity"}, {"75000", "999999999"}, {"synthetic-product", "forged-exam"}, {"2025-04-10T14:30:45", "2099-12-31T00:00:00"}, {`"currency":"IDR"`, `"currency":"USD"`}} {
		body := strings.ReplaceAll(lynkFixtureBody, change[0], change[1])
		got, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey))
		if err != nil || got != original {
			t.Fatal("unsigned value changed financial tuple")
		}
	}
}

func TestLynkModifiedSignedFieldsAndMerchantKeyReject(t *testing.T) {
	for _, change := range [][2]string{{"72000", "72001"}, {"0123456789abcdef0123456789abcdef", "1123456789abcdef0123456789abcdef"}, {"API_CALL_1744270275143115_4624014", "API_CALL_1744270275143115_4624015"}} {
		body := strings.ReplaceAll(lynkFixtureBody, change[0], change[1])
		got, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey))
		if !errors.Is(err, ErrLynkUnauthorized) || got != (LynkPaymentObservation{}) {
			t.Fatal("modified signed value accepted")
		}
	}
	if _, err := VerifyLynkPayment([]byte(lynkFixtureBody), lynkFixtureSignature, []byte("other-synthetic-merchant-key")); !errors.Is(err, ErrLynkUnauthorized) {
		t.Fatal("different merchant key accepted")
	}
}

func TestLynkRejectsNoncanonicalAndOutOfBoundAmounts(t *testing.T) {
	for _, amount := range []string{`"72000"`, `72000.0`, `7.2e4`, `0`, `-1`, `1000000001`, `9223372036854775808`, `null`, `true`, `+72000`, `072000`} {
		body := strings.Replace(lynkFixtureBody, `"grandTotal":72000`, `"grandTotal":`+amount, 1)
		if got, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey)); !errors.Is(err, ErrLynkInvalid) || got != (LynkPaymentObservation{}) {
			t.Fatalf("amount syntax accepted: %s", amount)
		}
	}
}

func TestLynkRejectsDuplicateKeysAndInvalidEnvelope(t *testing.T) {
	for _, body := range []string{
		strings.Replace(lynkFixtureBody, `"event":"payment.received"`, `"event":"payment.received","event":"payment.received"`, 1),
		strings.Replace(lynkFixtureBody, `"grandTotal":72000`, `"grandTotal":72000,"grandTotal":72000`, 1),
		strings.Replace(lynkFixtureBody, `"grandTotal":72000`, `"grandTotal":72000,"grand\u0054otal":72000`, 1),
		strings.Replace(lynkFixtureBody, `"email":"fixture@example.invalid"`, `"email":"one@example.invalid","email":"two@example.invalid"`, 1),
		strings.Replace(lynkFixtureBody, `"SUCCESS"`, `"PENDING"`, 1),
		strings.Replace(lynkFixtureBody, `"message_code":"0"`, `"message_code":0`, 1),
		strings.Replace(lynkFixtureBody, `"message_code":"0"`, `"message_code":"1"`, 1),
		strings.Replace(lynkFixtureBody, `"payment.received"`, `"payment.refunded"`, 1),
		lynkFixtureBody + ` {}`,
		`null`, `[]`, `{"event":"payment.received","data":null}`,
		strings.Replace(lynkFixtureBody, `"customer":{`, `"customer":{"nest":`+strings.Repeat("[", 20)+"0"+strings.Repeat("]", 20)+`,`, 1),
	} {
		if got, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey)); !errors.Is(err, ErrLynkInvalid) || got != (LynkPaymentObservation{}) {
			t.Fatal("ambiguous or invalid JSON accepted")
		}
	}
}

func TestLynkRejectsCaseAliasedContractKeys(t *testing.T) {
	for _, change := range [][2]string{{`"event":`, `"Event":`}, {`"data":`, `"Data":`}, {`"message_id":`, `"MESSAGE_ID":`}, {`"refId":`, `"REFID":`}, {`"grandTotal":`, `"GrandTotal":`}, {`"grandTotal":72000`, `"grandTotal":72000,"GRANDTOTAL":72000`}} {
		body := strings.Replace(lynkFixtureBody, change[0], change[1], 1)
		if _, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey)); !errors.Is(err, ErrLynkInvalid) {
			t.Fatal("case-aliased JSON contract key accepted")
		}
	}
}

func TestLynkBoundsAndErrorsNeverExposeInput(t *testing.T) {
	for _, signature := range []string{"", lynkFixtureSignature + "0", "v1=" + lynkFixtureSignature, strings.Repeat("z", 64), " " + lynkFixtureSignature, strings.Repeat("0", 64)} {
		got, err := VerifyLynkPayment([]byte(lynkFixtureBody), signature, []byte(lynkFixtureKey))
		if err == nil || got != (LynkPaymentObservation{}) {
			t.Fatal("invalid signature accepted")
		}
		if strings.Contains(err.Error(), "example.invalid") || strings.Contains(err.Error(), lynkFixtureKey) {
			t.Fatal("error exposes source data")
		}
	}
	for _, key := range [][]byte{nil, {}, []byte(strings.Repeat("k", 4097)), {0xff}} {
		if _, err := VerifyLynkPayment([]byte(lynkFixtureBody), lynkFixtureSignature, key); !errors.Is(err, ErrLynkInvalid) {
			t.Fatal("invalid key accepted")
		}
	}
	for _, body := range [][]byte{nil, append([]byte(lynkFixtureBody), []byte(strings.Repeat(" ", 65536))...), append([]byte(lynkFixtureBody), 0xff)} {
		if _, err := VerifyLynkPayment(body, lynkFixtureSignature, []byte(lynkFixtureKey)); !errors.Is(err, ErrLynkInvalid) {
			t.Fatal("unbounded or invalid encoding accepted")
		}
	}
	for _, ref := range []string{"", strings.Repeat("r", 129), "whitespace ref", `escaped\nref`} {
		body := strings.Replace(lynkFixtureBody, "0123456789abcdef0123456789abcdef", ref, 1)
		if _, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey)); !errors.Is(err, ErrLynkInvalid) {
			t.Fatal("invalid reference accepted")
		}
	}
	got, err := VerifyLynkPayment([]byte(lynkFixtureBody), strings.ToUpper(lynkFixtureSignature), []byte(lynkFixtureKey))
	if err != nil || got.NetAmountIDR != 72000 {
		t.Fatal("valid hexadecimal header rejected")
	}
}

func TestLynkStatelessVerificationDoesNotPreventReplay(t *testing.T) {
	first, err := VerifyLynkPayment([]byte(lynkFixtureBody), lynkFixtureSignature, []byte(lynkFixtureKey))
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifyLynkPayment([]byte(lynkFixtureBody), lynkFixtureSignature, []byte(lynkFixtureKey))
	if err != nil || first != second {
		t.Fatal("pure verifier introduced undocumented replay policy")
	}
}

func TestLynkDigestDoesNotAuthenticateFieldBoundaries(t *testing.T) {
	// The vendor concatenation has no separators. Moving the leading A from
	// message_id into refId preserves the digest but changes the tuple. An
	// independent trusted provider-reference map is required before allocation.
	body := strings.Replace(lynkFixtureBody, `"refId":"0123456789abcdef0123456789abcdef"`, `"refId":"0123456789abcdef0123456789abcdefA"`, 1)
	body = strings.Replace(body, `"message_id":"API_CALL_1744270275143115_4624014"`, `"message_id":"PI_CALL_1744270275143115_4624014"`, 1)
	got, err := VerifyLynkPayment([]byte(body), lynkFixtureSignature, []byte(lynkFixtureKey))
	if err != nil || got.RefID != "0123456789abcdef0123456789abcdefA" || got.MessageID != "PI_CALL_1744270275143115_4624014" {
		t.Fatal("documented digest boundary characterization changed")
	}
	if fmt.Sprint(got.NetAmountIDR) != "72000" {
		t.Fatal("wrong net amount")
	}
}
