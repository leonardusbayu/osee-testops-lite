package core

import (
	"reflect"
	"strings"
	"testing"
)

func TestStrictUUIDParsing(t *testing.T) {
	for _, s := range []string{"", " 12345678-1234-4234-8234-123456789abc", "12345678123442348234123456789abc", "12345678-1234-4234-8234-123456789abz", "12345678-1234-4234-8234-123456789ABC"} {
		if _, e := ParseID(s); e == nil {
			t.Errorf("accepted invalid ID %q", s)
		}
	}
	s := "12345678-1234-4234-8234-123456789abc"
	if id, e := ParseID(s); e != nil || string(id) != s {
		t.Fatal("valid ID changed")
	}
}
func TestCryptographicUUIDGeneration(t *testing.T) {
	seen := map[ID]bool{}
	for i := 0; i < 1000; i++ {
		id, e := NewID()
		if e != nil {
			t.Fatal(e)
		}
		s := string(id)
		if len(s) != 36 {
			t.Fatal("UUID must be 36 characters")
		}
		if s[14] != '4' || !strings.ContainsRune("89ab", rune(s[19])) {
			t.Fatal("not UUID v4")
		}
		if _, e := ParseID(s); e != nil || seen[id] {
			t.Fatal("invalid or repeated UUID")
		}
		seen[id] = true
	}
}
func TestIntegerMoney(t *testing.T) {
	m := Money{MinorUnits: 9007199254740993, Currency: "IDR"}
	if m.MinorUnits+1 != 9007199254740994 || reflect.TypeOf(m.MinorUnits).Kind() != reflect.Int64 {
		t.Fatal("money must be exact int64")
	}
}
func TestSeparateStateTypes(t *testing.T) {
	values := []any{PaymentPending, RegistrationDraft, AttendanceNotCheckedIn, ResultNotReceived, ShipmentLabelCreated}
	types := map[reflect.Type]bool{}
	states := map[string]bool{}
	for _, v := range values {
		ty := reflect.TypeOf(v)
		s := reflect.ValueOf(v).String()
		if types[ty] || states[s] || s == "" {
			t.Error("domain state axes must be distinct and explicit")
		}
		types[ty] = true
		states[s] = true
	}
}
