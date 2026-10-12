package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func staffCryptoBytes(t *testing.T, count int) []byte {
	t.Helper()
	value := make([]byte, count)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("synthetic crypto fixture generation failed")
	}
	return value
}

func staffCryptoPassword(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(staffCryptoBytes(t, 32))
}

func assertStaffPasswordFormat(t *testing.T, encoded string) {
	t.Helper()
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=19456,t=2,p=1" {
		t.Fatal("password algorithm or parameter contract failed")
	}
	salt, saltErr := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	digest, digestErr := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if saltErr != nil || digestErr != nil || len(salt) != 16 || len(digest) != 32 {
		t.Fatal("password salt or digest encoding contract failed")
	}
}

func TestStaffPasswordRoundTrip(t *testing.T) {
	password := staffCryptoPassword(t)
	first, err := hashStaffPassword(password)
	if err != nil {
		t.Fatal("valid password hashing failed")
	}
	assertStaffPasswordFormat(t, first)
	if !verifyStaffPassword(first, password) || verifyStaffPassword(first, staffCryptoPassword(t)) {
		t.Fatal("password verification contract failed")
	}
	second, err := hashStaffPassword(password)
	if err != nil || first == second {
		t.Fatal("password salts must be fresh")
	}
}

func TestStaffPasswordUnicodeAndWhitespace(t *testing.T) {
	for _, password := range []string{
		strings.Repeat("界", 12) + "  ",
		"  " + staffCryptoPassword(t) + "  ",
		strings.Repeat("界", 128),
		strings.Repeat("🙂", 128),
		strings.Repeat(" ", 12),
		"e\u0301" + staffCryptoPassword(t),
	} {
		encoded, err := hashStaffPassword(password)
		if err != nil || !verifyStaffPassword(encoded, password) {
			t.Fatal("valid Unicode or exact whitespace password rejected")
		}
		if trimmed := strings.TrimSpace(password); trimmed != password && verifyStaffPassword(encoded, trimmed) {
			t.Fatal("password must not be trimmed")
		}
		if strings.HasPrefix(password, "e\u0301") && verifyStaffPassword(encoded, "é"+password[len("e\u0301"):]) {
			t.Fatal("password must not be Unicode-normalized")
		}
	}
	for _, password := range []string{"", strings.Repeat("界", 11), strings.Repeat("a", 129), strings.Repeat("🙂", 129), staffCryptoPassword(t) + string([]byte{0xff})} {
		if encoded, err := hashStaffPassword(password); err == nil || encoded != "" {
			t.Fatal("invalid password bound or encoding accepted")
		}
	}
}

func TestStaffPasswordEncodingBounds(t *testing.T) {
	password := staffCryptoPassword(t)
	valid, err := hashStaffPassword(password)
	if err != nil {
		t.Fatal("valid password fixture hashing failed")
	}
	parts := strings.Split(valid, "$")
	malformed := []string{
		"", strings.Repeat("x", 4096), valid + "$extra", " " + valid,
		strings.Replace(valid, "argon2id", "argon2i", 1),
		strings.Replace(valid, "v=19", "v=16", 1),
		strings.Replace(valid, "m=19456,t=2,p=1", "m=4294967295,t=2,p=1", 1),
		strings.Replace(valid, "m=19456,t=2,p=1", "m=19456,t=999999,p=1", 1),
		strings.Replace(valid, "m=19456,t=2,p=1", "m=19456,t=2,p=255", 1),
		strings.Replace(valid, "m=19456,t=2,p=1", "m=019456,t=2,p=1", 1),
		strings.Replace(valid, "m=19456,t=2,p=1", "t=2,m=19456,p=1", 1),
		strings.Replace(valid, parts[4], base64.RawStdEncoding.EncodeToString(make([]byte, 15)), 1),
		strings.Replace(valid, parts[5], base64.RawStdEncoding.EncodeToString(make([]byte, 31)), 1),
		strings.Replace(valid, parts[4], parts[4]+"==", 1),
		strings.Replace(valid, parts[5], parts[5]+"\n", 1),
	}
	staffPasswordSlots <- struct{}{}
	staffPasswordSlots <- struct{}{}
	defer func() { <-staffPasswordSlots; <-staffPasswordSlots }()
	for _, encoded := range malformed {
		done := make(chan bool, 1)
		go func() { done <- verifyStaffPassword(encoded, password) }()
		select {
		case accepted := <-done:
			if accepted {
				t.Fatal("malformed encoded password accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("malformed encoding entered the derivation queue")
		}
	}
}

func TestStaffPasswordUnknownUserDummy(t *testing.T) {
	encoded, err := unknownStaffPasswordHash()
	if err != nil {
		t.Fatal("unknown-user dummy initialization failed")
	}
	assertStaffPasswordFormat(t, encoded)
	staffPasswordSlots <- struct{}{}
	staffPasswordSlots <- struct{}{}
	done := make(chan bool, 1)
	started := make(chan struct{})
	password := staffCryptoPassword(t)
	go func() { close(started); done <- verifyUnknownStaffPassword(password) }()
	<-started
	select {
	case <-done:
		<-staffPasswordSlots
		<-staffPasswordSlots
		t.Fatal("unknown user bypassed the real bounded derivation path")
	case <-time.After(25 * time.Millisecond):
	}
	<-staffPasswordSlots
	<-staffPasswordSlots
	select {
	case accepted := <-done:
		if accepted {
			t.Fatal("unknown user must never authenticate")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("unknown-user derivation did not complete")
	}
}

func TestStaffPasswordConcurrentBudget(t *testing.T) {
	staffPasswordSlots <- struct{}{}
	staffPasswordSlots <- struct{}{}
	password := staffCryptoPassword(t)
	done := make(chan error, 1)
	go func() { _, err := hashStaffPassword(password); done <- err }()
	select {
	case <-done:
		<-staffPasswordSlots
		<-staffPasswordSlots
		t.Fatal("a third derivation exceeded the memory budget")
	case <-time.After(25 * time.Millisecond):
	}
	<-staffPasswordSlots
	<-staffPasswordSlots
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("queued derivation failed after budget release")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued derivation did not resume")
	}
}

func publicStaffOTPSeed() []byte {
	seed := make([]byte, 32)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	return seed
}

func TestStaffTOTPVectorAndWindow(t *testing.T) {
	seed := publicStaffOTPSeed()
	// Literal fixtures computed independently with Python HMAC-SHA1.
	for _, vector := range []struct {
		unix, counter int64
		code          string
	}{
		{59, 1, "984859"}, {60, 2, "046223"},
		{1111111109, 37037036, "259579"}, {1111111111, 37037037, "634512"},
		{1234567890, 41152263, "468320"}, {20000000000, 666666666, "692595"},
	} {
		counter, err := acceptedTOTPCounter(seed, vector.code, time.Unix(vector.unix, 0), -1)
		if err != nil || counter != vector.counter {
			t.Fatal("independent TOTP vector or 64-bit counter contract failed")
		}
	}
	for _, vector := range []struct {
		unix, last, want int64
		code             string
	}{
		{29, -1, 0, "236440"}, {30, -1, 1, "984859"},
		{60, -1, 1, "984859"}, {60, 1, 2, "046223"},
	} {
		counter, err := acceptedTOTPCounter(seed, vector.code, time.Unix(vector.unix, 0).In(time.FixedZone("test", 7*60*60)), vector.last)
		if err != nil || counter != vector.want {
			t.Fatal("current/previous window or UTC comparison contract failed")
		}
	}
}

func TestStaffTOTPStrictDigitsAndReplay(t *testing.T) {
	seed, now := publicStaffOTPSeed(), time.Unix(60, 0)
	for _, code := range []string{"", "04622", "0046223", " 046223", "046223 ", "046223\n", "０４６２２３", "04622x", "373550", "236440"} {
		if _, err := acceptedTOTPCounter(seed, code, now, -1); err == nil {
			t.Fatal("non-canonical digits or out-of-window TOTP accepted")
		}
	}
	for _, row := range []struct {
		code string
		last int64
	}{{"046223", 2}, {"984859", 1}, {"046223", 99}, {"046223", -2}} {
		if _, err := acceptedTOTPCounter(seed, row.code, now, row.last); err == nil {
			t.Fatal("accepted counter reuse or invalid replay state permitted")
		}
	}
	for _, invalidSeed := range [][]byte{nil, seed[:20], append(append([]byte(nil), seed...), 0)} {
		if _, err := acceptedTOTPCounter(invalidSeed, "046223", now, -1); err == nil {
			t.Fatal("invalid seed size accepted")
		}
	}
	if _, err := acceptedTOTPCounter(seed, "046223", time.Unix(-1, 0), -1); err == nil {
		t.Fatal("pre-epoch time accepted")
	}
}

func TestStaffSeedAuthenticatedContext(t *testing.T) {
	key, seed := staffCryptoBytes(t, 32), staffCryptoBytes(t, 32)
	aad := "instance-a|principal-a|factor-1"
	first, err := sealStaffSeed(key, seed, aad)
	if err != nil || bytes.Contains(first, seed) {
		t.Fatal("valid seed encryption failed or exposed plaintext")
	}
	opened, err := openStaffSeed(key, first, aad)
	if err != nil || !bytes.Equal(opened, seed) {
		t.Fatal("authenticated seed roundtrip failed")
	}
	second, err := sealStaffSeed(key, seed, aad)
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("seed encryption nonce must be fresh")
	}
	for _, otherAAD := range []string{"instance-b|principal-a|factor-1", "instance-a|principal-b|factor-1", "instance-a|principal-a|factor-2", "", strings.Repeat("x", 513)} {
		if value, err := openStaffSeed(key, first, otherAAD); err == nil || len(value) != 0 {
			t.Fatal("seed opened under a mismatched or invalid context")
		}
	}
	for _, otherKey := range [][]byte{nil, key[:16], staffCryptoBytes(t, 32)} {
		if value, err := openStaffSeed(otherKey, first, aad); err == nil || len(value) != 0 {
			t.Fatal("seed opened under an invalid or different key")
		}
	}
	modified := append([]byte(nil), first...)
	modified[len(modified)-1] ^= 1
	for _, ciphertext := range [][]byte{nil, first[:5], first[:len(first)-1], append(append([]byte(nil), first...), 0), modified} {
		if value, err := openStaffSeed(key, ciphertext, aad); err == nil || len(value) != 0 {
			t.Fatal("malformed or altered seed ciphertext accepted")
		}
	}
	if _, err := sealStaffSeed(key[:16], seed, aad); err == nil {
		t.Fatal("seed encryption accepted a non-AES256 key")
	}
	if _, err := sealStaffSeed(key, seed[:20], aad); err == nil {
		t.Fatal("seed encryption accepted an invalid seed size")
	}
	if _, err := sealStaffSeed(key, seed, ""); err == nil {
		t.Fatal("seed encryption accepted an unbound context")
	}
	generated, err := newStaffTOTPSeed()
	another, otherErr := newStaffTOTPSeed()
	if err != nil || otherErr != nil || len(generated) != 32 || len(another) != 32 || bytes.Equal(generated, another) {
		t.Fatal("fresh factor seed material contract failed")
	}
}

func TestStaffRecoveryMaterial(t *testing.T) {
	seen := map[string]bool{}
	for range 2 {
		codes, digests, err := newStaffRecoveryMaterial()
		if err != nil || len(codes) != 10 || len(digests) != 10 {
			t.Fatal("recovery material count contract failed")
		}
		for index, code := range codes {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(code)
			if err != nil || len(decoded) != 32 || seen[code] {
				t.Fatal("recovery values must be unique canonical 32-byte random material")
			}
			seen[code] = true
			expected := sha256.Sum256([]byte(code))
			if digests[index] != hex.EncodeToString(expected[:]) || strings.Contains(digests[index], code) {
				t.Fatal("recovery persistence material must be digest-only")
			}
			computed, err := staffRecoveryDigest(code)
			if err != nil || computed != digests[index] {
				t.Fatal("recovery proof digest verification contract failed")
			}
			for _, malformed := range []string{"", " " + code, code + "=", code + "\n", code[:len(code)-1]} {
				if _, err := staffRecoveryDigest(malformed); err == nil {
					t.Fatal("non-canonical recovery input accepted")
				}
			}
		}
	}
}
