package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"golang.org/x/crypto/argon2"
)

const staffPasswordParameters = "m=19456,t=2,p=1"

var (
	staffPasswordSlots = make(chan struct{}, 2)
	staffDummyOnce     sync.Once
	staffDummyEncoded  string
	staffDummyError    error
)

func validStaffPassword(password string) bool {
	if len(password) > 512 || !utf8.ValidString(password) {
		return false
	}
	count := utf8.RuneCountInString(password)
	return count >= 12 && count <= 128
}

func deriveStaffPassword(password string, salt []byte) []byte {
	staffPasswordSlots <- struct{}{}
	defer func() { <-staffPasswordSlots }()
	return argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
}

func encodeStaffPassword(salt, digest []byte) string {
	return "$argon2id$v=19$" + staffPasswordParameters + "$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(digest)
}

func staffRandomBytes(count int) ([]byte, error) {
	value := make([]byte, count)
	if _, err := rand.Read(value); err != nil {
		return nil, ErrUnauthenticated
	}
	return value, nil
}

func hashStaffPassword(password string) (string, error) {
	if !validStaffPassword(password) {
		return "", ErrUnauthenticated
	}
	salt, err := staffRandomBytes(16)
	if err != nil {
		return "", err
	}
	return encodeStaffPassword(salt, deriveStaffPassword(password, salt)), nil
}

func verifyStaffPassword(encoded, password string) bool {
	if len(encoded) > 128 || !validStaffPassword(password) {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != staffPasswordParameters {
		return false
	}
	if len(parts[4]) != 22 || len(parts[5]) != 43 {
		return false
	}
	salt, saltErr := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	digest, digestErr := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if saltErr != nil || digestErr != nil || len(salt) != 16 || len(digest) != 32 ||
		base64.RawStdEncoding.EncodeToString(salt) != parts[4] || base64.RawStdEncoding.EncodeToString(digest) != parts[5] {
		return false
	}
	actual := deriveStaffPassword(password, salt)
	return subtle.ConstantTimeCompare(actual, digest) == 1
}

func unknownStaffPasswordHash() (string, error) {
	staffDummyOnce.Do(func() {
		salt, err := staffRandomBytes(16)
		if err != nil {
			staffDummyError = err
			return
		}
		digest, err := staffRandomBytes(32)
		if err != nil {
			staffDummyError = err
			return
		}
		staffDummyEncoded = encodeStaffPassword(salt, digest)
	})
	return staffDummyEncoded, staffDummyError
}

func verifyUnknownStaffPassword(password string) bool {
	encoded, err := unknownStaffPasswordHash()
	if err == nil {
		verifyStaffPassword(encoded, password)
	}
	return false
}

func acceptedTOTPCounter(seed []byte, code string, now time.Time, last int64) (int64, error) {
	if len(seed) != 32 || len(code) != 6 || now.Unix() < 0 || last < -1 {
		return -1, ErrUnauthenticated
	}
	for index := range code {
		if code[index] < '0' || code[index] > '9' {
			return -1, ErrUnauthenticated
		}
	}
	current := now.Unix() / 30
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	for _, counter := range []int64{current, current - 1} {
		if counter < 0 || counter <= last {
			continue
		}
		expected, err := hotp.GenerateCodeCustom(secret, uint64(counter), hotp.ValidateOpts{
			Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return -1, ErrUnauthenticated
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter, nil
		}
	}
	return -1, ErrUnauthenticated
}

func staffSeedCipher(key []byte, aad string) (cipher.AEAD, error) {
	if len(key) != 32 || len(aad) == 0 || len(aad) > 512 || !utf8.ValidString(aad) {
		return nil, ErrUnauthenticated
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return cipher.NewGCM(block)
}

func sealStaffSeed(key, seed []byte, aad string) ([]byte, error) {
	if len(seed) != 32 {
		return nil, ErrUnauthenticated
	}
	aead, err := staffSeedCipher(key, aad)
	if err != nil {
		return nil, err
	}
	nonce, err := staffRandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, seed, []byte(aad)), nil
}

func openStaffSeed(key, sealed []byte, aad string) ([]byte, error) {
	aead, err := staffSeedCipher(key, aad)
	if err != nil || len(sealed) != aead.NonceSize()+32+aead.Overhead() {
		return nil, ErrUnauthenticated
	}
	value, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(aad))
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return value, nil
}

func newStaffTOTPSeed() ([]byte, error) {
	return staffRandomBytes(32)
}

func newStaffRecoveryMaterial() ([]string, []string, error) {
	codes, digests := make([]string, 0, 10), make([]string, 0, 10)
	seen := make(map[string]bool, 10)
	for range 10 {
		material, err := staffRandomBytes(32)
		if err != nil {
			return nil, nil, err
		}
		code := base64.RawURLEncoding.EncodeToString(material)
		if seen[code] {
			return nil, nil, ErrUnauthenticated
		}
		seen[code] = true
		digest, err := staffRecoveryDigest(code)
		if err != nil {
			return nil, nil, err
		}
		codes, digests = append(codes, code), append(digests, digest)
	}
	return codes, digests, nil
}

func staffRecoveryDigest(code string) (string, error) {
	if len(code) != 43 {
		return "", ErrUnauthenticated
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(code)
	if err != nil || len(material) != 32 || base64.RawURLEncoding.EncodeToString(material) != code {
		return "", ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(code))
	return hex.EncodeToString(digest[:]), nil
}
