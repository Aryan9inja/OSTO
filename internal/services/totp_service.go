package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// TOTPPeriod defines the time step in seconds (RFC 6238 standard)
	TOTPPeriod = 30
	// TOTPDigits defines the length of the OTP code
	TOTPDigits = 6
	// SecretByteLength defines 160-bit key recommended by RFC 4226 / 6238
	SecretByteLength = 20
)

// TOTPService handles generation and validation of TOTP codes
type TOTPService struct {
	issuer string
}

// NewTOTPService creates a new TOTPService with given issuer
func NewTOTPService(issuer string) *TOTPService {
	if issuer == "" {
		issuer = "AuthCLISystem"
	}
	return &TOTPService{issuer: issuer}
}

// GenerateSecret creates a new random 160-bit base32-encoded secret
func (s *TOTPService) GenerateSecret() (string, error) {
	buf := make([]byte, SecretByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	// Google Authenticator standard base32 without padding
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
	return secret, nil
}

// GenerateKeyURI generates the otpauth:// URI for scanning with authenticator apps
func (s *TOTPService) GenerateKeyURI(username, secret string) string {
	cleanSecret := strings.ToUpper(strings.TrimSpace(secret))
	label := fmt.Sprintf("%s:%s", s.issuer, username)
	
	v := url.Values{}
	v.Set("secret", cleanSecret)
	v.Set("issuer", s.issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	v.Set("period", fmt.Sprintf("%d", TOTPPeriod))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + label,
		RawQuery: v.Encode(),
	}
	return u.String()
}

// GenerateCode calculates the 6-digit TOTP code for a secret at a specific Unix timestamp
func (s *TOTPService) GenerateCode(secret string, timestamp int64) (string, error) {
	cleanSecret := strings.ToUpper(strings.TrimSpace(secret))
	// Add padding if missing for standard base32 decoding
	if padLen := len(cleanSecret) % 8; padLen != 0 {
		cleanSecret += strings.Repeat("=", 8-padLen)
	}

	key, err := base32.StdEncoding.DecodeString(cleanSecret)
	if err != nil {
		return "", errors.New("invalid base32 secret")
	}

	counter := uint64(timestamp / TOTPPeriod)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Dynamic truncation per RFC 4226 Section 5.4
	offset := hash[len(hash)-1] & 0x0f
	truncatedHash := binary.BigEndian.Uint32(hash[offset : offset+4])
	truncatedHash &= 0x7fffffff // clear highest bit

	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	codeInt := truncatedHash % mod

	return fmt.Sprintf("%0*d", TOTPDigits, codeInt), nil
}

// ValidateCode verifies if the given code matches the expected TOTP with clock drift tolerance
func (s *TOTPService) ValidateCode(secret, code string, timestamp int64, windowSteps int) bool {
	cleanCode := strings.TrimSpace(code)
	if len(cleanCode) != TOTPDigits {
		return false
	}

	if windowSteps < 0 {
		windowSteps = 1
	}

	// Check time intervals: [current - windowSteps, current + windowSteps]
	for step := -windowSteps; step <= windowSteps; step++ {
		t := timestamp + int64(step*TOTPPeriod)
		expected, err := s.GenerateCode(secret, t)
		if err != nil {
			return false
		}

		if subtle.ConstantTimeCompare([]byte(expected), []byte(cleanCode)) == 1 {
			return true
		}
	}

	return false
}

// VerifyNow is a convenience method that validates code at the current time (drift window +/- 1 step)
func (s *TOTPService) VerifyNow(secret, code string) bool {
	return s.ValidateCode(secret, code, time.Now().Unix(), 1)
}
