package services

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPService_GenerateSecret(t *testing.T) {
	svc := NewTOTPService("TestIssuer")
	secret1, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if len(secret1) == 0 {
		t.Errorf("GenerateSecret() returned empty string")
	}

	secret2, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if secret1 == secret2 {
		t.Errorf("GenerateSecret() generated identical secrets consecutively")
	}
}

func TestTOTPService_GenerateKeyURI(t *testing.T) {
	svc := NewTOTPService("TestIssuer")
	secret := "JBSWY3DPEHPK3PXP"
	username := "alice"

	uri := svc.GenerateKeyURI(username, secret)
	if !strings.HasPrefix(uri, "otpauth://totp/TestIssuer:alice?") {
		t.Errorf("GenerateKeyURI() prefix unexpected, got = %s", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("GenerateKeyURI() missing secret, got = %s", uri)
	}
	if !strings.Contains(uri, "issuer=TestIssuer") {
		t.Errorf("GenerateKeyURI() missing issuer, got = %s", uri)
	}
}

func TestTOTPService_GenerateAndValidateCode(t *testing.T) {
	svc := NewTOTPService("TestIssuer")
	secret, err := svc.GenerateSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	now := time.Now().Unix()
	code, err := svc.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}

	if len(code) != 6 {
		t.Errorf("GenerateCode() length = %d, want 6", len(code))
	}

	// 1. Current time code must be valid
	if !svc.ValidateCode(secret, code, now, 1) {
		t.Errorf("ValidateCode() failed for freshly generated code at current time")
	}

	// 2. Skew tolerance: code at T should be valid at T+30s when window=1
	if !svc.ValidateCode(secret, code, now+30, 1) {
		t.Errorf("ValidateCode() failed within 1 step future window")
	}

	// 3. Skew tolerance: code at T should be valid at T-30s when window=1
	if !svc.ValidateCode(secret, code, now-30, 1) {
		t.Errorf("ValidateCode() failed within 1 step past window")
	}

	// 4. Exceeded skew tolerance: code at T should be invalid at T+90s when window=1
	if svc.ValidateCode(secret, code, now+90, 1) {
		t.Errorf("ValidateCode() should have rejected code past window (T+90s)")
	}

	// 5. Invalid code format or incorrect digits
	if svc.ValidateCode(secret, "000000", now, 1) && code != "000000" {
		t.Errorf("ValidateCode() accepted arbitrary wrong code")
	}

	if svc.ValidateCode(secret, "123", now, 1) {
		t.Errorf("ValidateCode() should reject codes shorter than 6 digits")
	}
}

func TestTOTPService_RFC6238_KnownVector(t *testing.T) {
	// Standard RFC 6238 test key: "12345678901234567890" (ASCII)
	// Base32 representation: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
	rfcSecret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	svc := NewTOTPService("RFC6238")

	// At time 59s: counter = 1 -> SHA1 TOTP is 287082
	code59, err := svc.GenerateCode(rfcSecret, 59)
	if err != nil {
		t.Fatalf("GenerateCode() failed: %v", err)
	}
	if code59 != "287082" {
		t.Errorf("RFC 6238 test vector mismatch at t=59s: got %s, want 287082", code59)
	}

	// At time 1111111109s: counter = 37037036 -> SHA1 TOTP is 081804
	code111, err := svc.GenerateCode(rfcSecret, 1111111109)
	if err != nil {
		t.Fatalf("GenerateCode() failed: %v", err)
	}
	if code111 != "081804" {
		t.Errorf("RFC 6238 test vector mismatch at t=1111111109s: got %s, want 081804", code111)
	}
}
