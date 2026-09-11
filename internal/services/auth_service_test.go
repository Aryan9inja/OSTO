package services

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/user/auth-cli-system/internal/models"
)

func TestAuthService_Register(t *testing.T) {
	authSvc, _, _, _ := setupTestServices(t)

	// 1. Success case
	user, err := authSvc.Register("testuser", "securePassword123")
	if err != nil {
		t.Fatalf("Register() failed: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("expected username testuser, got %s", user.Username)
	}
	if user.PasswordHash == "" || user.PasswordHash == "securePassword123" {
		t.Errorf("password was not hashed properly")
	}

	// 2. Duplicate registration
	_, err = authSvc.Register("testuser", "anotherPassword123")
	if !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("expected ErrUsernameTaken, got %v", err)
	}

	// 3. Invalid short username
	_, err = authSvc.Register("ab", "securePassword123")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("expected ErrInvalidUsername, got %v", err)
	}

	// 4. Invalid short password
	_, err = authSvc.Register("validuser", "short")
	if !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestAuthService_LockoutPolicy(t *testing.T) {
	authSvc, _, _, _ := setupTestServices(t)

	username := "lockout_victim"
	password := "correctPassword123"
	_, err := authSvc.Register(username, password)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Fail 4 times (max is 5)
	for i := 1; i <= 4; i++ {
		_, err := authSvc.Login(username, "wrongPassword", "")
		if err == nil {
			t.Fatalf("attempt %d: expected error on wrong password", i)
		}
		if !strings.Contains(err.Error(), "attempts remaining") {
			t.Errorf("attempt %d: expected remaining attempts warning, got: %v", i, err)
		}
	}

	// 5th failed attempt -> locks account
	_, err = authSvc.Login(username, "wrongPassword", "")
	if err == nil || !strings.Contains(err.Error(), "temporarily locked") {
		t.Fatalf("5th attempt should have triggered account lockout, got: %v", err)
	}

	// 6th attempt with correct password should still be locked
	_, err = authSvc.Login(username, password, "")
	if err == nil || !strings.Contains(err.Error(), "temporarily locked") {
		t.Fatalf("account should reject valid password while locked, got: %v", err)
	}
}

func TestAuthService_TwoFactorAuthentication(t *testing.T) {
	authSvc, _, totpSvc, db := setupTestServices(t)

	username := "mfa_user"
	password := "mfaPassword123"
	user, err := authSvc.Register(username, password)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// 1. Generate 2FA enrollment
	secret, uri, err := authSvc.GenerateMFAEnrollment(user.ID)
	if err != nil {
		t.Fatalf("GenerateMFAEnrollment() error = %v", err)
	}
	if len(secret) == 0 || !strings.HasPrefix(uri, "otpauth://") {
		t.Errorf("invalid secret or URI generated: %s, %s", secret, uri)
	}

	// 2. Enable with invalid code
	err = authSvc.EnableMFA(user.ID, "000000")
	if !errors.Is(err, ErrInvalidMFACode) {
		t.Errorf("expected ErrInvalidMFACode, got %v", err)
	}

	// 3. Enable with valid code
	validCode, err := totpSvc.GenerateCode(secret, time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}

	err = authSvc.EnableMFA(user.ID, validCode)
	if err != nil {
		t.Fatalf("EnableMFA() error = %v", err)
	}

	// 4. Verify 2FA status in DB
	var refreshed models.User
	db.First(&refreshed, user.ID)
	if !refreshed.TOTPEnabled {
		t.Errorf("TOTPEnabled flag was not set to true")
	}

	// 5. Login without 2FA code should return ErrMFAFactorRequired
	res, err := authSvc.Login(username, password, "")
	if !errors.Is(err, ErrMFAFactorRequired) {
		t.Fatalf("expected ErrMFAFactorRequired, got %v", err)
	}
	if res == nil || !res.MFARequired {
		t.Errorf("expected MFARequired = true in LoginResult")
	}

	// 6. Login with invalid 2FA code should fail
	_, err = authSvc.Login(username, password, "999999")
	if !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("expected ErrInvalidMFACode, got %v", err)
	}

	// 7. Login with valid 2FA code should succeed
	currentValidCode, _ := totpSvc.GenerateCode(secret, time.Now().Unix())
	loginSuccess, err := authSvc.Login(username, password, currentValidCode)
	if err != nil {
		t.Fatalf("Login with valid MFA code failed: %v", err)
	}
	if loginSuccess.Session == nil || loginSuccess.Session.Token == "" {
		t.Errorf("expected session on successful login")
	}

	// 8. Disable MFA
	err = authSvc.DisableMFA(user.ID)
	if err != nil {
		t.Fatalf("DisableMFA() error = %v", err)
	}

	// 9. Login now succeeds without 2FA code
	noMFALogin, err := authSvc.Login(username, password, "")
	if err != nil {
		t.Fatalf("Login without MFA code should succeed after disable: %v", err)
	}
	if noMFALogin.Session == nil {
		t.Errorf("expected session token")
	}
}
