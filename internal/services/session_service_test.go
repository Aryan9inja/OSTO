package services

import (
	"testing"
	"time"

	"github.com/user/auth-cli-system/internal/models"
)

func TestSessionService_Lifecycle(t *testing.T) {
	_, sessionSvc, _, db := setupTestServices(t)

	// Create a dummy user
	user := &models.User{
		Username:     "session_user",
		PasswordHash: "hashed_dummy",
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create dummy user: %v", err)
	}

	// 1. Create Session
	session, err := sessionSvc.CreateSession(user.ID)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if len(session.Token) != 64 {
		t.Errorf("expected 64 character hex token, got %d", len(session.Token))
	}

	// 2. Validate Session
	retrieved, err := sessionSvc.GetValidSession(session.Token)
	if err != nil {
		t.Fatalf("GetValidSession() error = %v", err)
	}
	if retrieved.UserID != user.ID {
		t.Errorf("GetValidSession() user_id mismatch: got %d, want %d", retrieved.UserID, user.ID)
	}
	if retrieved.User.Username != user.Username {
		t.Errorf("GetValidSession() failed to preload user: got %s", retrieved.User.Username)
	}

	// 3. Revoke Session
	err = sessionSvc.RevokeSession(session.Token)
	if err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}

	// 4. Validate revoked session returns error
	_, err = sessionSvc.GetValidSession(session.Token)
	if err == nil {
		t.Errorf("GetValidSession() should have returned error for revoked session")
	}

	// 5. Test Expired Session
	expiredSession := &models.Session{
		UserID:    user.ID,
		Token:     "expired_token_12345",
		ExpiresAt: time.Now().Add(-10 * time.Minute),
	}
	db.Create(expiredSession)

	_, err = sessionSvc.GetValidSession(expiredSession.Token)
	if err == nil {
		t.Errorf("GetValidSession() should have returned error for expired session")
	}
}
