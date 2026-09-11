package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/user/auth-cli-system/internal/models"
	"gorm.io/gorm"
)

var (
	ErrSessionNotFound = errors.New("session not found or has expired")
	ErrSessionRevoked  = errors.New("session has been revoked")
)

// SessionService handles session lifecycle and token validation
type SessionService struct {
	db             *gorm.DB
	defaultTimeout time.Duration
}

// NewSessionService creates a new SessionService
func NewSessionService(db *gorm.DB, defaultTimeout time.Duration) *SessionService {
	return &SessionService{
		db:             db,
		defaultTimeout: defaultTimeout,
	}
}

// GenerateToken creates a cryptographically secure 256-bit random token
func (s *SessionService) GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// CreateSession creates a new session in the database for a user
func (s *SessionService) CreateSession(userID uint) (*models.Session, error) {
	token, err := s.GenerateToken()
	if err != nil {
		return nil, err
	}

	session := &models.Session{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(s.defaultTimeout),
	}

	if err := s.db.Create(session).Error; err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// GetValidSession retrieves an active session by token, ensuring it is not expired or revoked
func (s *SessionService) GetValidSession(token string) (*models.Session, error) {
	if token == "" {
		return nil, ErrSessionNotFound
	}

	var session models.Session
	err := s.db.Preload("User").
		Where("token = ? AND revoked_at IS NULL AND expires_at > ?", token, time.Now()).
		First(&session).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("database query failed: %w", err)
	}

	return &session, nil
}

// RevokeSession marks a session token as revoked
func (s *SessionService) RevokeSession(token string) error {
	now := time.Now()
	res := s.db.Model(&models.Session{}).
		Where("token = ? AND revoked_at IS NULL", token).
		Update("revoked_at", &now)

	if res.Error != nil {
		return fmt.Errorf("failed to revoke session: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// RevokeAllUserSessions marks all active sessions for a user as revoked
func (s *SessionService) RevokeAllUserSessions(userID uint) error {
	now := time.Now()
	err := s.db.Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now).Error
	if err != nil {
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}
	return nil
}
