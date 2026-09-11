package services

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/user/auth-cli-system/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrUsernameTaken      = errors.New("username is already registered")
	ErrInvalidUsername    = errors.New("username must be 3-32 alphanumeric characters or underscores")
	ErrInvalidPassword    = errors.New("password must be at least 8 characters long")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is temporarily locked due to too many failed attempts")
	ErrMFAFactorRequired  = errors.New("2FA code required for this account")
	ErrInvalidMFACode     = errors.New("invalid 2FA code")
	ErrUserNotFound       = errors.New("user not found")
	ErrMFANotConfigured   = errors.New("2FA setup not initiated")
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)

// AuthService coordinates user registration, authentication, lockout, and 2FA
type AuthService struct {
	db              *gorm.DB
	totpService     *TOTPService
	sessionService  *SessionService
	maxAttempts     int
	lockoutDuration time.Duration
}

// NewAuthService creates a new AuthService instance
func NewAuthService(
	db *gorm.DB,
	totpService *TOTPService,
	sessionService *SessionService,
	maxAttempts int,
	lockoutDuration time.Duration,
) *AuthService {
	return &AuthService{
		db:              db,
		totpService:     totpService,
		sessionService:  sessionService,
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
	}
}

// Register creates a new user account with secure password hashing
func (s *AuthService) Register(username, password string) (*models.User, error) {
	username = strings.TrimSpace(username)
	if !usernameRegex.MatchString(username) {
		return nil, ErrInvalidUsername
	}

	if len(password) < 8 {
		return nil, ErrInvalidPassword
	}

	// Check if user already exists
	var existing models.User
	err := s.db.Where("LOWER(username) = LOWER(?)", username).First(&existing).Error
	if err == nil {
		return nil, ErrUsernameTaken
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("database check failed: %w", err)
	}

	// Hash password using bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		Username:     username,
		PasswordHash: string(hash),
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	return user, nil
}

// LoginResult contains the user and session on successful login
type LoginResult struct {
	User        *models.User
	Session     *models.Session
	MFARequired bool
}

// Login authenticates a user with credentials and optional TOTP code
func (s *AuthService) Login(username, password, totpCode string) (*LoginResult, error) {
	username = strings.TrimSpace(username)
	var user models.User

	err := s.db.Where("LOWER(username) = LOWER(?)", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	// 1. Check account lockout state
	if user.IsLocked() {
		remaining := time.Until(*user.LockedUntil).Round(time.Second)
		return nil, fmt.Errorf("%w: try again in %v", ErrAccountLocked, remaining)
	}

	// If lockout expired, reset counter
	if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
		user.ResetLockout()
		_ = s.db.Save(&user)
	}

	// 2. Verify password with bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Increment failed attempts
		user.FailedLoginAttempts++
		if user.FailedLoginAttempts >= s.maxAttempts {
			user.LockTemporarily(s.lockoutDuration)
			_ = s.db.Save(&user)
			return nil, fmt.Errorf("%w for %v", ErrAccountLocked, s.lockoutDuration)
		}
		_ = s.db.Save(&user)
		remainingAttempts := s.maxAttempts - user.FailedLoginAttempts
		return nil, fmt.Errorf("%w (%d attempts remaining before lockout)", ErrInvalidCredentials, remainingAttempts)
	}

	// 3. Handle TOTP MFA if enabled
	if user.TOTPEnabled {
		if totpCode == "" {
			return &LoginResult{
				User:        &user,
				MFARequired: true,
			}, ErrMFAFactorRequired
		}

		if !s.totpService.VerifyNow(user.TOTPSecret, totpCode) {
			return nil, ErrInvalidMFACode
		}
	}

	// 4. Authentication succeeded: reset lockout state and record last login
	user.ResetLockout()
	now := time.Now()
	// Capture previous login time for the response, then update
	lastLogin := user.LastLoginAt
	user.LastLoginAt = &now
	if err := s.db.Save(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to update user login stats: %w", err)
	}

	// 5. Create new session
	session, err := s.sessionService.CreateSession(user.ID)
	if err != nil {
		return nil, err
	}

	// Restore previous login time in the returned struct for display purposes
	userForDisplay := user
	userForDisplay.LastLoginAt = lastLogin

	return &LoginResult{
		User:        &userForDisplay,
		Session:     session,
		MFARequired: false,
	}, nil
}

// GenerateMFAEnrollment generates a secret and URI to begin 2FA setup
func (s *AuthService) GenerateMFAEnrollment(userID uint) (secret string, uri string, err error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return "", "", ErrUserNotFound
	}

	secret, err = s.totpService.GenerateSecret()
	if err != nil {
		return "", "", err
	}

	// Store the pending secret on the user record
	user.TOTPSecret = secret
	if err := s.db.Save(&user).Error; err != nil {
		return "", "", fmt.Errorf("failed to persist secret: %w", err)
	}

	uri = s.totpService.GenerateKeyURI(user.Username, secret)
	return secret, uri, nil
}

// EnableMFA verifies a TOTP code and activates 2FA for the user
func (s *AuthService) EnableMFA(userID uint, code string) error {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return ErrUserNotFound
	}

	if user.TOTPSecret == "" {
		return ErrMFANotConfigured
	}

	if !s.totpService.VerifyNow(user.TOTPSecret, code) {
		return ErrInvalidMFACode
	}

	user.TOTPEnabled = true
	if err := s.db.Save(&user).Error; err != nil {
		return fmt.Errorf("failed to activate 2FA: %w", err)
	}

	return nil
}

// DisableMFA deactivates 2FA and clears the secret
func (s *AuthService) DisableMFA(userID uint) error {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return ErrUserNotFound
	}

	user.TOTPEnabled = false
	user.TOTPSecret = ""
	if err := s.db.Save(&user).Error; err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	return nil
}
