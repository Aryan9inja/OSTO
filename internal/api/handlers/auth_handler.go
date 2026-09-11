package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/auth-cli-system/internal/api/middleware"
	"github.com/user/auth-cli-system/internal/models"
	"github.com/user/auth-cli-system/internal/services"
)

type AuthHandler struct {
	authService    *services.AuthService
	sessionService *services.SessionService
}

func NewAuthHandler(authService *services.AuthService, sessionService *services.SessionService) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		sessionService: sessionService,
	}
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	TOTPCode string `json:"totp_code"`
}

type UserSummary struct {
	Username            string     `json:"username"`
	RegistrationDate    time.Time  `json:"registration_date"`
	MFAStatus           string     `json:"mfa_status"`
	SessionExpiresAt    *time.Time `json:"session_expires_at,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	user, err := h.authService.Register(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, services.ErrUsernameTaken) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrInvalidUsername) || errors.Is(err, services.ErrInvalidPassword) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":  "User registered successfully",
		"username": user.Username,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and password are required"})
		return
	}

	result, err := h.authService.Login(req.Username, req.Password, req.TOTPCode)
	if err != nil {
		if errors.Is(err, services.ErrMFAFactorRequired) {
			c.JSON(http.StatusOK, gin.H{
				"status":       "mfa_required",
				"message":      "2FA code is required",
				"totp_enabled": true,
			})
			return
		}
		if errors.Is(err, services.ErrAccountLocked) || strings.Contains(err.Error(), "temporarily locked") {
			c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrInvalidCredentials) || strings.Contains(err.Error(), "invalid username or password") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, services.ErrInvalidMFACode) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid 2FA code"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed due to server error"})
		return
	}

	mfaStatus := "disabled"
	if result.User.TOTPEnabled {
		mfaStatus = "enabled"
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"token":  result.Session.Token,
		"user": UserSummary{
			Username:         result.User.Username,
			RegistrationDate: result.User.CreatedAt,
			MFAStatus:        mfaStatus,
			SessionExpiresAt: &result.Session.ExpiresAt,
			LastLoginAt:      result.User.LastLoginAt,
		},
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	sessionVal, exists := c.Get(middleware.ContextSessionKey)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No active session"})
		return
	}

	session := sessionVal.(*models.Session)
	if err := h.sessionService.RevokeSession(session.Token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
