package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/user/auth-cli-system/internal/api/middleware"
	"github.com/user/auth-cli-system/internal/models"
)

type UserHandler struct{}

func NewUserHandler() *UserHandler {
	return &UserHandler{}
}

func (h *UserHandler) WhoAmI(c *gin.Context) {
	userVal, exists := c.Get(middleware.ContextUserKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	user := userVal.(models.User)

	sessionVal, _ := c.Get(middleware.ContextSessionKey)
	session := sessionVal.(*models.Session)

	mfaStatus := "disabled"
	if user.TOTPEnabled {
		mfaStatus = "enabled"
	}

	c.JSON(http.StatusOK, UserSummary{
		Username:         user.Username,
		RegistrationDate: user.CreatedAt,
		MFAStatus:        mfaStatus,
		SessionExpiresAt: &session.ExpiresAt,
		LastLoginAt:      user.LastLoginAt,
	})
}
