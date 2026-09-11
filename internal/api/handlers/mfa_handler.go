package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/user/auth-cli-system/internal/api/middleware"
	"github.com/user/auth-cli-system/internal/models"
	"github.com/user/auth-cli-system/internal/services"
)

type MFAHandler struct {
	authService *services.AuthService
}

func NewMFAHandler(authService *services.AuthService) *MFAHandler {
	return &MFAHandler{authService: authService}
}

type EnableMFARequest struct {
	Code string `json:"code" binding:"required"`
}

func (h *MFAHandler) Generate(c *gin.Context) {
	userVal, _ := c.Get(middleware.ContextUserKey)
	user := userVal.(models.User)

	secret, uri, err := h.authService.GenerateMFAEnrollment(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate 2FA setup"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret": secret,
		"uri":    uri,
	})
}

func (h *MFAHandler) Enable(c *gin.Context) {
	userVal, _ := c.Get(middleware.ContextUserKey)
	user := userVal.(models.User)

	var req EnableMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Verification code is required"})
		return
	}

	if err := h.authService.EnableMFA(user.ID, req.Code); err != nil {
		if errors.Is(err, services.ErrInvalidMFACode) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification code. Please try again."})
			return
		}
		if errors.Is(err, services.ErrMFANotConfigured) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Please generate a 2FA secret before enabling"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable 2FA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA successfully enabled"})
}

func (h *MFAHandler) Disable(c *gin.Context) {
	userVal, _ := c.Get(middleware.ContextUserKey)
	user := userVal.(models.User)

	if err := h.authService.DisableMFA(user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable 2FA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA successfully disabled"})
}
