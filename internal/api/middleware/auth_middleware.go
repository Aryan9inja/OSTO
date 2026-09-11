package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/user/auth-cli-system/internal/services"
)

const (
	ContextUserKey    = "currentUser"
	ContextSessionKey = "currentSession"
)

// AuthMiddleware validates session tokens on protected endpoints
func AuthMiddleware(sessionService *services.SessionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization format must be Bearer <token>"})
			return
		}

		token := strings.TrimSpace(parts[1])
		session, err := sessionService.GetValidSession(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session is invalid or has expired. Please log in again."})
			return
		}

		c.Set(ContextUserKey, session.User)
		c.Set(ContextSessionKey, session)
		c.Next()
	}
}
