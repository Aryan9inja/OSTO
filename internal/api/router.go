package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/user/auth-cli-system/internal/api/handlers"
	"github.com/user/auth-cli-system/internal/api/middleware"
	"github.com/user/auth-cli-system/internal/services"
)

// SetupRouter initializes Gin engine with all API routes and middleware
func SetupRouter(
	authService *services.AuthService,
	sessionService *services.SessionService,
) *gin.Engine {
	// Set Gin to release mode by default for clean production logs
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	authHandler := handlers.NewAuthHandler(authService, sessionService)
	mfaHandler := handlers.NewMFAHandler(authService)
	userHandler := handlers.NewUserHandler()

	apiV1 := r.Group("/api/v1")
	{
		// Public authentication routes
		auth := apiV1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
		}

		// Protected routes requiring active session
		protected := apiV1.Group("")
		protected.Use(middleware.AuthMiddleware(sessionService))
		{
			protected.POST("/auth/logout", authHandler.Logout)
			protected.GET("/user/me", userHandler.WhoAmI)

			mfa := protected.Group("/mfa")
			{
				mfa.POST("/generate", mfaHandler.Generate)
				mfa.POST("/enable", mfaHandler.Enable)
				mfa.POST("/disable", mfaHandler.Disable)
			}
		}
	}

	return r
}
