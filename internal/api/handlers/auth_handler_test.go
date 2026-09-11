package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/auth-cli-system/internal/api/middleware"
	"github.com/user/auth-cli-system/internal/models"
	"github.com/user/auth-cli-system/internal/services"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestAPI(t *testing.T) (*gin.Engine, *services.AuthService, *services.SessionService) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	_ = db.Migrator().DropTable(&models.Session{}, &models.User{})
	_ = db.AutoMigrate(&models.User{}, &models.Session{})

	totpSvc := services.NewTOTPService("TestIssuer")
	sessionSvc := services.NewSessionService(db, 30*time.Minute)
	authSvc := services.NewAuthService(db, totpSvc, sessionSvc, 5, 15*time.Minute)

	r := gin.New()
	authHandler := NewAuthHandler(authSvc, sessionSvc)
	userHandler := NewUserHandler()
	mfaHandler := NewMFAHandler(authSvc)

	api := r.Group("/api/v1")
	{
		api.POST("/auth/register", authHandler.Register)
		api.POST("/auth/login", authHandler.Login)

		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(sessionSvc))
		{
			protected.POST("/auth/logout", authHandler.Logout)
			protected.GET("/user/me", userHandler.WhoAmI)
			protected.POST("/mfa/generate", mfaHandler.Generate)
			protected.POST("/mfa/enable", mfaHandler.Enable)
			protected.POST("/mfa/disable", mfaHandler.Disable)
		}
	}

	return r, authSvc, sessionSvc
}

func TestHTTP_RegisterAndLoginFlow(t *testing.T) {
	router, _, _ := setupTestAPI(t)

	// 1. Register User
	regPayload := map[string]string{
		"username": "bobsmith",
		"password": "mySecurePassword123",
	}
	regBody, _ := json.Marshal(regPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Login with valid credentials
	loginPayload := map[string]string{
		"username": "bobsmith",
		"password": "mySecurePassword123",
	}
	loginBody, _ := json.Marshal(loginPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var loginResp struct {
		Status string `json:"status"`
		Token  string `json:"token"`
		User   struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatalf("expected token in login response")
	}

	// 3. Access protected /user/me with session token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/user/me", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK from protected /user/me, got %d", w.Code)
	}

	// 4. Access protected /user/me without token should return 401
	req = httptest.NewRequest(http.MethodGet, "/api/v1/user/me", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized without token, got %d", w.Code)
	}

	// 5. Logout
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK on logout, got %d", w.Code)
	}

	// 6. Access protected /user/me with revoked token should return 401
	req = httptest.NewRequest(http.MethodGet, "/api/v1/user/me", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 Unauthorized with revoked token, got %d", w.Code)
	}
}
