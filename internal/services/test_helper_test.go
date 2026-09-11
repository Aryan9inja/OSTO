package services

import (
	"testing"
	"time"

	"github.com/user/auth-cli-system/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTestDB(t *testing.T) *gorm.DB {
	// In-memory SQLite with unique connection to keep state per test
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Clean tables before running
	_ = db.Migrator().DropTable(&models.Session{}, &models.User{})

	if err := db.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
		t.Fatalf("failed to auto-migrate test models: %v", err)
	}

	return db
}

func setupTestServices(t *testing.T) (*AuthService, *SessionService, *TOTPService, *gorm.DB) {
	db := setupTestDB(t)
	totpSvc := NewTOTPService("TestSystem")
	sessionSvc := NewSessionService(db, 30*time.Minute)
	authSvc := NewAuthService(db, totpSvc, sessionSvc, 5, 15*time.Minute)
	return authSvc, sessionSvc, totpSvc, db
}
