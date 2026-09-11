package database

import (
	"fmt"
	"log"
	"time"

	"github.com/user/auth-cli-system/internal/config"
	"github.com/user/auth-cli-system/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InitDB initializes the database connection and runs auto-migrations
func InitDB(cfg *config.Config) (*gorm.DB, error) {
	var dialector gorm.Dialector

	if cfg.DBDriver == "sqlite" {
		dialector = sqlite.Open(cfg.SqlitePath)
	} else {
		dialector = postgres.Open(cfg.DSN())
	}

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	}

	var db *gorm.DB
	var err error

	// Retry connection with exponential backoff for container environments
	maxRetries := 15
	for i := 1; i <= maxRetries; i++ {
		db, err = gorm.Open(dialector, gormConfig)
		if err == nil {
			sqlDB, dbErr := db.DB()
			if dbErr == nil {
				if pingErr := sqlDB.Ping(); pingErr == nil {
					// Configure connection pooling
					sqlDB.SetMaxIdleConns(10)
					sqlDB.SetMaxOpenConns(50)
					sqlDB.SetConnMaxLifetime(time.Hour)
					log.Printf("Successfully connected to database (%s)", cfg.DBDriver)
					break
				}
			}
		}

		if i == maxRetries {
			return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
		}

		log.Printf("Waiting for database connection (attempt %d/%d)...", i, maxRetries)
		time.Sleep(2 * time.Second)
	}

	// Auto-migrate schema
	if err := db.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
		return nil, fmt.Errorf("failed to run auto-migrations: %w", err)
	}

	log.Println("Database schema auto-migrations applied successfully")
	return db, nil
}
