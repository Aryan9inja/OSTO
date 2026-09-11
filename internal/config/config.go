package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all server and application configuration
type Config struct {
	// Server
	ServerPort string
	ServerURL  string

	// Database
	DBDriver   string // "postgres" or "sqlite"
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string
	SqlitePath string

	// Security & Auth Policies
	SessionTimeout        time.Duration
	MaxFailedAttempts     int
	LockoutDuration       time.Duration
	TOTPIssuer            string
}

// LoadConfig loads configuration from environment variables with safe defaults
func LoadConfig() *Config {
	sessionTimeoutMin := getEnvAsInt("SESSION_TIMEOUT_MINUTES", 30)
	lockoutDurationMin := getEnvAsInt("LOCKOUT_DURATION_MINUTES", 15)
	maxFailedAttempts := getEnvAsInt("MAX_FAILED_ATTEMPTS", 5)

	return &Config{
		ServerPort:            getEnv("SERVER_PORT", "8080"),
		ServerURL:             getEnv("SERVER_URL", "http://localhost:8080"),
		DBDriver:              getEnv("DB_DRIVER", "postgres"),
		DBHost:                getEnv("DB_HOST", "localhost"),
		DBPort:                getEnv("DB_PORT", "5432"),
		DBUser:                getEnv("DB_USER", "authuser"),
		DBPassword:            getEnv("DB_PASSWORD", "authpassword"),
		DBName:                getEnv("DB_NAME", "authdb"),
		DBSSLMode:             getEnv("DB_SSLMODE", "disable"),
		SqlitePath:            getEnv("SQLITE_PATH", "auth.db"),
		SessionTimeout:        time.Duration(sessionTimeoutMin) * time.Minute,
		MaxFailedAttempts:     maxFailedAttempts,
		LockoutDuration:       time.Duration(lockoutDurationMin) * time.Minute,
		TOTPIssuer:            getEnv("TOTP_ISSUER", "AuthCLISystem"),
	}
}

// DSN returns the PostgreSQL connection string or SQLite file path
func (c *Config) DSN() string {
	if c.DBDriver == "sqlite" {
		return c.SqlitePath
	}
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=UTC",
		c.DBHost, c.DBPort, c.DBUser, c.DBPassword, c.DBName, c.DBSSLMode)
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return fallback
}
