package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/user/auth-cli-system/internal/api"
	"github.com/user/auth-cli-system/internal/config"
	"github.com/user/auth-cli-system/internal/database"
	"github.com/user/auth-cli-system/internal/services"
)

func main() {
	log.Println("Starting Auth & 2FA API Server...")

	// 1. Load configuration
	cfg := config.LoadConfig()

	// 2. Initialize database
	db, err := database.InitDB(cfg)
	if err != nil {
		log.Fatalf("Fatal: Database initialization failed: %v", err)
	}

	// 3. Initialize domain services
	totpService := services.NewTOTPService(cfg.TOTPIssuer)
	sessionService := services.NewSessionService(db, cfg.SessionTimeout)
	authService := services.NewAuthService(
		db,
		totpService,
		sessionService,
		cfg.MaxFailedAttempts,
		cfg.LockoutDuration,
	)

	// 4. Setup Gin HTTP router
	router := api.SetupRouter(authService, sessionService)

	serverAddr := fmt.Sprintf(":%s", cfg.ServerPort)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 5. Run server in background goroutine
	go func() {
		log.Printf("Server listening on port %s", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server ListenAndServe error: %v", err)
		}
	}()

	// 6. Graceful shutdown on SIGINT or SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped successfully")
}
