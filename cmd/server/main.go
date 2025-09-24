package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/madeofpendletonwool/podpeople-db/internal/api"
	"github.com/madeofpendletonwool/podpeople-db/internal/config"
	"github.com/madeofpendletonwool/podpeople-db/internal/db"
	"github.com/madeofpendletonwool/podpeople-db/internal/services"
	"github.com/madeofpendletonwool/podpeople-db/internal/templates"
	"github.com/madeofpendletonwool/podpeople-db/internal/utils"
)

func main() {
	// Parse command line flags
	var templateDir = flag.String("templates", "./templates", "Path to templates directory")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	if err := db.Initialize(cfg.Database.Path); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize template manager
	tmpl, err := templates.NewTemplateManager(*templateDir)
	if err != nil {
		log.Fatalf("Failed to initialize template manager: %v", err)
	}

	// Initialize services
	notificationService := utils.NewNotificationService(cfg)
	podcastService := services.NewPodcastService(cfg)
	hostService := services.NewHostService(cfg, notificationService, db.DB)
	adminService := services.NewAdminService(cfg)

	// Initialize server
	server := api.NewServer(cfg, tmpl, podcastService, hostService, adminService)

	// Configure HTTP server
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Server.Port),
		Handler: server,
	}

	// Handle graceful shutdown
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop

		log.Println("Shutting down server...")
		if err := httpServer.Close(); err != nil {
			log.Printf("Error during server shutdown: %v", err)
		}
		log.Println("Server stopped")
	}()

	// Start the server
	log.Printf("Server is running on http://0.0.0.0:%s", cfg.Server.Port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
}
