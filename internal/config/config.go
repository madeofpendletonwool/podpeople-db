package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the application configuration
type Config struct {
	Server     ServerConfig
	Database   DatabaseConfig
	Admin      AdminConfig
	Ntfy       NtfyConfig
	PodcastAPI PodcastAPIConfig
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port    string
	BaseURL string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Path string
}

// AdminConfig holds admin configuration
type AdminConfig struct {
	Username string
	Password string
}

// NtfyConfig holds notification configuration
type NtfyConfig struct {
	URL   string
	Topic string
}

// PodcastAPIConfig holds podcast API configuration
type PodcastAPIConfig struct {
	SearchAPIURL string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Set default values
	cfg := &Config{
		Server: ServerConfig{
			Port:    "8085",
			BaseURL: getEnv("BASE_URL", "http://localhost:8085"),
		},
		Database: DatabaseConfig{
			Path: getEnv("DB_PATH", "/app/podpeople-data/podpeopledb.sqlite"),
		},
		Admin: AdminConfig{
			Username: getEnv("ADMIN_USERNAME", "admin"),
			Password: getEnv("ADMIN_PASSWORD", "admin"),
		},
		Ntfy: NtfyConfig{
			URL:   getEnv("NTFY_URL", "https://ntfy.sh"),
			Topic: getEnv("NTFY_TOPIC", ""),
		},
		PodcastAPI: PodcastAPIConfig{
			SearchAPIURL: getEnv("SEARCH_API_URL", "https://search.pinepods.online"),
		},
	}

	// Ensure data directory exists
	dataDir := filepath.Dir(cfg.Database.Path)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory %s: %w", dataDir, err)
	}

	// Check for required configurations
	if cfg.PodcastAPI.SearchAPIURL == "" {
		return nil, fmt.Errorf("SEARCH_API_URL is required")
	}

	// Show warning for default admin credentials
	if cfg.Admin.Username == "admin" && cfg.Admin.Password == "admin" {
		fmt.Println("WARNING: Using default admin credentials. Please change them immediately.")
	}

	return cfg, nil
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	// Remove quotes if present (sometimes happens with docker-compose env vars)
	if len(value) > 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}

	return value
}
