package db

import (
	"log"
	"os"

	"github.com/madeofpendletonwool/podpeople-db/internal/models" // Update with actual import path
)

// applyMigrations runs all database migrations
func applyMigrations() error {
	log.Println("Applying database migrations...")

	// Create tables
	err := createTables()
	if err != nil {
		return err
	}

	// Create indexes
	err = createIndexes()
	if err != nil {
		return err
	}

	// Ensure admin user exists
	err = ensureAdminUser()
	if err != nil {
		return err
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// createTables creates database tables if they don't exist
func createTables() error {
	_, err := DB.Exec(`
		-- Hosts table
		CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			link TEXT,
			img TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Podcasts table
		CREATE TABLE IF NOT EXISTS podcasts (
			id INTEGER PRIMARY KEY,
			title TEXT NOT NULL,
			feed_url TEXT
		);

		-- Host-Podcast associations table
		CREATE TABLE IF NOT EXISTS host_podcasts (
			host_id INTEGER,
			podcast_id INTEGER,
			role TEXT NOT NULL,
			status TEXT DEFAULT 'pending',
			approval_key TEXT UNIQUE,
			approval_key_expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (host_id, podcast_id),
			FOREIGN KEY (host_id) REFERENCES hosts(id),
			FOREIGN KEY (podcast_id) REFERENCES podcasts(id)
		);

		-- Admins table
		CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		-- Sessions table
		CREATE TABLE IF NOT EXISTS sessions (
		    token TEXT PRIMARY KEY,
		    data BLOB NOT NULL,
		    expiry TIMESTAMP NOT NULL
		);

		-- Episodes table
		CREATE TABLE IF NOT EXISTS episodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			podcast_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			audio_url TEXT UNIQUE NOT NULL,
			pub_date DATETIME,
			duration INTEGER, -- duration in seconds
			season_number INTEGER,
			episode_number INTEGER,
			image_url TEXT,
			link TEXT,
			guid TEXT,
			status TEXT DEFAULT 'pending', -- pending, approved, rejected
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (podcast_id) REFERENCES podcasts(id)
		);

		-- Episode guests table - many-to-many relationship
		CREATE TABLE IF NOT EXISTS episode_guests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			episode_id INTEGER NOT NULL,
			host_id INTEGER NOT NULL,
			role TEXT NOT NULL DEFAULT 'guest', -- guest, host, co-host
			status TEXT DEFAULT 'pending', -- pending, approved, rejected
			approval_key TEXT UNIQUE,
			approval_key_expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(episode_id, host_id),
			FOREIGN KEY (episode_id) REFERENCES episodes(id),
			FOREIGN KEY (host_id) REFERENCES hosts(id)
		);
	`)

	if err != nil {
		return err
	}

	return nil
}

// createIndexes creates indexes on the tables
func createIndexes() error {
	_, err := DB.Exec(`
		-- Add IF NOT EXISTS to index creation
		CREATE INDEX IF NOT EXISTS idx_host_podcasts_host_id ON host_podcasts(host_id);
		CREATE INDEX IF NOT EXISTS idx_host_podcasts_podcast_id ON host_podcasts(podcast_id);
		CREATE INDEX IF NOT EXISTS idx_host_podcasts_status ON host_podcasts(status);
		CREATE INDEX IF NOT EXISTS idx_hosts_name ON hosts(name);
		
		-- Episode indexes
		CREATE INDEX IF NOT EXISTS idx_episodes_podcast_id ON episodes(podcast_id);
		CREATE INDEX IF NOT EXISTS idx_episodes_audio_url ON episodes(audio_url);
		CREATE INDEX IF NOT EXISTS idx_episodes_status ON episodes(status);
		CREATE INDEX IF NOT EXISTS idx_episodes_pub_date ON episodes(pub_date);
		
		-- Episode guests indexes
		CREATE INDEX IF NOT EXISTS idx_episode_guests_episode_id ON episode_guests(episode_id);
		CREATE INDEX IF NOT EXISTS idx_episode_guests_host_id ON episode_guests(host_id);
		CREATE INDEX IF NOT EXISTS idx_episode_guests_status ON episode_guests(status);
	`)

	if err != nil {
		return err
	}

	return nil
}

// ensureAdminUser ensures that at least one admin user exists
func ensureAdminUser() error {
	// Check if any admin user exists
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		// No admin exists, create one
		username := os.Getenv("ADMIN_USERNAME")
		password := os.Getenv("ADMIN_PASSWORD")

		if username == "" || password == "" {
			// Use default values if environment variables are not set
			username = "admin"
			password = "admin"
			log.Println("Warning: Using default admin credentials. Please change them immediately.")
		}

		admin := models.Admin{
			Username: username,
		}

		// Set password (will hash it)
		if err = admin.SetPassword(password); err != nil {
			return err
		}

		// Create admin
		if err = admin.Create(DB); err != nil {
			return err
		}

		log.Printf("Admin user '%s' created successfully\n", username)
	}

	return nil
}
