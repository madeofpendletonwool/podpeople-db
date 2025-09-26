package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/madeofpendletonwool/podpeople-db/internal/db"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
)

// AdminLoginPageHandler handles rendering the admin login page
func (s *Server) AdminLoginPageHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is already authenticated
	if s.SessionManager.GetBool(r.Context(), "authenticated") {
		// Already authenticated, redirect to dashboard
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}
	
	// Not authenticated, show login form
	if err := s.TemplateManager.Render(w, "admin_login.html", nil); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// AdminLoginHandler handles admin login
func (s *Server) AdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse both form data and multipart form data
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err := r.ParseForm(); err != nil {
			// Check if this is an AJAX request
			if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid form data"})
				return
			}
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate user
	admin, err := s.AdminService.Authenticate(username, password)
	if err != nil {
		// Check if this is an AJAX request
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username or password"})
			return
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session data
	s.SessionManager.Put(r.Context(), "authenticated", true)
	s.SessionManager.Put(r.Context(), "adminID", admin.ID)
	s.SessionManager.Put(r.Context(), "adminUsername", admin.Username)

	// Check if this is an AJAX request
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"redirect": "/admin/dashboard",
		})
		return
	}

	// Redirect to dashboard for regular form submissions
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// AdminDashboardHandler handles the admin dashboard
func (s *Server) AdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get pending hosts
	pendingHosts, err := s.AdminService.GetPendingHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get pending episode guests
	pendingEpisodeGuests, err := s.AdminService.GetPendingEpisodeGuests()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get admin users
	admins, err := s.AdminService.GetAllAdmins()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create combined data structure
	data := struct {
		PendingHosts         []models.Host                        `json:"pendingHosts"`
		PendingEpisodeGuests []models.EpisodeGuestWithDetails     `json:"pendingEpisodeGuests"`
		Admins               []models.Admin                       `json:"admins"`
	}{
		PendingHosts:         pendingHosts,
		PendingEpisodeGuests: pendingEpisodeGuests,
		Admins:               admins,
	}

	log.Printf("Found %d pending hosts, %d pending episode guests, and %d admins", 
		len(pendingHosts), len(pendingEpisodeGuests), len(admins))

	if err := s.TemplateManager.Render(w, "admin_dashboard", data); err != nil {
		log.Printf("Error rendering admin dashboard template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Successfully rendered admin dashboard")
}

// ApproveHostHandler handles approving a host
func (s *Server) ApproveHostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hostID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	if err := s.HostService.ApproveHost(hostID); err != nil {
		http.Error(w, "Failed to approve host", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// AutoApproveHandler handles one-time approval links
func (s *Server) AutoApproveHandler(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")

	rowsAffected, err := s.HostService.ApproveHostByKey(key)
	if err != nil {
		http.Error(w, "Failed to process approval", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "Invalid or expired approval key", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Host successfully approved"))
}

// RejectHostHandler handles rejecting a host
func (s *Server) RejectHostHandler(w http.ResponseWriter, r *http.Request) {
	hostID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	if err := s.HostService.RejectHost(hostID); err != nil {
		http.Error(w, "Failed to reject host", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// ApproveEpisodeGuestHandler handles approving an episode guest
func (s *Server) ApproveEpisodeGuestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	guestID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid episode guest ID", http.StatusBadRequest)
		return
	}

	if err := s.EpisodeService.ApproveEpisodeGuest(guestID); err != nil {
		http.Error(w, "Failed to approve episode guest", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// RejectEpisodeGuestHandler handles rejecting an episode guest
func (s *Server) RejectEpisodeGuestHandler(w http.ResponseWriter, r *http.Request) {
	guestID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid episode guest ID", http.StatusBadRequest)
		return
	}

	if err := s.EpisodeService.RejectEpisodeGuest(guestID); err != nil {
		http.Error(w, "Failed to reject episode guest", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// AddAdminHandler handles adding a new admin
func (s *Server) AddAdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Add new admin
	_, err := s.AdminService.AddAdmin(username, password)
	if err != nil {
		http.Error(w, "Error creating admin user", http.StatusInternalServerError)
		return
	}

	// Get updated list of admins
	admins, err := s.AdminService.GetAllAdmins()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return just the admin list HTML
	if err := s.TemplateManager.Render(w, "admin-users-list", admins); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// EditAdminHandler handles editing an admin
func (s *Server) EditAdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	adminID, err := strconv.Atoi(r.FormValue("adminId"))
	if err != nil {
		http.Error(w, "Invalid admin ID", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password") // May be empty if not changing password

	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	// Update admin
	if err := s.AdminService.UpdateAdmin(adminID, username, password); err != nil {
		http.Error(w, "Error updating admin user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// DeleteAdminHandler handles deleting an admin
func (s *Server) DeleteAdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	adminID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid admin ID", http.StatusBadRequest)
		return
	}

	// Delete admin
	if err := s.AdminService.DeleteAdmin(adminID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ImportDatabaseHandler handles importing a SQLite database file
func (s *Server) ImportDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (32MB max file size)
	err := r.ParseMultipartForm(32 << 20) // 32MB
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to parse form: " + err.Error()})
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("database")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "No database file provided: " + err.Error()})
		return
	}
	defer file.Close()

	// Validate file size (limit to 100MB)
	if header.Size > 100<<20 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "File too large. Maximum size is 100MB"})
		return
	}

	// Validate file extension
	ext := filepath.Ext(header.Filename)
	validExts := map[string]bool{".sqlite": true, ".sqlite3": true, ".db": true}
	if !validExts[ext] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid file type. Only .sqlite, .sqlite3, and .db files are allowed"})
		return
	}

	// Create a temporary file to validate the uploaded database
	tempFile, err := os.CreateTemp("", "import_*.sqlite")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create temporary file: " + err.Error()})
		return
	}
	defer os.Remove(tempFile.Name()) // Clean up temp file
	defer tempFile.Close()

	// Copy uploaded file to temp file
	_, err = io.Copy(tempFile, file)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save uploaded file: " + err.Error()})
		return
	}

	// Validate that the file is a valid SQLite database
	testDB, err := sql.Open("sqlite3", tempFile.Name())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid SQLite file: " + err.Error()})
		return
	}
	defer testDB.Close()

	// Test that we can query the database
	var dbVersion string
	err = testDB.QueryRow("SELECT sqlite_version()").Scan(&dbVersion)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "File is not a valid SQLite database: " + err.Error()})
		return
	}

	// Count records for reporting (optional)
	var recordCount int64
	recordCount = 0 // Default if we can't count

	// Try to count records from main tables
	tables := []string{"hosts", "host_podcasts", "admins", "episodes", "episode_hosts"}
	for _, table := range tables {
		var count int64
		query := fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
		if err := testDB.QueryRow(query).Scan(&count); err == nil {
			recordCount += count
		}
	}

	// Create backup of current database
	currentDBPath := s.Config.Database.Path
	backupPath := currentDBPath + ".backup." + fmt.Sprintf("%d", os.Getpid())

	// Copy current database to backup
	if _, err := os.Stat(currentDBPath); err == nil {
		currentDB, err := os.Open(currentDBPath)
		if err != nil {
			// Try to reinitialize the original database
			db.Initialize(currentDBPath)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to backup current database: " + err.Error()})
			return
		}
		defer currentDB.Close()

		backupDB, err := os.Create(backupPath)
		if err != nil {
			currentDB.Close()
			db.Initialize(currentDBPath)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create backup file: " + err.Error()})
			return
		}
		defer backupDB.Close()

		_, err = io.Copy(backupDB, currentDB)
		if err != nil {
			currentDB.Close()
			backupDB.Close()
			os.Remove(backupPath)
			db.Initialize(currentDBPath)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create backup: " + err.Error()})
			return
		}
	}

	// Replace the current database with the uploaded file
	err = os.Rename(tempFile.Name(), currentDBPath)
	if err != nil {
		// If rename fails, try copy
		tempFile.Seek(0, 0) // Reset file pointer
		newDB, err := os.Create(currentDBPath)
		if err != nil {
			// Restore backup if it exists
			if _, backupErr := os.Stat(backupPath); backupErr == nil {
				os.Rename(backupPath, currentDBPath)
			}
			db.Initialize(currentDBPath)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to replace database: " + err.Error()})
			return
		}
		defer newDB.Close()

		_, err = io.Copy(newDB, tempFile)
		if err != nil {
			newDB.Close()
			// Restore backup if it exists
			if _, backupErr := os.Stat(backupPath); backupErr == nil {
				os.Rename(backupPath, currentDBPath)
			}
			db.Initialize(currentDBPath)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to copy database: " + err.Error()})
			return
		}
	}

	// Reinitialize the database connection with the new file
	err = db.Initialize(currentDBPath)
	if err != nil {
		// Restore backup if something goes wrong
		if _, backupErr := os.Stat(backupPath); backupErr == nil {
			os.Rename(backupPath, currentDBPath)
			db.Initialize(currentDBPath) // Try to restore original
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to initialize new database: " + err.Error()})
		return
	}

	// Reinitialize the session manager with the new database connection
	s.ReinitializeSessionManager()

	// Clean up backup file on success
	if _, err := os.Stat(backupPath); err == nil {
		os.Remove(backupPath)
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"message":         "Database imported successfully",
		"recordsImported": recordCount,
		"filename":        header.Filename,
	})

	log.Printf("Database imported successfully from file: %s (%d records)", header.Filename, recordCount)
}
