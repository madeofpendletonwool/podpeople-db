package api

import (
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
)

// AdminLoginPageHandler handles rendering the admin login page
func (s *Server) AdminLoginPageHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.TemplateManager.Render(w, "admin_login.html", nil); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// AdminLoginHandler handles admin login
func (s *Server) AdminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate user
	admin, err := s.AdminService.Authenticate(username, password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Set session data
	s.SessionManager.Put(r.Context(), "authenticated", true)
	s.SessionManager.Put(r.Context(), "adminID", admin.ID)
	s.SessionManager.Put(r.Context(), "adminUsername", admin.Username)

	// Redirect to dashboard
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

	// Get admin users
	admins, err := s.AdminService.GetAllAdmins()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create combined data structure
	data := struct {
		PendingHosts []models.Host  `json:"pendingHosts"`
		Admins       []models.Admin `json:"admins"`
	}{
		PendingHosts: pendingHosts,
		Admins:       admins,
	}

	log.Printf("Found %d pending hosts and %d admins", len(pendingHosts), len(admins))

	if err := s.TemplateManager.Render(w, "admin_dashboard", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
