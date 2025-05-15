package services

import (
	"fmt"

	"github.com/madeofpendletonwool/podpeople-db/internal/config"
	"github.com/madeofpendletonwool/podpeople-db/internal/db"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
)

// AdminService handles admin-related operations
type AdminService struct {
	Config *config.Config
}

// NewAdminService creates a new admin service
func NewAdminService(cfg *config.Config) *AdminService {
	return &AdminService{
		Config: cfg,
	}
}

// Authenticate authenticates an admin user
func (s *AdminService) Authenticate(username, password string) (*models.Admin, error) {
	var admin models.Admin
	if err := admin.FindByUsername(db.DB, username); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !admin.CheckPassword(password) {
		return nil, fmt.Errorf("invalid credentials")
	}

	return &admin, nil
}

// GetPendingHosts gets all hosts pending approval
func (s *AdminService) GetPendingHosts() ([]models.Host, error) {
	return models.GetPendingHosts(db.DB)
}

// GetAllAdmins gets all admin users
func (s *AdminService) GetAllAdmins() ([]models.Admin, error) {
	return models.GetAllAdmins(db.DB)
}

// AddAdmin adds a new admin user
func (s *AdminService) AddAdmin(username, password string) (*models.Admin, error) {
	admin := models.Admin{
		Username: username,
	}

	if err := admin.SetPassword(password); err != nil {
		return nil, fmt.Errorf("error setting password: %w", err)
	}

	if err := admin.Create(db.DB); err != nil {
		return nil, fmt.Errorf("error creating admin: %w", err)
	}

	return &admin, nil
}

// UpdateAdmin updates an admin user
func (s *AdminService) UpdateAdmin(id int, username, password string) error {
	var admin models.Admin
	if err := admin.FindByID(db.DB, id); err != nil {
		return fmt.Errorf("admin not found: %w", err)
	}

	admin.Username = username

	// Update password if provided
	if password != "" {
		if err := admin.SetPassword(password); err != nil {
			return fmt.Errorf("error setting password: %w", err)
		}
	}

	if err := admin.Update(db.DB); err != nil {
		return fmt.Errorf("error updating admin: %w", err)
	}

	return nil
}

// DeleteAdmin deletes an admin user
func (s *AdminService) DeleteAdmin(id int) error {
	// Check that we're not deleting the last admin
	count, err := models.CountAdmins(db.DB)
	if err != nil {
		return fmt.Errorf("error counting admins: %w", err)
	}

	if count <= 1 {
		return fmt.Errorf("cannot delete the last admin user")
	}

	var admin models.Admin
	if err := admin.FindByID(db.DB, id); err != nil {
		return fmt.Errorf("admin not found: %w", err)
	}

	if err := admin.Delete(db.DB); err != nil {
		return fmt.Errorf("error deleting admin: %w", err)
	}

	return nil
}
