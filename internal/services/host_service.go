package services

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/madeofpendletonwool/podpeople-db/internal/config"
	"github.com/madeofpendletonwool/podpeople-db/internal/db"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
	"github.com/madeofpendletonwool/podpeople-db/internal/utils"
)

// HostService handles host-related operations
type HostService struct {
	Config              *config.Config
	NotificationService *utils.NotificationService
}

// NewHostService creates a new host service
func NewHostService(cfg *config.Config, notificationSvc *utils.NotificationService) *HostService {
	return &HostService{
		Config:              cfg,
		NotificationService: notificationSvc,
	}
}

// SubmitHost submits a new host for approval
func (s *HostService) SubmitHost(host models.Host, podcastID int, role string) error {
	return db.Transaction(func(tx *sql.Tx) error {
		// Check if image URL is valid
		if host.Img != "" && !utils.IsValidImageURL(host.Img) {
			host.Img = "" // Clear invalid image URL
		}

		// Check if host exists
		var hostID int
		err := tx.QueryRow("SELECT id FROM hosts WHERE name = ?", host.Name).Scan(&hostID)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("error checking for existing host: %w", err)
		}

		if err == sql.ErrNoRows {
			// Host doesn't exist, create a new one
			result, err := tx.Exec(`
				INSERT INTO hosts (name, description, link, img)
				VALUES (?, ?, ?, ?)`,
				host.Name, host.Description, host.Link, host.Img)
			if err != nil {
				return fmt.Errorf("error creating host: %w", err)
			}

			hostID64, err := result.LastInsertId()
			if err != nil {
				return fmt.Errorf("error getting host ID: %w", err)
			}
			hostID = int(hostID64)
		}

		// Insert or update the podcast
		_, err = tx.Exec(`
			INSERT INTO podcasts (id, title)
			VALUES (?, ?)
			ON CONFLICT (id) DO UPDATE SET
			title = excluded.title`,
			podcastID, host.Podcasts[0].Title)
		if err != nil {
			return fmt.Errorf("error upserting podcast: %w", err)
		}

		// Create host-podcast association
		_, err = tx.Exec(`
			INSERT INTO host_podcasts (host_id, podcast_id, role, status)
			VALUES (?, ?, ?, 'pending')
			ON CONFLICT (host_id, podcast_id) DO UPDATE SET
			role = excluded.role,
			status = 'pending'`,
			hostID, podcastID, role)
		if err != nil {
			return fmt.Errorf("error creating host-podcast association: %w", err)
		}

		// Generate approval key
		approvalKey, err := utils.GenerateApprovalKey()
		if err != nil {
			return fmt.Errorf("error generating approval key: %w", err)
		}

		// Set expiration time to 24 hours from now
		expiresAt := time.Now().Add(24 * time.Hour)

		// Update approval key for all pending associations for this host
		_, err = tx.Exec(`
			UPDATE host_podcasts
			SET approval_key = ?, approval_key_expires_at = ?
			WHERE host_id = ? AND status = 'pending'`,
			approvalKey, expiresAt, hostID)
		if err != nil {
			return fmt.Errorf("error updating approval key: %w", err)
		}

		// Set host ID for return
		host.ID = hostID

		// Get the complete host info
		var h models.Host
		err = h.FindByID(db.DB, hostID)
		if err != nil {
			return fmt.Errorf("error getting host info: %w", err)
		}

		// Send notification
		err = s.NotificationService.SendNewHostNotification(h, approvalKey)
		if err != nil {
			// Just log the error, don't fail the transaction
			fmt.Printf("Warning: Failed to send notification: %v\n", err)
		}

		return nil
	})
}

// ApproveHost approves a pending host
func (s *HostService) ApproveHost(hostID int) error {
	_, err := db.DB.Exec(`
		UPDATE host_podcasts
		SET status = 'approved'
		WHERE host_id = ?
		AND status = 'pending'`,
		hostID)
	return err
}

// ApproveHostByKey approves a host using an approval key
func (s *HostService) ApproveHostByKey(key string) (int64, error) {
	result, err := db.DB.Exec(`
		UPDATE host_podcasts
		SET status = 'approved',
			approval_key = NULL,
			approval_key_expires_at = NULL
		WHERE approval_key = ?
		AND approval_key_expires_at > CURRENT_TIMESTAMP
		AND status = 'pending'`,
		key)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// RejectHost rejects a host
func (s *HostService) RejectHost(hostID int) error {
	return db.Transaction(func(tx *sql.Tx) error {
		// Delete host-podcast associations
		_, err := tx.Exec("DELETE FROM host_podcasts WHERE host_id = ?", hostID)
		if err != nil {
			return err
		}

		// Delete the host
		_, err = tx.Exec("DELETE FROM hosts WHERE id = ?", hostID)
		return err
	})
}

// UpdateHost updates a host's details
func (s *HostService) UpdateHost(host models.Host) error {
	return db.Transaction(func(tx *sql.Tx) error {
		// Update host details
		_, err := tx.Exec(`
			UPDATE hosts
			SET name = ?, description = ?, link = ?, img = ?
			WHERE id = ?`,
			host.Name, host.Description, host.Link, host.Img, host.ID)
		if err != nil {
			return err
		}

		// Update role in host_podcasts table if provided
		if len(host.Podcasts) > 0 {
			_, err = tx.Exec(`
				UPDATE host_podcasts
				SET role = ?
				WHERE host_id = ?`,
				host.Podcasts[0].Role, host.ID)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// GetRecentHosts gets recently approved hosts
func (s *HostService) GetRecentHosts(limit int) ([]models.Host, error) {
	return models.GetRecentApprovedHosts(db.DB, limit)
}

// SearchHosts searches for hosts by name
func (s *HostService) SearchHosts(term string, limit int) ([]models.Host, error) {
	return models.SearchHosts(db.DB, term, limit)
}
