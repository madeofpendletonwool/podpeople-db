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
	db                  *sql.DB
}

// NewHostService creates a new host service
func NewHostService(cfg *config.Config, notificationSvc *utils.NotificationService, database *sql.DB) *HostService {
	return &HostService{
		Config:              cfg,
		NotificationService: notificationSvc,
		db:                  database,
	}
}

// Modified SubmitHost function to return the host ID
func (s *HostService) SubmitHost(host models.Host, podcastID int, role string) (int, error) {
	var resultHostID int // Define this outside the transaction to return it

	err := db.Transaction(func(tx *sql.Tx) error {
		// Check if image URL is valid
		if host.Img != "" && !utils.IsValidImageURL(host.Img) {
			host.Img = "" // Clear invalid image URL
		}

		// Check if host exists — match on the normalized name so "Griffin McElroy",
		// "Griffin Mcelroy" and "griffin  mcelroy" resolve to the same canonical host.
		nameNormalized := models.NormalizeName(host.Name)
		var hostID int
		err := tx.QueryRow("SELECT id FROM hosts WHERE name_normalized = ?", nameNormalized).Scan(&hostID)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("error checking for existing host: %w", err)
		}

		if err == sql.ErrNoRows {
			// Host doesn't exist, create a new one
			result, err := tx.Exec(`
				INSERT INTO hosts (name, name_normalized, description, link, img)
				VALUES (?, ?, ?, ?, ?)`,
				host.Name, nameNormalized, host.Description, host.Link, host.Img)
			if err != nil {
				return fmt.Errorf("error creating host: %w", err)
			}

			hostID64, err := result.LastInsertId()
			if err != nil {
				return fmt.Errorf("error getting host ID: %w", err)
			}
			hostID = int(hostID64)
		}

		// Set the result ID to be returned
		resultHostID = hostID

		// Insert or update the podcast. Persist feed_url when the caller supplied it so the DB is
		// self-sufficient (avoids re-resolving feed URLs from the index on every host-search).
		// COALESCE keeps any existing non-empty feed_url if this submission didn't carry one.
		feedURL := host.Podcasts[0].FeedURL
		_, err = tx.Exec(`
			INSERT INTO podcasts (id, title, feed_url)
			VALUES (?, ?, NULLIF(?, ''))
			ON CONFLICT (id) DO UPDATE SET
			title = excluded.title,
			feed_url = COALESCE(NULLIF(excluded.feed_url, ''), podcasts.feed_url)`,
			podcastID, host.Podcasts[0].Title, feedURL)
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

		// Create a new host instance for notification
		notificationHost := models.Host{
			ID:          hostID,
			Name:        host.Name,
			Description: host.Description,
			Link:        host.Link,
			Img:         host.Img,
		}

		// Send notification
		err = s.NotificationService.SendNewHostNotification(notificationHost, approvalKey)
		if err != nil {
			// Just log the error, don't fail the transaction
			fmt.Printf("Warning: Failed to send notification: %v\n", err)
		}

		return nil
	})

	if err != nil {
		return 0, err
	}

	return resultHostID, nil
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

// GetStats returns database statistics
func (s *HostService) GetStats() (models.Stats, error) {
	var stats models.Stats

	// Get total hosts
	err := s.db.QueryRow("SELECT COUNT(*) FROM hosts").Scan(&stats.TotalHosts)
	if err != nil {
		return stats, err
	}

	// Get total podcasts (distinct)
	err = s.db.QueryRow("SELECT COUNT(DISTINCT podcast_id) FROM host_podcasts").Scan(&stats.TotalPodcasts)
	if err != nil {
		return stats, err
	}

	// Get pending hosts
	err = s.db.QueryRow("SELECT COUNT(*) FROM host_podcasts WHERE status = 'pending'").Scan(&stats.PendingHosts)
	if err != nil {
		return stats, err
	}

	// Get approved hosts
	err = s.db.QueryRow("SELECT COUNT(*) FROM host_podcasts WHERE status = 'approved'").Scan(&stats.ApprovedHosts)
	if err != nil {
		return stats, err
	}

	// Get episodes with guests (count distinct episodes that have episode_guests entries)
	err = s.db.QueryRow("SELECT COUNT(DISTINCT episode_id) FROM episode_guests WHERE status = 'approved'").Scan(&stats.EpisodesWithGuests)
	if err != nil {
		return stats, err
	}

	// Get pending episode guests
	err = s.db.QueryRow("SELECT COUNT(*) FROM episode_guests WHERE status = 'pending'").Scan(&stats.PendingEpisodeGuests)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

// GetPopularPodcasts returns podcasts with the most hosts
func (s *HostService) GetPopularPodcasts(limit int) ([]models.PodcastSummary, error) {
	query := `
		SELECT 
			hp.podcast_id,
			p.title,
			COUNT(*) as host_count
		FROM host_podcasts hp
		JOIN podcasts p ON p.id = hp.podcast_id
		WHERE hp.status = 'approved'
		GROUP BY hp.podcast_id, p.title
		ORDER BY host_count DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var podcasts []models.PodcastSummary
	for rows.Next() {
		var podcast models.PodcastSummary
		err := rows.Scan(&podcast.PodcastID, &podcast.Title, &podcast.HostCount)
		podcast.Description = "" // Set empty since we don't have this in the database
		if err != nil {
			return nil, err
		}
		podcasts = append(podcasts, podcast)
	}

	return podcasts, nil
}

// CreateHost creates a new host and returns it
func (s *HostService) CreateHost(name, description, link, img, podcastTitle, role string) (*models.Host, error) {
	host := models.Host{
		Name:        name,
		Description: description,
		Link:        link,
		Img:         img,
	}

	err := host.Create(s.db)
	if err != nil {
		return nil, err
	}

	return &host, nil
}

// ExportPublicDataset exports only approved public data for external use
func (s *HostService) ExportPublicDataset() (*models.PublicDataset, error) {
	dataset := &models.PublicDataset{
		ExportDate: time.Now(),
		Version:    "1.0",
	}

	// Export approved hosts
	hostsQuery := `
		SELECT DISTINCT h.id, h.name, COALESCE(h.description, '') as description, 
		       COALESCE(h.link, '') as link, COALESCE(h.img, '') as img, h.created_at 
		FROM hosts h 
		JOIN host_podcasts hp ON h.id = hp.host_id 
		WHERE hp.status = 'approved'
		ORDER BY h.id
	`
	rows, err := s.db.Query(hostsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var host models.Host
		err := rows.Scan(&host.ID, &host.Name, &host.Description, &host.Link, &host.Img, &host.CreatedAt)
		if err != nil {
			return nil, err
		}
		dataset.Hosts = append(dataset.Hosts, host)
	}

	// Export podcasts that have approved hosts
	podcastsQuery := `
		SELECT DISTINCT p.id, p.title, COALESCE(p.feed_url, '') as feed_url 
		FROM podcasts p 
		JOIN host_podcasts hp ON p.id = hp.podcast_id 
		WHERE hp.status = 'approved'
		ORDER BY p.id
	`
	rows, err = s.db.Query(podcastsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var podcast models.Podcast
		err := rows.Scan(&podcast.ID, &podcast.Title, &podcast.FeedURL)
		if err != nil {
			return nil, err
		}
		dataset.Podcasts = append(dataset.Podcasts, podcast)
	}

	// Export approved host-podcast relationships
	hostPodcastsQuery := `
		SELECT host_id, podcast_id, role, status, created_at 
		FROM host_podcasts 
		WHERE status = 'approved'
		ORDER BY host_id, podcast_id
	`
	rows, err = s.db.Query(hostPodcastsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var hp models.HostPodcast
		err := rows.Scan(&hp.HostID, &hp.PodcastID, &hp.Role, &hp.Status, &hp.CreatedAt)
		if err != nil {
			return nil, err
		}
		dataset.HostPodcasts = append(dataset.HostPodcasts, hp)
	}

	// Export approved episodes
	episodesQuery := `
		SELECT id, podcast_id, title, COALESCE(description, '') as description, audio_url, 
		       pub_date, COALESCE(duration, 0) as duration, season_number, episode_number, 
		       COALESCE(image_url, '') as image_url, COALESCE(link, '') as link, 
		       COALESCE(guid, '') as guid, status, created_at 
		FROM episodes 
		WHERE status = 'approved'
		ORDER BY id
	`
	rows, err = s.db.Query(episodesQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var episode models.Episode
		err := rows.Scan(&episode.ID, &episode.PodcastID, &episode.Title, &episode.Description,
			&episode.AudioURL, &episode.PubDate, &episode.Duration, &episode.SeasonNumber,
			&episode.EpisodeNumber, &episode.ImageURL, &episode.Link, &episode.GUID,
			&episode.Status, &episode.CreatedAt)
		if err != nil {
			return nil, err
		}
		dataset.Episodes = append(dataset.Episodes, episode)
	}

	// Export approved episode guests
	episodeGuestsQuery := `
		SELECT id, episode_id, host_id, role, status, created_at 
		FROM episode_guests 
		WHERE status = 'approved'
		ORDER BY id
	`
	rows, err = s.db.Query(episodeGuestsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var eg models.EpisodeGuest
		err := rows.Scan(&eg.ID, &eg.EpisodeID, &eg.HostID, &eg.Role, &eg.Status, &eg.CreatedAt)
		if err != nil {
			return nil, err
		}
		dataset.EpisodeGuests = append(dataset.EpisodeGuests, eg)
	}

	return dataset, nil
}

// GetChangesSince returns approved records changed since `since`, for incremental (delta) sync.
// Change time is COALESCE(updated_at, created_at) so newly-inserted rows (updated_at NULL) are
// caught by their created_at. Podcasts are reference data resolved on demand, so not included.
func (s *HostService) GetChangesSince(since time.Time) (*models.PublicDataset, error) {
	dataset := &models.PublicDataset{
		ExportDate: time.Now(),
		Version:    "delta-1",
	}

	hostRows, err := s.db.Query(`
		SELECT id, name, COALESCE(description, ''), COALESCE(link, ''), COALESCE(img, ''), created_at
		FROM hosts
		WHERE COALESCE(updated_at, created_at) > ?
		ORDER BY id`, since)
	if err != nil {
		return nil, err
	}
	defer hostRows.Close()
	for hostRows.Next() {
		var h models.Host
		if err := hostRows.Scan(&h.ID, &h.Name, &h.Description, &h.Link, &h.Img, &h.CreatedAt); err != nil {
			return nil, err
		}
		dataset.Hosts = append(dataset.Hosts, h)
	}

	hpRows, err := s.db.Query(`
		SELECT host_id, podcast_id, role, status, created_at
		FROM host_podcasts
		WHERE COALESCE(updated_at, created_at) > ?
		ORDER BY host_id, podcast_id`, since)
	if err != nil {
		return nil, err
	}
	defer hpRows.Close()
	for hpRows.Next() {
		var hp models.HostPodcast
		if err := hpRows.Scan(&hp.HostID, &hp.PodcastID, &hp.Role, &hp.Status, &hp.CreatedAt); err != nil {
			return nil, err
		}
		dataset.HostPodcasts = append(dataset.HostPodcasts, hp)
	}

	epRows, err := s.db.Query(`
		SELECT id, podcast_id, title, COALESCE(description, ''), audio_url, pub_date,
		       COALESCE(duration, 0), season_number, episode_number, COALESCE(image_url, ''),
		       COALESCE(link, ''), COALESCE(guid, ''), status, created_at
		FROM episodes
		WHERE COALESCE(updated_at, created_at) > ?
		ORDER BY id`, since)
	if err != nil {
		return nil, err
	}
	defer epRows.Close()
	for epRows.Next() {
		var e models.Episode
		if err := epRows.Scan(&e.ID, &e.PodcastID, &e.Title, &e.Description, &e.AudioURL, &e.PubDate,
			&e.Duration, &e.SeasonNumber, &e.EpisodeNumber, &e.ImageURL, &e.Link, &e.GUID,
			&e.Status, &e.CreatedAt); err != nil {
			return nil, err
		}
		dataset.Episodes = append(dataset.Episodes, e)
	}

	egRows, err := s.db.Query(`
		SELECT id, episode_id, host_id, role, status, created_at
		FROM episode_guests
		WHERE COALESCE(updated_at, created_at) > ?
		ORDER BY id`, since)
	if err != nil {
		return nil, err
	}
	defer egRows.Close()
	for egRows.Next() {
		var eg models.EpisodeGuest
		if err := egRows.Scan(&eg.ID, &eg.EpisodeID, &eg.HostID, &eg.Role, &eg.Status, &eg.CreatedAt); err != nil {
			return nil, err
		}
		dataset.EpisodeGuests = append(dataset.EpisodeGuests, eg)
	}

	return dataset, nil
}

// GetTopHosts returns hosts ranked by how many approved podcasts they appear in — for the
// discovery/browse grid.
func (s *HostService) GetTopHosts(limit int) ([]models.HostRanked, error) {
	rows, err := s.db.Query(`
		SELECT h.id, h.name, COALESCE(h.img, ''), COUNT(hp.podcast_id) AS podcast_count
		FROM hosts h
		JOIN host_podcasts hp ON h.id = hp.host_id
		WHERE hp.status = 'approved'
		GROUP BY h.id
		ORDER BY podcast_count DESC, h.name
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []models.HostRanked
	for rows.Next() {
		var h models.HostRanked
		if err := rows.Scan(&h.ID, &h.Name, &h.Img, &h.PodcastCount); err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// GetDuplicateHostGroups returns groups of hosts that share a normalized name (dedup candidates
// for the admin merge tool).
func (s *HostService) GetDuplicateHostGroups() ([]models.DuplicateHostGroup, error) {
	rows, err := s.db.Query(`
		SELECT h.id, h.name, COALESCE(h.img, ''), h.name_normalized
		FROM hosts h
		WHERE h.name_normalized IN (
			SELECT name_normalized FROM hosts
			WHERE name_normalized IS NOT NULL AND name_normalized != ''
			GROUP BY name_normalized HAVING COUNT(*) > 1
		)
		ORDER BY h.name_normalized, h.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groupsByKey := make(map[string]*models.DuplicateHostGroup)
	var order []string
	for rows.Next() {
		var id int
		var name, img, norm string
		if err := rows.Scan(&id, &name, &img, &norm); err != nil {
			return nil, err
		}
		g, ok := groupsByKey[norm]
		if !ok {
			g = &models.DuplicateHostGroup{NameNormalized: norm}
			groupsByKey[norm] = g
			order = append(order, norm)
		}
		g.Hosts = append(g.Hosts, models.HostRanked{ID: id, Name: name, Img: img})
	}

	groups := make([]models.DuplicateHostGroup, 0, len(order))
	for _, k := range order {
		groups = append(groups, *groupsByKey[k])
	}
	return groups, nil
}

// MergeHosts folds duplicateID into canonicalID: repoints host_podcasts and episode_guests, then
// deletes the duplicate host. Association rows that would collide with an existing one on the
// canonical host are dropped (the canonical row wins).
func (s *HostService) MergeHosts(canonicalID, duplicateID int) error {
	if canonicalID == duplicateID {
		return fmt.Errorf("canonical and duplicate host IDs must differ")
	}

	return db.Transaction(func(tx *sql.Tx) error {
		// Ensure both hosts exist.
		var canonName string
		if err := tx.QueryRow("SELECT name FROM hosts WHERE id = ?", canonicalID).Scan(&canonName); err != nil {
			return fmt.Errorf("canonical host %d not found: %w", canonicalID, err)
		}
		var dupName string
		if err := tx.QueryRow("SELECT name FROM hosts WHERE id = ?", duplicateID).Scan(&dupName); err != nil {
			return fmt.Errorf("duplicate host %d not found: %w", duplicateID, err)
		}

		// Repoint host_podcasts, skipping pairs the canonical host already has (UNIQUE host_id,podcast_id).
		if _, err := tx.Exec(`
			UPDATE host_podcasts SET host_id = ?
			WHERE host_id = ?
			AND podcast_id NOT IN (SELECT podcast_id FROM host_podcasts WHERE host_id = ?)`,
			canonicalID, duplicateID, canonicalID); err != nil {
			return fmt.Errorf("error repointing host_podcasts: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM host_podcasts WHERE host_id = ?", duplicateID); err != nil {
			return fmt.Errorf("error cleaning up duplicate host_podcasts: %w", err)
		}

		// Repoint episode_guests, skipping episodes the canonical host already guests on
		// (UNIQUE episode_id,host_id).
		if _, err := tx.Exec(`
			UPDATE episode_guests SET host_id = ?
			WHERE host_id = ?
			AND episode_id NOT IN (SELECT episode_id FROM episode_guests WHERE host_id = ?)`,
			canonicalID, duplicateID, canonicalID); err != nil {
			return fmt.Errorf("error repointing episode_guests: %w", err)
		}
		if _, err := tx.Exec("DELETE FROM episode_guests WHERE host_id = ?", duplicateID); err != nil {
			return fmt.Errorf("error cleaning up duplicate episode_guests: %w", err)
		}

		// Touch canonical host so the merge propagates via delta sync.
		if _, err := tx.Exec("UPDATE hosts SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", canonicalID); err != nil {
			return fmt.Errorf("error touching canonical host: %w", err)
		}

		// Remove the now-orphaned duplicate host.
		if _, err := tx.Exec("DELETE FROM hosts WHERE id = ?", duplicateID); err != nil {
			return fmt.Errorf("error deleting duplicate host: %w", err)
		}

		return nil
	})
}
