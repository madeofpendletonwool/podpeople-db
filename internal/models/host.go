package models

import (
	"database/sql"
)

// FindByID finds a host by ID
func (h *Host) FindByID(db *sql.DB, id int) error {
	err := db.QueryRow(`
		SELECT id, name, description, link, img, created_at
		FROM hosts
		WHERE id = ?`,
		id).Scan(&h.ID, &h.Name, &h.Description, &h.Link, &h.Img, &h.CreatedAt)

	if err != nil {
		return err
	}

	// Get podcast associations
	rows, err := db.Query(`
		SELECT hp.podcast_id, p.title, hp.role, hp.status
		FROM host_podcasts hp
		JOIN podcasts p ON p.id = hp.podcast_id
		WHERE hp.host_id = ?`,
		id)

	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var pa PodcastAssociation
		err := rows.Scan(&pa.PodcastID, &pa.Title, &pa.Role, &pa.Status)
		if err != nil {
			return err
		}
		h.Podcasts = append(h.Podcasts, pa)
	}

	return nil
}

// Create creates a new host in the database
func (h *Host) Create(db *sql.DB) error {
	result, err := db.Exec(`
		INSERT INTO hosts (name, description, link, img)
		VALUES (?, ?, ?, ?)`,
		h.Name, h.Description, h.Link, h.Img)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	h.ID = int(id)
	return nil
}

// Update updates a host in the database
func (h *Host) Update(db *sql.DB) error {
	_, err := db.Exec(`
		UPDATE hosts
		SET name = ?, description = ?, link = ?, img = ?
		WHERE id = ?`,
		h.Name, h.Description, h.Link, h.Img, h.ID)

	return err
}

// Delete deletes a host from the database
func (h *Host) Delete(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM hosts WHERE id = ?", h.ID)
	return err
}

// AddPodcastAssociation adds a podcast association to a host
func (h *Host) AddPodcastAssociation(db *sql.DB, podcastID int, title string, role string, status string) error {
	// First, ensure the podcast exists
	_, err := db.Exec(`
		INSERT INTO podcasts (id, title)
		VALUES (?, ?)
		ON CONFLICT (id) DO UPDATE SET
		title = excluded.title`,
		podcastID, title)

	if err != nil {
		return err
	}

	// Then create the association
	_, err = db.Exec(`
		INSERT INTO host_podcasts (host_id, podcast_id, role, status)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (host_id, podcast_id) DO UPDATE SET
		role = excluded.role,
		status = excluded.status`,
		h.ID, podcastID, role, status)

	return err
}

// GetApprovedHostsForPodcast gets all approved hosts for a podcast
func GetApprovedHostsForPodcast(db *sql.DB, podcastID int) ([]Host, error) {
	query := `
		SELECT h.id, h.name, h.description, h.link, h.img, hp.role
		FROM hosts h
		JOIN host_podcasts hp ON h.id = hp.host_id
		WHERE hp.podcast_id = ?
		AND hp.status = 'approved'`

	rows, err := db.Query(query, podcastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var role string
		err := rows.Scan(&h.ID, &h.Name, &h.Description, &h.Link, &h.Img, &role)
		if err != nil {
			return nil, err
		}

		// Create podcast association for this host
		h.Podcasts = []PodcastAssociation{{
			PodcastID: podcastID,
			Role:      role,
			Status:    "approved",
		}}

		hosts = append(hosts, h)
	}

	return hosts, nil
}

// GetRecentApprovedHosts gets recently approved hosts
func GetRecentApprovedHosts(db *sql.DB, limit int) ([]Host, error) {
	query := `
		SELECT DISTINCT h.id, h.name, h.img, h.created_at,
		       hp.role, hp.podcast_id, p.title
		FROM hosts h
		JOIN host_podcasts hp ON h.id = hp.host_id
		JOIN podcasts p ON p.id = hp.podcast_id
		WHERE hp.status = 'approved'
		ORDER BY h.created_at DESC
		LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var role string
		var podcastID int
		var podcastTitle string

		err := rows.Scan(
			&h.ID,
			&h.Name,
			&h.Img,
			&h.CreatedAt,
			&role,
			&podcastID,
			&podcastTitle,
		)
		if err != nil {
			return nil, err
		}

		// Create podcast association
		h.Podcasts = []PodcastAssociation{{
			PodcastID: podcastID,
			Title:     podcastTitle,
			Role:      role,
			Status:    "approved",
		}}

		hosts = append(hosts, h)
	}

	return hosts, nil
}

// SearchHosts searches for hosts by name
func SearchHosts(db *sql.DB, term string, limit int) ([]Host, error) {
	query := `
		SELECT DISTINCT h.id, h.name, hp.role, h.description, h.link, h.img, hp.podcast_id, p.title
		FROM hosts h
		JOIN host_podcasts hp ON h.id = hp.host_id
		JOIN podcasts p ON p.id = hp.podcast_id
		WHERE hp.status = 'approved'
		AND h.name LIKE ?
		ORDER BY h.name
		LIMIT ?`

	searchTerm := "%" + term + "%"
	rows, err := db.Query(query, searchTerm, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	hostMap := make(map[int]*Host) // Use a map to avoid duplicates

	for rows.Next() {
		var h Host
		var role string
		var podcastID int
		var podcastTitle string

		err := rows.Scan(
			&h.ID,
			&h.Name,
			&role,
			&h.Description,
			&h.Link,
			&h.Img,
			&podcastID,
			&podcastTitle,
		)
		if err != nil {
			return nil, err
		}

		// Check if we've already added this host
		if existingHost, ok := hostMap[h.ID]; ok {
			// Add this podcast to the existing host
			existingHost.Podcasts = append(existingHost.Podcasts, PodcastAssociation{
				PodcastID: podcastID,
				Title:     podcastTitle,
				Role:      role,
				Status:    "approved",
			})
		} else {
			// This is a new host
			h.Podcasts = []PodcastAssociation{{
				PodcastID: podcastID,
				Title:     podcastTitle,
				Role:      role,
				Status:    "approved",
			}}
			hostMap[h.ID] = &h
			hosts = append(hosts, h)
		}
	}

	return hosts, nil
}

// GetPendingHosts gets hosts pending approval
func GetPendingHosts(db *sql.DB) ([]Host, error) {
	query := `
		SELECT h.id, h.name, h.description, h.link, h.img,
			   hp.role, hp.podcast_id, p.title
		FROM hosts h
		JOIN host_podcasts hp ON h.id = hp.host_id
		JOIN podcasts p ON p.id = hp.podcast_id
		WHERE hp.status = 'pending'`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pendingHosts []Host
	hostMap := make(map[int]*Host) // Use a map to avoid duplicates

	for rows.Next() {
		var h Host
		var role string
		var podcastID int
		var podcastTitle string

		err := rows.Scan(
			&h.ID,
			&h.Name,
			&h.Description,
			&h.Link,
			&h.Img,
			&role,
			&podcastID,
			&podcastTitle,
		)
		if err != nil {
			return nil, err
		}

		// Check if we've already added this host
		if existingHost, ok := hostMap[h.ID]; ok {
			// Add this podcast to the existing host
			existingHost.Podcasts = append(existingHost.Podcasts, PodcastAssociation{
				PodcastID: podcastID,
				Title:     podcastTitle,
				Role:      role,
				Status:    "pending",
			})
		} else {
			// This is a new host
			h.Podcasts = []PodcastAssociation{{
				PodcastID: podcastID,
				Title:     podcastTitle,
				Role:      role,
				Status:    "pending",
			}}
			hostMap[h.ID] = &h
			pendingHosts = append(pendingHosts, h)
		}
	}

	return pendingHosts, nil
}
