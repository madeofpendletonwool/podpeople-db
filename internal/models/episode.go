package models

import (
	"database/sql"
	"time"
)

// Episode represents a podcast episode
type Episode struct {
	ID            int       `json:"id"`
	PodcastID     int       `json:"podcast_id"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	AudioURL      string    `json:"audio_url"`
	PubDate       time.Time `json:"pub_date"`
	Duration      int       `json:"duration"` // in seconds
	SeasonNumber  *int      `json:"season_number,omitempty"`
	EpisodeNumber *int      `json:"episode_number,omitempty"`
	ImageURL      string    `json:"image_url,omitempty"`
	Link          string    `json:"link,omitempty"`
	GUID          string    `json:"guid,omitempty"`
	Status        string    `json:"status"` // pending, approved, rejected
	CreatedAt     time.Time `json:"created_at"`
	Guests        []Host    `json:"guests,omitempty"`
}

// EpisodeGuest represents the relationship between an episode and a guest
type EpisodeGuest struct {
	ID                    int       `json:"id"`
	EpisodeID             int       `json:"episode_id"`
	HostID                int       `json:"host_id"`
	Role                  string    `json:"role"` // guest, host, co-host
	Status                string    `json:"status"`
	ApprovalKey           string    `json:"approval_key,omitempty"`
	ApprovalKeyExpiresAt  time.Time `json:"approval_key_expires_at,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

// FindByID finds an episode by its ID
func (e *Episode) FindByID(db *sql.DB, id int) error {
	return db.QueryRow(`
		SELECT id, podcast_id, title, description, audio_url, pub_date, 
		       duration, season_number, episode_number, image_url, link, 
		       guid, status, created_at
		FROM episodes
		WHERE id = ?`, id).Scan(
		&e.ID, &e.PodcastID, &e.Title, &e.Description, &e.AudioURL,
		&e.PubDate, &e.Duration, &e.SeasonNumber, &e.EpisodeNumber,
		&e.ImageURL, &e.Link, &e.GUID, &e.Status, &e.CreatedAt)
}

// FindByAudioURL finds an episode by its audio URL
func (e *Episode) FindByAudioURL(db *sql.DB, audioURL string) error {
	return db.QueryRow(`
		SELECT id, podcast_id, title, description, audio_url, pub_date, 
		       duration, season_number, episode_number, image_url, link, 
		       guid, status, created_at
		FROM episodes
		WHERE audio_url = ?`, audioURL).Scan(
		&e.ID, &e.PodcastID, &e.Title, &e.Description, &e.AudioURL,
		&e.PubDate, &e.Duration, &e.SeasonNumber, &e.EpisodeNumber,
		&e.ImageURL, &e.Link, &e.GUID, &e.Status, &e.CreatedAt)
}

// Create creates a new episode in the database
func (e *Episode) Create(db *sql.DB) error {
	result, err := db.Exec(`
		INSERT INTO episodes (podcast_id, title, description, audio_url, pub_date, 
		                     duration, season_number, episode_number, image_url, 
		                     link, guid, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.PodcastID, e.Title, e.Description, e.AudioURL, e.PubDate,
		e.Duration, e.SeasonNumber, e.EpisodeNumber, e.ImageURL,
		e.Link, e.GUID, e.Status)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	e.ID = int(id)
	return nil
}

// Update updates an episode in the database
func (e *Episode) Update(db *sql.DB) error {
	_, err := db.Exec(`
		UPDATE episodes
		SET title = ?, description = ?, audio_url = ?, pub_date = ?, 
		    duration = ?, season_number = ?, episode_number = ?, 
		    image_url = ?, link = ?, guid = ?, status = ?
		WHERE id = ?`,
		e.Title, e.Description, e.AudioURL, e.PubDate, e.Duration,
		e.SeasonNumber, e.EpisodeNumber, e.ImageURL, e.Link,
		e.GUID, e.Status, e.ID)

	return err
}

// Delete deletes an episode from the database
func (e *Episode) Delete(db *sql.DB) error {
	// First delete episode guests
	_, err := db.Exec("DELETE FROM episode_guests WHERE episode_id = ?", e.ID)
	if err != nil {
		return err
	}

	// Then delete the episode
	_, err = db.Exec("DELETE FROM episodes WHERE id = ?", e.ID)
	return err
}

// GetEpisodesByPodcastID gets all episodes for a podcast
func GetEpisodesByPodcastID(db *sql.DB, podcastID int, limit int) ([]Episode, error) {
	query := `
		SELECT id, podcast_id, title, description, audio_url, pub_date, 
		       duration, season_number, episode_number, image_url, link, 
		       guid, status, created_at
		FROM episodes
		WHERE podcast_id = ? AND status = 'approved'
		ORDER BY pub_date DESC`
	
	if limit > 0 {
		query += " LIMIT ?"
	}

	var rows *sql.Rows
	var err error
	
	if limit > 0 {
		rows, err = db.Query(query, podcastID, limit)
	} else {
		rows, err = db.Query(query, podcastID)
	}
	
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var episodes []Episode
	for rows.Next() {
		var e Episode
		err := rows.Scan(&e.ID, &e.PodcastID, &e.Title, &e.Description,
			&e.AudioURL, &e.PubDate, &e.Duration, &e.SeasonNumber,
			&e.EpisodeNumber, &e.ImageURL, &e.Link, &e.GUID,
			&e.Status, &e.CreatedAt)
		if err != nil {
			return nil, err
		}
		episodes = append(episodes, e)
	}

	return episodes, nil
}

// GetPendingEpisodes gets all pending episodes
func GetPendingEpisodes(db *sql.DB) ([]Episode, error) {
	rows, err := db.Query(`
		SELECT id, podcast_id, title, description, audio_url, pub_date, 
		       duration, season_number, episode_number, image_url, link, 
		       guid, status, created_at
		FROM episodes
		WHERE status = 'pending'
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var episodes []Episode
	for rows.Next() {
		var e Episode
		err := rows.Scan(&e.ID, &e.PodcastID, &e.Title, &e.Description,
			&e.AudioURL, &e.PubDate, &e.Duration, &e.SeasonNumber,
			&e.EpisodeNumber, &e.ImageURL, &e.Link, &e.GUID,
			&e.Status, &e.CreatedAt)
		if err != nil {
			return nil, err
		}
		episodes = append(episodes, e)
	}

	return episodes, nil
}

// ApproveEpisode approves a pending episode
func ApproveEpisode(db *sql.DB, episodeID int) error {
	_, err := db.Exec("UPDATE episodes SET status = 'approved' WHERE id = ?", episodeID)
	return err
}

// RejectEpisode rejects a pending episode
func RejectEpisode(db *sql.DB, episodeID int) error {
	_, err := db.Exec("UPDATE episodes SET status = 'rejected' WHERE id = ?", episodeID)
	return err
}

// EpisodeGuest methods

// FindEpisodeGuestByID finds an episode guest by its ID
func (eg *EpisodeGuest) FindByID(db *sql.DB, id int) error {
	return db.QueryRow(`
		SELECT id, episode_id, host_id, role, status, approval_key, 
		       approval_key_expires_at, created_at
		FROM episode_guests
		WHERE id = ?`, id).Scan(
		&eg.ID, &eg.EpisodeID, &eg.HostID, &eg.Role, &eg.Status,
		&eg.ApprovalKey, &eg.ApprovalKeyExpiresAt, &eg.CreatedAt)
}

// Create creates a new episode guest relationship
func (eg *EpisodeGuest) Create(db *sql.DB) error {
	result, err := db.Exec(`
		INSERT INTO episode_guests (episode_id, host_id, role, status, 
		                           approval_key, approval_key_expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		eg.EpisodeID, eg.HostID, eg.Role, eg.Status,
		eg.ApprovalKey, eg.ApprovalKeyExpiresAt)

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	eg.ID = int(id)
	return nil
}

// Update updates an episode guest relationship
func (eg *EpisodeGuest) Update(db *sql.DB) error {
	_, err := db.Exec(`
		UPDATE episode_guests
		SET role = ?, status = ?
		WHERE id = ?`,
		eg.Role, eg.Status, eg.ID)

	return err
}

// Delete deletes an episode guest relationship
func (eg *EpisodeGuest) Delete(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM episode_guests WHERE id = ?", eg.ID)
	return err
}

// GetGuestsByEpisodeID gets all guests for an episode
func GetGuestsByEpisodeID(db *sql.DB, episodeID int) ([]Host, error) {
	rows, err := db.Query(`
		SELECT h.id, h.name, h.description, h.link, h.img, h.created_at,
		       eg.role, eg.status
		FROM hosts h
		JOIN episode_guests eg ON h.id = eg.host_id
		WHERE eg.episode_id = ? AND eg.status = 'approved'
		ORDER BY h.name`, episodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var role, status string
		err := rows.Scan(&h.ID, &h.Name, &h.Description, &h.Link,
			&h.Img, &h.CreatedAt, &role, &status)
		if err != nil {
			return nil, err
		}
		
		// Add podcast association info
		h.Podcasts = []PodcastAssociation{{
			Role:   role,
			Status: status,
		}}
		
		hosts = append(hosts, h)
	}

	return hosts, nil
}

// GetPendingEpisodeGuests gets all pending episode guest relationships
func GetPendingEpisodeGuests(db *sql.DB) ([]EpisodeGuest, error) {
	rows, err := db.Query(`
		SELECT id, episode_id, host_id, role, status, approval_key, 
		       approval_key_expires_at, created_at
		FROM episode_guests
		WHERE status = 'pending'
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var guests []EpisodeGuest
	for rows.Next() {
		var eg EpisodeGuest
		err := rows.Scan(&eg.ID, &eg.EpisodeID, &eg.HostID, &eg.Role,
			&eg.Status, &eg.ApprovalKey, &eg.ApprovalKeyExpiresAt, &eg.CreatedAt)
		if err != nil {
			return nil, err
		}
		guests = append(guests, eg)
	}

	return guests, nil
}

// ApproveEpisodeGuest approves a pending episode guest
func ApproveEpisodeGuest(db *sql.DB, id int) error {
	_, err := db.Exec("UPDATE episode_guests SET status = 'approved' WHERE id = ?", id)
	return err
}

// RejectEpisodeGuest rejects a pending episode guest
func RejectEpisodeGuest(db *sql.DB, id int) error {
	_, err := db.Exec("UPDATE episode_guests SET status = 'rejected' WHERE id = ?", id)
	return err
}

// GetPendingEpisodeGuestsWithDetails gets all pending episode guests with full episode and host details
func GetPendingEpisodeGuestsWithDetails(db *sql.DB) ([]EpisodeGuestWithDetails, error) {
	query := `
		SELECT 
			eg.id, eg.episode_id, eg.host_id, eg.role, eg.status, eg.created_at,
			e.title as episode_title, e.description as episode_description,
			e.podcast_id, p.title as podcast_title,
			h.name as host_name, h.description as host_description, 
			h.link as host_link, h.img as host_img
		FROM episode_guests eg
		JOIN episodes e ON eg.episode_id = e.id
		JOIN podcasts p ON e.podcast_id = p.id
		JOIN hosts h ON eg.host_id = h.id
		WHERE eg.status = 'pending'
		ORDER BY eg.created_at DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var guests []EpisodeGuestWithDetails
	for rows.Next() {
		var guest EpisodeGuestWithDetails
		err := rows.Scan(
			&guest.ID, &guest.EpisodeID, &guest.HostID, &guest.Role, &guest.Status, &guest.CreatedAt,
			&guest.EpisodeTitle, &guest.EpisodeDescription,
			&guest.PodcastID, &guest.PodcastTitle,
			&guest.HostName, &guest.HostDescription, &guest.HostLink, &guest.HostImg,
		)
		if err != nil {
			return nil, err
		}
		guests = append(guests, guest)
	}

	return guests, nil
}