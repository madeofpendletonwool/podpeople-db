package models

import (
	"database/sql"
)

// FindByID finds a podcast by its ID
func (p *Podcast) FindByID(db *sql.DB, id int) error {
	return db.QueryRow(`
		SELECT id, title, feed_url
		FROM podcasts
		WHERE id = ?`, id).Scan(&p.ID, &p.Title, &p.FeedURL)
}

// Create creates a new podcast in the database
func (p *Podcast) Create(db *sql.DB) error {
	_, err := db.Exec(`
		INSERT INTO podcasts (id, title, feed_url)
		VALUES (?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
		title = excluded.title,
		feed_url = excluded.feed_url`,
		p.ID, p.Title, p.FeedURL)

	return err
}

// Update updates a podcast in the database
func (p *Podcast) Update(db *sql.DB) error {
	_, err := db.Exec(`
		UPDATE podcasts
		SET title = ?, feed_url = ?
		WHERE id = ?`,
		p.Title, p.FeedURL, p.ID)

	return err
}

// Delete deletes a podcast from the database
func (p *Podcast) Delete(db *sql.DB) error {
	// First delete host associations
	_, err := db.Exec("DELETE FROM host_podcasts WHERE podcast_id = ?", p.ID)
	if err != nil {
		return err
	}

	// Then delete the podcast
	_, err = db.Exec("DELETE FROM podcasts WHERE id = ?", p.ID)
	return err
}

// GetAllPodcasts gets all podcasts from the database
func GetAllPodcasts(db *sql.DB) ([]Podcast, error) {
	rows, err := db.Query(`
		SELECT id, title, feed_url
		FROM podcasts
		ORDER BY title`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var podcasts []Podcast
	for rows.Next() {
		var p Podcast
		if err := rows.Scan(&p.ID, &p.Title, &p.FeedURL); err != nil {
			return nil, err
		}
		podcasts = append(podcasts, p)
	}

	return podcasts, nil
}

// GetPodcastsWithHosts gets podcasts that have approved hosts
func GetPodcastsWithHosts(db *sql.DB) ([]Podcast, error) {
	rows, err := db.Query(`
		SELECT DISTINCT p.id, p.title, p.feed_url
		FROM podcasts p
		JOIN host_podcasts hp ON p.id = hp.podcast_id
		WHERE hp.status = 'approved'
		ORDER BY p.title`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var podcasts []Podcast
	for rows.Next() {
		var p Podcast
		if err := rows.Scan(&p.ID, &p.Title, &p.FeedURL); err != nil {
			return nil, err
		}
		podcasts = append(podcasts, p)
	}

	return podcasts, nil
}
