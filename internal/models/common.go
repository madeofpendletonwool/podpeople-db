package models

import (
	"time"
)

// Person represents a person from the podcast:person XML tag
type Person struct {
	Name     string   `json:"name"`
	Role     string   `json:"role,attr"`
	Group    string   `json:"group,attr,omitempty"`
	Img      string   `json:"img,attr,omitempty"`
	Href     string   `json:"href,attr,omitempty"`
	Episodes []string `json:"episodes,omitempty"` // List of episode titles this person is associated with
}

// Podcast represents a podcast from the podcast index
type Podcast struct {
	ID          int      `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
	OwnerName   string   `json:"ownerName"`
	Image       string   `json:"image"`
	Link        string   `json:"link"`
	FeedURL     string   `json:"url"`
	Hosts       []Person `json:"hosts"`
}

// Host represents a podcast host or guest
type Host struct {
	ID          int                  `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Link        string               `json:"link"`
	Img         string               `json:"img"`
	CreatedAt   time.Time            `json:"createdAt"`
	Podcasts    []PodcastAssociation `json:"podcasts,omitempty"`
	Episodes    []string             `json:"episodes,omitempty"` // For Podcast 2.0 person episodes
}

// PodcastAssociation represents a relationship between a host and a podcast
type PodcastAssociation struct {
	PodcastID int    `json:"podcastId"`
	Title     string `json:"podcastTitle"`
	Role      string `json:"role"`
	Status    string `json:"status"`
}

// Admin represents an administrator user
type Admin struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // Password is never included in JSON
	CreatedAt time.Time `json:"createdAt"`
}

// Stats represents database statistics
type Stats struct {
	TotalHosts          int `json:"total_hosts"`
	TotalPodcasts       int `json:"total_podcasts"`
	PendingHosts        int `json:"pending_hosts"`
	ApprovedHosts       int `json:"approved_hosts"`
	EpisodesWithGuests  int `json:"episodes_with_guests"`
	PendingEpisodeGuests int `json:"pending_episode_guests"`
}

// PublicDataset represents the public exportable dataset
type PublicDataset struct {
	ExportDate    time.Time           `json:"export_date"`
	Version       string              `json:"version"`
	Hosts         []Host              `json:"hosts"`
	Podcasts      []Podcast           `json:"podcasts"`
	HostPodcasts  []HostPodcast       `json:"host_podcasts"`
	Episodes      []Episode           `json:"episodes"`
	EpisodeGuests []EpisodeGuest      `json:"episode_guests"`
}

// HostPodcast represents the many-to-many relationship between hosts and podcasts
type HostPodcast struct {
	HostID    int    `json:"host_id"`
	PodcastID int    `json:"podcast_id"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// EpisodeGuest represents a guest appearance on an episode
type EpisodeGuest struct {
	ID                   int       `json:"id"`
	EpisodeID            int       `json:"episode_id"`
	HostID               int       `json:"host_id"`
	Role                 string    `json:"role"`
	Status               string    `json:"status"`
	ApprovalKey          string    `json:"approval_key,omitempty"`
	ApprovalKeyExpiresAt time.Time `json:"approval_key_expires_at,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
}

// PodcastSummary represents a summary of a podcast
type PodcastSummary struct {
	PodcastID   int    `json:"podcast_id"`
	Title       string `json:"title"`
	HostCount   int    `json:"host_count"`
	Description string `json:"description"`
}

// EpisodeSummary represents a summary of an episode for display
type EpisodeSummary struct {
	ID            int       `json:"id"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	AudioURL      string    `json:"audio_url"`
	PubDate       time.Time `json:"pub_date"`
	Duration      int       `json:"duration"`
	SeasonNumber  *int      `json:"season_number,omitempty"`
	EpisodeNumber *int      `json:"episode_number,omitempty"`
	ImageURL      string    `json:"image_url,omitempty"`
	Link          string    `json:"link,omitempty"`
	GuestCount    int       `json:"guest_count"`
	CanAddGuests  bool      `json:"can_add_guests"` // true if this episode allows guest submissions
	Guests        []Host    `json:"guests,omitempty"` // approved guests for this episode
}

// EpisodeGuestWithDetails represents episode guest with full episode and host details
type EpisodeGuestWithDetails struct {
	ID                    int       `json:"id"`
	EpisodeID             int       `json:"episode_id"`
	HostID                int       `json:"host_id"`
	Role                  string    `json:"role"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
	// Episode details
	EpisodeTitle       string    `json:"episode_title"`
	EpisodeDescription string    `json:"episode_description"`
	PodcastID          int       `json:"podcast_id"`
	PodcastTitle       string    `json:"podcast_title"`
	// Host details
	HostName        string `json:"host_name"`
	HostDescription string `json:"host_description"`
	HostLink        string `json:"host_link"`
	HostImg         string `json:"host_img"`
}
