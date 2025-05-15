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
