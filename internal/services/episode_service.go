package services

import (
	"database/sql"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/madeofpendletonwool/podpeople-db/internal/config"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
	"github.com/madeofpendletonwool/podpeople-db/internal/utils"
)

// EpisodeService handles episode-related operations
type EpisodeService struct {
	Config *config.Config
	DB     *sql.DB
}

// NewEpisodeService creates a new episode service
func NewEpisodeService(cfg *config.Config, db *sql.DB) *EpisodeService {
	return &EpisodeService{
		Config: cfg,
		DB:     db,
	}
}

// RSS feed structures for parsing
type RSS struct {
	XMLName xml.Name `xml:"rss"`
	Channel Channel  `xml:"channel"`
}

type Channel struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
	Image       Image  `xml:"image"`
	Items       []Item `xml:"item"`
}

type Image struct {
	URL string `xml:"url"`
}

type Item struct {
	Title         string    `xml:"title"`
	Description   string    `xml:"description"`
	PubDate       string    `xml:"pubDate"`
	GUID          string    `xml:"guid"`
	Link          string    `xml:"link"`
	Enclosure     Enclosure `xml:"enclosure"`
	ItunesImage   string    `xml:"image href,attr"`
	Season        string    `xml:"season"`
	Episode       string    `xml:"episode"`
	ItunesDuration string   `xml:"duration"`
	Persons       []Person  `xml:"person"`
}

type Person struct {
	Name  string `xml:",chardata"`
	Role  string `xml:"role,attr"`
	Group string `xml:"group,attr"`
	Img   string `xml:"img,attr"`
	Href  string `xml:"href,attr"`
}

type Enclosure struct {
	URL  string `xml:"url,attr"`
	Type string `xml:"type,attr"`
}

// GetEpisodesByPodcastID fetches episodes for a podcast from its RSS feed
func (s *EpisodeService) GetEpisodesByPodcastID(podcastID int, limit int) ([]models.EpisodeSummary, error) {
	// Get the podcast from Podcast Index API to access its feed URL
	podcast, err := s.getPodcastFromAPI(podcastID)
	if err != nil {
		return nil, fmt.Errorf("failed to get podcast: %w", err)
	}

	if podcast.FeedURL == "" {
		return nil, fmt.Errorf("no feed URL available for podcast")
	}

	// Fetch and parse the RSS feed, also getting episode-level person data
	episodes, episodePersons, err := s.parseRSSFeedWithPersons(podcast.FeedURL, podcastID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSS feed: %w", err)
	}

	// Check if the podcast already has person tags (if so, don't allow guest additions)
	canAddGuests := !s.podcastHasPersonTags(podcast)

	// Convert to EpisodeSummary and set CanAddGuests flag
	var episodeSummaries []models.EpisodeSummary
	for _, episode := range episodes {
		// Get approved guests for this episode from database
		dbGuests, _ := models.GetGuestsByEpisodeID(s.DB, episode.ID)
		
		// Get Podcast 2.0 guests for this episode from RSS feed
		var allGuests []models.Host
		allGuests = append(allGuests, dbGuests...)
		
		// Add Podcast 2.0 guests if available
		if rssGuests, exists := episodePersons[episode.AudioURL]; exists {
			for _, person := range rssGuests {
				rssGuest := models.Host{
					Name: person.Name,
					Img:  person.Img,
					Link: person.Href,
					Podcasts: []models.PodcastAssociation{{
						PodcastID: podcastID,
						Title:     podcast.Title,
						Role:      person.Role,
						Status:    "approved", // RSS feed data is considered approved
					}},
				}
				allGuests = append(allGuests, rssGuest)
			}
		}
		
		episodeSummaries = append(episodeSummaries, models.EpisodeSummary{
			ID:            episode.ID,
			Title:         episode.Title,
			Description:   episode.Description,
			AudioURL:      episode.AudioURL,
			PubDate:       episode.PubDate,
			Duration:      episode.Duration,
			SeasonNumber:  episode.SeasonNumber,
			EpisodeNumber: episode.EpisodeNumber,
			ImageURL:      episode.ImageURL,
			Link:          episode.Link,
			GuestCount:    len(allGuests),
			CanAddGuests:  canAddGuests,
			Guests:        allGuests,
		})
	}

	return episodeSummaries, nil
}

// parseRSSFeedWithPersons parses an RSS feed and returns episodes along with episode-level person data
func (s *EpisodeService) parseRSSFeedWithPersons(feedURL string, podcastID int, limit int) ([]models.Episode, map[string][]Person, error) {
	// Fetch RSS feed
	resp, err := http.Get(feedURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch RSS feed: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read RSS feed: %w", err)
	}

	// Parse RSS
	var rss RSS
	err = xml.Unmarshal(body, &rss)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse RSS XML: %w", err)
	}

	var episodes []models.Episode
	episodePersons := make(map[string][]Person) // Map audio URL to persons
	itemCount := 0
	
	for _, item := range rss.Channel.Items {
		if limit > 0 && itemCount >= limit {
			break
		}

		// Skip items without audio enclosures
		if item.Enclosure.URL == "" {
			continue
		}

		// Store episode person data
		if len(item.Persons) > 0 {
			episodePersons[item.Enclosure.URL] = item.Persons
		}

		// Check if this episode already exists in database by audio URL
		var existingEpisode models.Episode
		err := existingEpisode.FindByAudioURL(s.DB, item.Enclosure.URL)
		if err == nil {
			// Episode exists, add it to our list
			episodes = append(episodes, existingEpisode)
			itemCount++
			continue
		} else if err != sql.ErrNoRows {
			// Some other error occurred
			return nil, nil, fmt.Errorf("failed to check existing episode: %w", err)
		}

		// Parse pub date
		pubDate, err := s.parsePubDate(item.PubDate)
		if err != nil {
			pubDate = time.Now() // Use current time as fallback
		}

		// Parse duration
		duration := s.parseDuration(item.ItunesDuration)

		// Parse season and episode numbers
		var seasonNumber, episodeNumber *int
		if item.Season != "" {
			if s, err := strconv.Atoi(item.Season); err == nil {
				seasonNumber = &s
			}
		}
		if item.Episode != "" {
			if e, err := strconv.Atoi(item.Episode); err == nil {
				episodeNumber = &e
			}
		}

		// Determine image URL
		imageURL := item.ItunesImage
		if imageURL == "" && rss.Channel.Image.URL != "" {
			imageURL = rss.Channel.Image.URL
		}

		// Create episode model
		episode := models.Episode{
			PodcastID:     podcastID,
			Title:         item.Title,
			Description:   s.cleanDescription(item.Description),
			AudioURL:      item.Enclosure.URL,
			PubDate:       pubDate,
			Duration:      duration,
			SeasonNumber:  seasonNumber,
			EpisodeNumber: episodeNumber,
			ImageURL:      imageURL,
			Link:          item.Link,
			GUID:          item.GUID,
			Status:        "approved", // Episodes from feeds are auto-approved
		}

		// Save to database
		if err := episode.Create(s.DB); err != nil {
			// If creation fails due to duplicate audio URL, try to fetch existing
			var existingEpisode models.Episode
			if err2 := existingEpisode.FindByAudioURL(s.DB, item.Enclosure.URL); err2 == nil {
				episodes = append(episodes, existingEpisode)
			} else {
				log.Printf("Failed to create episode '%s' and failed to find existing: create_err=%v, find_err=%v", item.Title, err, err2)
			}
			// Continue with next episode even if this one failed
			continue
		}

		episodes = append(episodes, episode)
		itemCount++
	}

	return episodes, episodePersons, nil
}

// Helper functions

func (s *EpisodeService) getPodcastByID(podcastID int) (models.Podcast, error) {
	var podcast models.Podcast
	err := podcast.FindByID(s.DB, podcastID)
	return podcast, err
}

func (s *EpisodeService) getPodcastFromAPI(podcastID int) (models.Podcast, error) {
	podcastService := NewPodcastService(s.Config)
	return podcastService.GetPodcastDetails(strconv.Itoa(podcastID))
}

func (s *EpisodeService) podcastHasPersonTags(podcast models.Podcast) bool {
	return len(podcast.Hosts) > 0
}

func (s *EpisodeService) getEpisodeGuestCount(episodeID int) (int, error) {
	var count int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM episode_guests WHERE episode_id = ? AND status = 'approved'", episodeID).Scan(&count)
	return count, err
}

func (s *EpisodeService) parsePubDate(pubDateStr string) (time.Time, error) {
	// Common RSS date formats
	formats := []string{
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, pubDateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", pubDateStr)
}

func (s *EpisodeService) parseDuration(durationStr string) int {
	if durationStr == "" {
		return 0
	}

	// Handle different duration formats
	parts := strings.Split(durationStr, ":")
	var totalSeconds int

	switch len(parts) {
	case 1:
		// Just seconds
		if seconds, err := strconv.Atoi(parts[0]); err == nil {
			totalSeconds = seconds
		}
	case 2:
		// MM:SS
		if minutes, err := strconv.Atoi(parts[0]); err == nil {
			if seconds, err := strconv.Atoi(parts[1]); err == nil {
				totalSeconds = minutes*60 + seconds
			}
		}
	case 3:
		// HH:MM:SS
		if hours, err := strconv.Atoi(parts[0]); err == nil {
			if minutes, err := strconv.Atoi(parts[1]); err == nil {
				if seconds, err := strconv.Atoi(parts[2]); err == nil {
					totalSeconds = hours*3600 + minutes*60 + seconds
				}
			}
		}
	}

	return totalSeconds
}

func (s *EpisodeService) cleanDescription(description string) string {
	// Remove HTML tags and clean up description
	cleaned := strings.ReplaceAll(description, "<br>", "\n")
	cleaned = strings.ReplaceAll(cleaned, "<br/>", "\n")
	cleaned = strings.ReplaceAll(cleaned, "<p>", "")
	cleaned = strings.ReplaceAll(cleaned, "</p>", "\n")
	
	// Basic HTML tag removal (very simple)
	for strings.Contains(cleaned, "<") && strings.Contains(cleaned, ">") {
		start := strings.Index(cleaned, "<")
		end := strings.Index(cleaned[start:], ">")
		if end == -1 {
			break
		}
		cleaned = cleaned[:start] + cleaned[start+end+1:]
	}
	
	// Clean up multiple newlines
	for strings.Contains(cleaned, "\n\n\n") {
		cleaned = strings.ReplaceAll(cleaned, "\n\n\n", "\n\n")
	}
	
	return strings.TrimSpace(cleaned)
}

// AddEpisodeGuest adds a guest to an episode
func (s *EpisodeService) AddEpisodeGuest(episodeID, hostID int, role string) error {
	// Generate a unique approval key
	approvalKey, err := utils.GenerateApprovalKey()
	if err != nil {
		return fmt.Errorf("failed to generate approval key: %w", err)
	}

	episodeGuest := models.EpisodeGuest{
		EpisodeID:            episodeID,
		HostID:               hostID,
		Role:                 role,
		Status:               "pending", // All guest submissions start as pending
		ApprovalKey:          approvalKey,
		ApprovalKeyExpiresAt: time.Now().Add(7 * 24 * time.Hour), // Expires in 7 days
	}

	return episodeGuest.Create(s.DB)
}

// GetEpisodeByID gets a single episode by ID
func (s *EpisodeService) GetEpisodeByID(episodeID int) (models.Episode, error) {
	var episode models.Episode
	err := episode.FindByID(s.DB, episodeID)
	if err != nil {
		return episode, err
	}

	// Load guests for this episode
	guests, err := models.GetGuestsByEpisodeID(s.DB, episodeID)
	if err != nil {
		return episode, err
	}

	episode.Guests = guests
	return episode, nil
}

func (s *EpisodeService) GetEpisodeByAudioURL(audioURL string) (models.Episode, error) {
	var episode models.Episode
	err := episode.FindByAudioURL(s.DB, audioURL)
	if err != nil {
		return episode, err
	}
	return episode, nil
}

// ApproveEpisodeGuest approves a pending episode guest
func (s *EpisodeService) ApproveEpisodeGuest(guestID int) error {
	return models.ApproveEpisodeGuest(s.DB, guestID)
}

// RejectEpisodeGuest rejects a pending episode guest
func (s *EpisodeService) RejectEpisodeGuest(guestID int) error {
	return models.RejectEpisodeGuest(s.DB, guestID)
}