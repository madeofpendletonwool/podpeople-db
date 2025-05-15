package services

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/madeofpendletonwool/podpeople-db/internal/config"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
)

// PodcastService handles podcast-related operations
type PodcastService struct {
	Config *config.Config
}

// NewPodcastService creates a new podcast service
func NewPodcastService(cfg *config.Config) *PodcastService {
	return &PodcastService{
		Config: cfg,
	}
}

// GetPodcastDetails fetches podcast details from the podcast index
func (s *PodcastService) GetPodcastDetails(id string) (models.Podcast, error) {
	if s.Config.PodcastAPI.SearchAPIURL == "" {
		return models.Podcast{}, fmt.Errorf("SEARCH_API_URL is not configured")
	}

	url := fmt.Sprintf("%s/api/podcast?id=%s", s.Config.PodcastAPI.SearchAPIURL, id)
	resp, err := http.Get(url)
	if err != nil {
		return models.Podcast{}, fmt.Errorf("error making request to API: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return models.Podcast{}, fmt.Errorf("error reading response body: %w", err)
	}

	var result struct {
		Feed models.Podcast `json:"feed"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return models.Podcast{}, fmt.Errorf("error unmarshalling JSON: %w", err)
	}

	log.Printf("Fetching podcast feed from URL: %s", result.Feed.FeedURL)
	feedResp, err := http.Get(result.Feed.FeedURL)
	if err != nil {
		return models.Podcast{}, fmt.Errorf("error fetching podcast feed: %w", err)
	}
	defer feedResp.Body.Close()

	// Read the feed content
	feedContent, err := ioutil.ReadAll(feedResp.Body)
	if err != nil {
		return models.Podcast{}, fmt.Errorf("error reading feed content: %w", err)
	}

	// Log a sample of the feed content
	if len(feedContent) > 1000 {
		log.Printf("First 1000 characters of feed content: %s", string(feedContent[:1000]))
	} else {
		log.Printf("Feed content (%d characters): %s", len(feedContent), string(feedContent))
	}

	// Parse the XML for podcast:person tags
	persons, err := s.extractPersonTags(feedContent)
	if err != nil {
		log.Printf("Warning: Failed to parse podcast:person tags: %v", err)
		// Continue without person tags
	}

	// Deduplicate hosts
	result.Feed.Hosts = s.deduplicateHosts(persons)

	return result.Feed, nil
}

// extractPersonTags extracts person tags from podcast XML
func (s *PodcastService) extractPersonTags(feedContent []byte) ([]models.Person, error) {
	feedReader := bytes.NewReader(feedContent)
	decoder := xml.NewDecoder(feedReader)
	var persons []models.Person
	var currentEpisodeTitle string

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing feed XML: %w", err)
		}

		switch se := token.(type) {
		case xml.StartElement:
			if se.Name.Local == "item" {
				// We've entered a new item/episode
				currentEpisodeTitle = ""
			} else if se.Name.Local == "title" && currentEpisodeTitle == "" {
				// This is the episode title
				var title string
				decoder.DecodeElement(&title, &se)
				currentEpisodeTitle = title
			} else if se.Name.Space == "https://podcastindex.org/namespace/1.0" && se.Name.Local == "person" {
				var person models.Person
				// Extract attributes
				for _, attr := range se.Attr {
					switch attr.Name.Local {
					case "role":
						person.Role = attr.Value
					case "group":
						person.Group = attr.Value
					case "img":
						person.Img = attr.Value
					case "href":
						person.Href = attr.Value
					}
				}

				// Get the name from the content
				var name string
				decoder.DecodeElement(&name, &se)
				person.Name = name

				if currentEpisodeTitle != "" {
					person.Episodes = []string{currentEpisodeTitle}
				}

				log.Printf("Decoded person: %+v", person)
				persons = append(persons, person)
			}
		}
	}

	log.Printf("Found %d persons in the podcast feed", len(persons))
	return persons, nil
}

// deduplicateHosts removes duplicate hosts and prioritizes roles
func (s *PodcastService) deduplicateHosts(persons []models.Person) []models.Person {
	uniqueHosts := make(map[string]*models.Person)
	for _, person := range persons {
		if existingPerson, found := uniqueHosts[person.Name]; found {
			// Prioritize "host" role
			if strings.Contains(strings.ToLower(person.Role), "host") {
				existingPerson.Role = "Host"
			} else if existingPerson.Role != "Host" {
				existingPerson.Role = "Guest"
			}
			// Append episode if it's not already in the list
			if len(person.Episodes) > 0 && !s.contains(existingPerson.Episodes, person.Episodes[0]) {
				existingPerson.Episodes = append(existingPerson.Episodes, person.Episodes...)
			}
		} else {
			personCopy := person
			if strings.Contains(strings.ToLower(personCopy.Role), "host") {
				personCopy.Role = "Host"
			} else {
				personCopy.Role = "Guest"
			}
			uniqueHosts[person.Name] = &personCopy
		}
	}

	result := make([]models.Person, 0, len(uniqueHosts))
	for _, person := range uniqueHosts {
		result = append(result, *person)
	}

	// Sort the result slice by episode count (most episodes first)
	sort.Slice(result, func(i, j int) bool {
		return len(result[i].Episodes) > len(result[j].Episodes)
	})

	return result
}

// contains checks if a slice contains a string
func (s *PodcastService) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
