package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/madeofpendletonwool/podpeople-db/internal/db"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
)

// HomeHandler handles the home page
func (s *Server) HomeHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.TemplateManager.Render(w, "home.html", nil); err != nil {
		log.Printf("Error rendering home template: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

// Modified PodcastHandler function for public.go
func (s *Server) PodcastHandler(w http.ResponseWriter, r *http.Request) {
	var podcastID string
	// Check if ID is in URL path
	if id := chi.URLParam(r, "id"); id != "" {
		podcastID = id
	} else {
		// Check if ID is in query parameters
		podcastID = r.URL.Query().Get("id")
	}

	if podcastID == "" {
		// Handle missing podcast ID
		data := struct {
			Title   string
			Message string
		}{
			Title:   "Missing Podcast ID",
			Message: "Please provide a valid Podcast Index ID to continue.",
		}

		if err := s.TemplateManager.Render(w, "error.html", data); err != nil {
			http.Error(w, "Error rendering error page", http.StatusInternalServerError)
		}
		return
	}

	// Check for invalid podcast IDs specifically for "0"
	if podcastID == "0" {
		data := struct {
			Title   string
			Message string
		}{
			Title:   "Invalid Podcast ID",
			Message: "The podcast ID '0' is not valid. Please provide a correct Podcast Index ID.",
		}

		if err := s.TemplateManager.Render(w, "error.html", data); err != nil {
			http.Error(w, "Error rendering error page", http.StatusInternalServerError)
		}
		return
	}

	// Get podcast details
	podcast, err := s.PodcastService.GetPodcastDetails(podcastID)
	if err != nil {
		log.Printf("Error getting podcast details: %v", err)

		data := struct {
			Title   string
			Message string
		}{
			Title:   "Podcast Not Found",
			Message: fmt.Sprintf("Error getting podcast details: %v", err),
		}

		if err := s.TemplateManager.Render(w, "error.html", data); err != nil {
			http.Error(w, "Error rendering error page", http.StatusInternalServerError)
		}
		return
	}

	var hosts []models.Host
	var originalHosts []models.Person // Keep track of original Person data for sorting
	
	if len(podcast.Hosts) == 0 {
		// If no <podcast:person> tags were found, fetch approved hosts from the database
		idInt, _ := strconv.Atoi(podcastID)
		hosts, err = models.GetApprovedHostsForPodcast(db.DB, idInt)
		if err != nil {
			log.Printf("Error getting hosts: %v", err)
			http.Error(w, fmt.Sprintf("Error getting hosts: %v", err), http.StatusInternalServerError)
			return
		}
		// For database hosts, sort by name since we don't have episode counts easily accessible
		sort.Slice(hosts, func(i, j int) bool {
			return hosts[i].Name < hosts[j].Name
		})
	} else {
		// Keep original hosts for sorting by episode count
		originalHosts = make([]models.Person, len(podcast.Hosts))
		copy(originalHosts, podcast.Hosts)
		
		// Sort original hosts by episode count (descending)
		sort.Slice(originalHosts, func(i, j int) bool {
			return len(originalHosts[i].Episodes) > len(originalHosts[j].Episodes)
		})
		
		// Convert Person structs to Host structs (up to 6)
		maxHosts := len(originalHosts)
		if maxHosts > 6 {
			maxHosts = 6
		}
		
		for i := 0; i < maxHosts; i++ {
			person := originalHosts[i]
			host := models.Host{
				Name:     person.Name,
				Img:      person.Img,
				Link:     person.Href,
				Episodes: person.Episodes, // Include episodes from Podcast 2.0 data
				Podcasts: []models.PodcastAssociation{{
					PodcastID: podcast.ID,
					Title:     podcast.Title,
					Role:      person.Role,
					Status:    "approved",
				}},
			}
			hosts = append(hosts, host)
		}
	}
	
	// Limit database hosts to 6 as well
	if len(podcast.Hosts) == 0 && len(hosts) > 6 {
		hosts = hosts[:6]
	}

	// Check if the user is an admin
	isAdmin := s.SessionManager.GetBool(r.Context(), "authenticated")

	// Check if there are more hosts available
	var hasMoreHosts bool
	var totalHostCount int
	
	if len(podcast.Hosts) > 0 {
		totalHostCount = len(podcast.Hosts)
		hasMoreHosts = totalHostCount > 6
	} else {
		// For database hosts, we already limited to 6, so we need to check the original count
		idInt, _ := strconv.Atoi(podcastID)
		allHosts, err := models.GetApprovedHostsForPodcast(db.DB, idInt)
		if err == nil {
			totalHostCount = len(allHosts)
			hasMoreHosts = totalHostCount > 6
		}
	}

	// JSON encode the original hosts for JavaScript
	originalHostsJSON, _ := json.Marshal(podcast.Hosts)
	originalHostsJSONEncoded := url.QueryEscape(string(originalHostsJSON))

	data := struct {
		Podcast           models.Podcast
		Hosts             []models.Host
		PersonTags        bool
		IsAdmin           bool
		HasMoreHosts      bool
		TotalHosts        int
		OriginalHosts     []models.Person // For the modal display
		OriginalHostsJSON string          // JSON-encoded hosts for JavaScript
	}{
		Podcast:           podcast,
		Hosts:             hosts,
		PersonTags:        len(podcast.Hosts) > 0,
		IsAdmin:           isAdmin,
		HasMoreHosts:      hasMoreHosts,
		TotalHosts:        totalHostCount,
		OriginalHosts:     podcast.Hosts, // Pass all original hosts for modal
		OriginalHostsJSON: originalHostsJSONEncoded,
	}

	if err := s.TemplateManager.Render(w, "podcast.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, fmt.Sprintf("Error rendering page: %v", err), http.StatusInternalServerError)
	}
}

// Updated AddHostHandler function
func (s *Server) AddHostHandler(w http.ResponseWriter, r *http.Request) {
	// Set content type early to ensure it's always set
	w.Header().Set("Content-Type", "application/json")

	if err := r.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	podcastID, err := strconv.Atoi(r.Form.Get("podcastId"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid podcast ID"})
		return
	}

	// Get podcast details to ensure it exists
	podcast, err := s.PodcastService.GetPodcastDetails(strconv.Itoa(podcastID))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Unable to fetch podcast details: " + err.Error()})
		return
	}

	// Create host
	host := models.Host{
		Name:        r.Form.Get("name"),
		Description: r.Form.Get("description"),
		Link:        r.Form.Get("link"),
		Img:         r.Form.Get("img"),
		Podcasts: []models.PodcastAssociation{{
			PodcastID: podcastID,
			Title:     podcast.Title,
			Role:      r.Form.Get("role"),
			Status:    "pending",
		}},
	}

	// Submit host and get back the ID
	hostID, err := s.HostService.SubmitHost(host, podcastID, r.Form.Get("role"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if hostID == 0 {
		json.NewEncoder(w).Encode(map[string]string{"error": "Host ID was not set after submission"})
		return
	}

	log.Printf("Host successfully submitted with ID: %d", hostID)

	// Create response host with the ID
	responseHost := models.Host{
		ID:          hostID,
		Name:        host.Name,
		Description: host.Description,
		Link:        host.Link,
		Img:         host.Img,
		Podcasts: []models.PodcastAssociation{{
			PodcastID: podcastID,
			Title:     podcast.Title,
			Role:      r.Form.Get("role"),
			Status:    "pending",
		}},
	}

	json.NewEncoder(w).Encode(responseHost)
}

// AddEpisodeGuestHandler handles adding a guest to an episode
func (s *Server) AddEpisodeGuestHandler(w http.ResponseWriter, r *http.Request) {
	// Parse both multipart and regular form data
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err := r.ParseForm(); err != nil {
			log.Printf("Failed to parse form data: %v", err)
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
	}

	episodeAudioUrl := r.FormValue("episodeAudioUrl")
	log.Printf("Received episodeAudioUrl: '%s'", episodeAudioUrl)
	if episodeAudioUrl == "" {
		log.Printf("Missing episodeAudioUrl")
		http.Error(w, "Episode audio URL is required", http.StatusBadRequest)
		return
	}

	hostName := r.FormValue("hostName")
	if hostName == "" {
		hostName = r.FormValue("guestName") // Try guestName as fallback
	}
	role := r.FormValue("role")
	description := r.FormValue("description")
	link := r.FormValue("link")
	img := r.FormValue("img")
	
	log.Printf("Received hostName: '%s', role: '%s', description: '%s'", hostName, role, description)

	if hostName == "" || role == "" {
		log.Printf("Missing required fields - hostName: '%s', role: '%s'", hostName, role)
		http.Error(w, "Guest name and role are required", http.StatusBadRequest)
		return
	}

	// First, find or create the episode by audio URL
	episode, err := s.EpisodeService.GetEpisodeByAudioURL(episodeAudioUrl)
	if err != nil {
		log.Printf("Error finding episode by audio URL '%s': %v", episodeAudioUrl, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "Episode not found"})
		return
	}

	// Check if the podcast allows guest submissions (no person tags)
	podcast, err := s.PodcastService.GetPodcastDetails(strconv.Itoa(episode.PodcastID))
	if err != nil {
		log.Printf("Error getting podcast details: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to validate podcast"})
		return
	}

	if len(podcast.Hosts) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "This podcast already has host/guest data from its feed"})
		return
	}

	// Try to find existing host by name, or create a new one
	hosts, err := s.HostService.SearchHosts(hostName, 1)
	if err != nil {
		log.Printf("Error searching hosts: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to search for host"})
		return
	}

	var hostID int
	if len(hosts) > 0 && strings.EqualFold(hosts[0].Name, hostName) {
		// Exact match found
		hostID = hosts[0].ID
	} else {
		// Create new host with provided information
		hostDescription := description
		if hostDescription == "" {
			hostDescription = fmt.Sprintf("Guest on episode: %s", episode.Title)
		}
		
		host := models.Host{
			Name:        hostName,
			Description: hostDescription,
			Link:        link,
			Img:         img,
		}

		newHost, err := s.HostService.CreateHost(host.Name, host.Description, host.Link, host.Img, "", "")
		if err != nil {
			log.Printf("Error creating host: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to create host"})
			return
		}
		hostID = newHost.ID
	}

	// Add the guest to the episode
	err = s.EpisodeService.AddEpisodeGuest(episode.ID, hostID, role)
	if err != nil {
		log.Printf("Error adding episode guest: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to add guest to episode"})
		return
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Guest submission received! It will be reviewed by administrators.",
		"hostName": hostName,
		"role": role,
		"episodeTitle": episode.Title,
	})
}

// SearchHostsHandler handles searching for hosts
func (s *Server) SearchHostsHandler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("name")
	if len(term) < 3 {
		// Search term too short, return empty result
		return
	}

	hosts, err := s.HostService.SearchHosts(term, 5)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.TemplateManager.Render(w, "host-suggestions", hosts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetHostDetailsHandler handles getting host details
func (s *Server) GetHostDetailsHandler(w http.ResponseWriter, r *http.Request) {
	hostID, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	var host models.Host
	if err := host.FindByID(db.DB, hostID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
}

// ProxyImageHandler handles proxying images
func (s *Server) ProxyImageHandler(w http.ResponseWriter, r *http.Request) {
	imageURL := r.URL.Query().Get("url")
	if imageURL == "" {
		http.Error(w, "No image URL provided", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(imageURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy the content type
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))

	// Copy the image data
	io.Copy(w, resp.Body)
}

// GetPodcastAPI handles API requests for podcast details
func (s *Server) GetPodcastAPI(w http.ResponseWriter, r *http.Request) {
	podcastID := chi.URLParam(r, "id")
	podcast, err := s.PodcastService.GetPodcastDetails(podcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(podcast)
}

// GetHostsAPI handles API requests for hosts
func (s *Server) GetHostsAPI(w http.ResponseWriter, r *http.Request) {
	podcastID := chi.URLParam(r, "id")
	idInt, _ := strconv.Atoi(podcastID)
	hosts, err := models.GetApprovedHostsForPodcast(db.DB, idInt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

// GetEpisodesHandler handles API requests for podcast episodes
func (s *Server) GetEpisodesHandler(w http.ResponseWriter, r *http.Request) {
	podcastID := chi.URLParam(r, "id")
	idInt, err := strconv.Atoi(podcastID)
	if err != nil {
		http.Error(w, "Invalid podcast ID", http.StatusBadRequest)
		return
	}

	// Get limit parameter (default to 20)
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	episodes, err := s.EpisodeService.GetEpisodesByPodcastID(idInt, limit)
	if err != nil {
		log.Printf("Error getting episodes for podcast %d: %v", idInt, err)
		http.Error(w, "Failed to get episodes", http.StatusInternalServerError)
		return
	}

	// Render episodes template
	if err := s.TemplateManager.Render(w, "episodes-list.html", episodes); err != nil {
		log.Printf("Error rendering episodes template: %v", err)
		http.Error(w, "Failed to render episodes", http.StatusInternalServerError)
	}
}

// DownloadDatabaseHandler handles downloading the database
func (s *Server) DownloadDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	// Open the database file
	dbPath := s.Config.Database.Path
	dbFile, err := os.Open(dbPath)
	if err != nil {
		http.Error(w, "Unable to open database file", http.StatusInternalServerError)
		return
	}
	defer dbFile.Close()

	// Get file info for size
	fileInfo, err := dbFile.Stat()
	if err != nil {
		http.Error(w, "Unable to get file information", http.StatusInternalServerError)
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Type", "application/x-sqlite3")
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(dbPath))
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))

	// Copy the file to the response writer
	_, err = io.Copy(w, dbFile)
	if err != nil {
		http.Error(w, "Error during file transfer", http.StatusInternalServerError)
		return
	}
}

// GetRecentHostsHandler handles getting recent hosts
func (s *Server) GetRecentHostsHandler(w http.ResponseWriter, r *http.Request) {
	const maxHosts = 6

	hosts, err := s.HostService.GetRecentHosts(maxHosts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Hosts   []models.Host
		Message string
	}{
		Hosts: hosts,
	}

	if len(hosts) == 0 {
		data.Message = "No hosts have been added... yet!"
	}

	if err := s.TemplateManager.Render(w, "recent_hosts.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// DeleteHostHandler handles deleting a host
func (s *Server) DeleteHostHandler(w http.ResponseWriter, r *http.Request) {
	hostID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	// Get host details first (for logging)
	var host models.Host
	if err := host.FindByID(db.DB, hostID); err == nil {
		log.Printf("Deleting host: %s (ID: %d)", host.Name, host.ID)
	}

	// Delete host
	var tempHost models.Host
	tempHost.ID = hostID
	if err := tempHost.Delete(db.DB); err != nil {
		http.Error(w, "Failed to delete host", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// EditHostHandler handles editing a host
func (s *Server) EditHostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	hostID, err := strconv.Atoi(r.FormValue("hostId"))
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	// Create host object
	host := models.Host{
		ID:          hostID,
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		Link:        r.FormValue("link"),
		Img:         r.FormValue("img"),
	}

	// Add role if provided
	role := r.FormValue("role")
	if role != "" {
		host.Podcasts = []models.PodcastAssociation{{
			Role: role,
		}}
	}

	// Update host
	if err := s.HostService.UpdateHost(host); err != nil {
		http.Error(w, "Error updating host", http.StatusInternalServerError)
		return
	}

	// Get updated host for response
	if err := host.FindByID(db.DB, hostID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the updated host HTML
	if err := s.TemplateManager.Render(w, "host-item", host); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// SearchPageHandler handles the dedicated search results page
func (s *Server) SearchPageHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	data := map[string]interface{}{
		"Query": query,
	}

	if query == "" {
		data["Message"] = "Please enter a search term"
	} else if len(query) < 2 {
		data["Message"] = "Please enter at least 2 characters to search"
	} else {
		// Search using PinePods API
		results, err := s.PodcastService.SearchPodcasts(query)
		if err != nil {
			data["Message"] = fmt.Sprintf("Search error: %v", err)
		} else {
			data["Results"] = results
		}
	}

	if err := s.TemplateManager.Render(w, "search_page.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// SearchPodcastsHandler handles searching for podcasts using PinePods API (for HTMX calls)
func (s *Server) SearchPodcastsHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if len(query) < 2 {
		if err := s.TemplateManager.Render(w, "search_results.html", map[string]interface{}{
			"Message": "Please enter at least 2 characters to search",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Search using PinePods API
	results, err := s.PodcastService.SearchPodcasts(query)
	if err != nil {
		if err := s.TemplateManager.Render(w, "search_results.html", map[string]interface{}{
			"Message": fmt.Sprintf("Search error: %v", err),
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	data := map[string]interface{}{
		"Results": results,
		"Query":   query,
	}

	if len(results) == 0 {
		data["Message"] = fmt.Sprintf("No podcasts found for \"%s\"", query)
	}

	if err := s.TemplateManager.Render(w, "search_results.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetStatsHandler handles getting database stats
func (s *Server) GetStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := s.HostService.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.TemplateManager.Render(w, "stats.html", stats); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// GetPopularPodcastsHandler handles getting popular podcasts
func (s *Server) GetPopularPodcastsHandler(w http.ResponseWriter, r *http.Request) {
	podcasts, err := s.HostService.GetPopularPodcasts(6)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Podcasts []models.PodcastSummary
		Message  string
	}{
		Podcasts: podcasts,
	}

	if len(podcasts) == 0 {
		data.Message = "No popular podcasts found"
	}

	if err := s.TemplateManager.Render(w, "popular_podcasts.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
