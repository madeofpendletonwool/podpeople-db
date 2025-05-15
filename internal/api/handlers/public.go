package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/yourusername/podpeople-db/internal/db"
	"github.com/yourusername/podpeople-db/internal/models"
)

// HomeHandler handles the home page
func (s *Server) HomeHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.TemplateManager.Render(w, "home.html", nil); err != nil {
		log.Printf("Error rendering home template: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
}

// PodcastHandler handles the podcast detail page
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
		http.Error(w, "Missing podcast ID", http.StatusBadRequest)
		return
	}

	// Get podcast details
	podcast, err := s.PodcastService.GetPodcastDetails(podcastID)
	if err != nil {
		log.Printf("Error getting podcast details: %v", err)
		http.Error(w, fmt.Sprintf("Error getting podcast details: %v", err), http.StatusInternalServerError)
		return
	}

	var hosts []models.Host
	if len(podcast.Hosts) == 0 {
		// If no <podcast:person> tags were found, fetch approved hosts from the database
		idInt, _ := strconv.Atoi(podcastID)
		hosts, err = models.GetApprovedHostsForPodcast(db.DB, idInt)
		if err != nil {
			log.Printf("Error getting hosts: %v", err)
			http.Error(w, fmt.Sprintf("Error getting hosts: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		// Convert Person structs to Host structs
		for _, person := range podcast.Hosts {
			host := models.Host{
				Name: person.Name,
				Img:  person.Img,
				Link: person.Href,
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

	// Check if the user is an admin
	isAdmin := s.SessionManager.GetBool(r.Context(), "authenticated")

	data := struct {
		Podcast    models.Podcast
		Hosts      []models.Host
		PersonTags bool
		IsAdmin    bool
	}{
		Podcast:    podcast,
		Hosts:      hosts,
		PersonTags: len(podcast.Hosts) > 0,
		IsAdmin:    isAdmin,
	}

	if err := s.TemplateManager.Render(w, "podcast.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, fmt.Sprintf("Error rendering page: %v", err), http.StatusInternalServerError)
	}
}

// AddHostHandler handles adding a new host
func (s *Server) AddHostHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	podcastID, err := strconv.Atoi(r.Form.Get("podcastId"))
	if err != nil {
		http.Error(w, "Invalid podcast ID", http.StatusBadRequest)
		return
	}

	// Get podcast details to ensure it exists
	podcast, err := s.PodcastService.GetPodcastDetails(strconv.Itoa(podcastID))
	if err != nil {
		http.Error(w, "Unable to fetch podcast details", http.StatusInternalServerError)
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

	// Submit host
	if err := s.HostService.SubmitHost(host, podcastID, r.Form.Get("role")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get complete host info for response
	if err := host.FindByID(db.DB, host.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
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
