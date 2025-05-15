package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"encoding/xml"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Person struct {
	XMLName  xml.Name `xml:"person"`
	Name     string   `xml:",chardata"`
	Role     string   `xml:"role,attr"`
	Group    string   `xml:"group,attr,omitempty"`
	Img      string   `xml:"img,attr,omitempty"`
	Href     string   `xml:"href,attr,omitempty"`
	Episodes []string // List of episode titles this person is associated with
}

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

type Host struct {
	ID          int                  `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Link        string               `json:"link"`
	Img         string               `json:"img"`
	CreatedAt   time.Time            `json:"createdAt"`
	Podcasts    []PodcastAssociation `json:"podcasts,omitempty"`
}

type PodcastAssociation struct {
	PodcastID int    `json:"podcastId"`
	Title     string `json:"podcastTitle"`
	Role      string `json:"role"`
	Status    string `json:"status"`
}

type Admin struct {
	ID       int
	Username string
	Password string
}

var (
	db        *sql.DB
	templates *template.Template
	store     = sessions.NewCookieStore([]byte("secret-key"))
	ntfyURL   = os.Getenv("NTFY_URL")   // e.g., "https://ntfy.sh"
	ntfyTopic = os.Getenv("NTFY_TOPIC") // e.g., "podpeople-notifications"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from ntfy domains
		w.Header().Set("Access-Control-Allow-Origin", "*") // Or specific ntfy domain
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "/app/podpeople-data/podpeopledb.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDB()

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}
	templates = template.Must(template.New("").Funcs(funcMap).ParseGlob("templates/*.html"))

	r := mux.NewRouter()
	r.Use(corsMiddleware)

	// Public routes
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/podcast/{id}", podcastHandler)
	r.HandleFunc("/podcast/", podcastHandler)
	r.HandleFunc("/add-host", addHostHandler).Methods("POST")
	r.HandleFunc("/search-hosts", searchHostsHandler)
	r.HandleFunc("/get-host-details", getHostDetailsHandler)
	r.HandleFunc("/delete-host/{id}", adminAuthMiddleware(deleteHostHandler)).Methods("DELETE")
	r.HandleFunc("/proxy-image", proxyImageHandler)
	r.HandleFunc("/edit-host", adminAuthMiddleware(editHostHandler)).Methods("PUT")

	// Admin routes
	r.HandleFunc("/admin/login", adminLoginHandler).Methods("GET", "POST")
	r.HandleFunc("/admin/dashboard", adminAuthMiddleware(adminDashboardHandler))
	r.HandleFunc("/admin/approve/{id}", adminAuthMiddleware(approveHostHandler)).Methods("POST")
	r.HandleFunc("/admin/reject/{id}", adminAuthMiddleware(rejectHostHandler)).Methods("POST")
	r.HandleFunc("/admin/auto-approve/{key}", autoApproveHandler).Methods("POST")
	r.HandleFunc("/admin/add-admin", adminAuthMiddleware(addAdminHandler)).Methods("POST")
	r.HandleFunc("/admin/edit-admin", adminAuthMiddleware(editAdminHandler)).Methods("PUT")
	r.HandleFunc("/admin/delete-admin/{id}", adminAuthMiddleware(deleteAdminHandler)).Methods("DELETE")

	// API routes
	r.HandleFunc("/api/podcast/{id}", getPodcastFromIndexAPI)
	r.HandleFunc("/api/hosts/{id}", getHostsAPI)
	r.HandleFunc("/api/download-database", downloadDatabaseHandler)
	r.HandleFunc("/api/recent-hosts", getRecentHostsHandler)

	// Update the debug route to use the new schema
	r.HandleFunc("/debug/hosts", func(w http.ResponseWriter, r *http.Request) {
		query := `
			SELECT DISTINCT h.id, h.name, hp.role, hp.status, p.title
			FROM hosts h
			JOIN host_podcasts hp ON h.id = hp.host_id
			JOIN podcasts p ON p.id = hp.podcast_id
			WHERE hp.status = 'approved'
			ORDER BY h.name
		`
		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var hosts []struct {
			ID           int    `json:"id"`
			Name         string `json:"name"`
			Role         string `json:"role"`
			Status       string `json:"status"`
			PodcastTitle string `json:"podcastTitle"`
		}

		for rows.Next() {
			var h struct {
				ID           int    `json:"id"`
				Name         string `json:"name"`
				Role         string `json:"role"`
				Status       string `json:"status"`
				PodcastTitle string `json:"podcastTitle"`
			}
			err := rows.Scan(&h.ID, &h.Name, &h.Role, &h.Status, &h.PodcastTitle)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			hosts = append(hosts, h)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hosts)
	})

	// Docs Routes
	r.HandleFunc("/docs/what-is-this-for", func(w http.ResponseWriter, r *http.Request) {
		templates.ExecuteTemplate(w, "docs_what_is_this_for.html", nil)
	})

	r.HandleFunc("/docs/adding-hosts", func(w http.ResponseWriter, r *http.Request) {
		templates.ExecuteTemplate(w, "docs_adding_hosts.html", nil)
	})

	r.HandleFunc("/docs/integration", func(w http.ResponseWriter, r *http.Request) {
		templates.ExecuteTemplate(w, "docs_integration.html", nil)
	})
	r.HandleFunc("/docs/self-host", func(w http.ResponseWriter, r *http.Request) {
		templates.ExecuteTemplate(w, "docs_self_host.html", nil)
	})

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	fmt.Println("Server is running on http://localhost:8085")
	log.Fatal(http.ListenAndServe(":8085", r))
}

func initDB() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			role TEXT,
			description TEXT,
			link TEXT,
			img TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS podcasts (
			id INTEGER PRIMARY KEY,
			title TEXT NOT NULL,
			feed_url TEXT
		);

		CREATE TABLE IF NOT EXISTS host_podcasts (
			host_id INTEGER,
			podcast_id INTEGER,
			role TEXT NOT NULL,
			status TEXT DEFAULT 'pending',
			approval_key TEXT UNIQUE,
			approval_key_expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (host_id, podcast_id),
			FOREIGN KEY (host_id) REFERENCES hosts(id),
			FOREIGN KEY (podcast_id) REFERENCES podcasts(id)
		);
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        );

		-- Add IF NOT EXISTS to index creation
		CREATE INDEX IF NOT EXISTS idx_host_podcasts_host_id ON host_podcasts(host_id);
		CREATE INDEX IF NOT EXISTS idx_host_podcasts_podcast_id ON host_podcasts(podcast_id);
		CREATE INDEX IF NOT EXISTS idx_host_podcasts_status ON host_podcasts(status);

    `)
	if err != nil {
		log.Fatal(err)
	}

	// Check if any admin user exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if err != nil {
		log.Fatal(err)
	}

	if count == 0 {
		// No admin exists, create one
		username := os.Getenv("ADMIN_USERNAME")
		password := os.Getenv("ADMIN_PASSWORD")

		if username == "" || password == "" {
			// Use default values if environment variables are not set
			username = "admin"
			password = "admin"
			log.Println("Warning: Using default admin credentials. Please change them immediately.")
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		_, err = db.Exec("INSERT INTO admins (username, password) VALUES (?, ?)", username, string(hashedPassword))
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Admin user '%s' created successfully\n", username)
	}
}

func generateApprovalKey() (string, error) {
	bytes := make([]byte, 32) // 256 bits of randomness
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func createHostApprovalKey(hostID int) (string, error) {
	key, err := generateApprovalKey()
	if err != nil {
		return "", err
	}

	// Set expiration time to 24 hours from now
	expiresAt := time.Now().Add(24 * time.Hour)

	// Update all pending associations for this host
	_, err = db.Exec(`
        UPDATE host_podcasts
        SET approval_key = ?, approval_key_expires_at = ?
        WHERE host_id = ? AND status = 'pending'`,
		key, expiresAt, hostID)

	if err != nil {
		return "", err
	}

	return key, nil
}

func adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		templates.ExecuteTemplate(w, "admin_login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var admin Admin
	err := db.QueryRow("SELECT id, username, password FROM admins WHERE username = ?", username).Scan(&admin.ID, &admin.Username, &admin.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["authenticated"] = true
	session.Save(r, w)

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get pending hosts
	query := `
        SELECT h.id, h.name, h.description, h.link, h.img,
               hp.role, hp.podcast_id, p.title
        FROM hosts h
        JOIN host_podcasts hp ON h.id = hp.host_id
        JOIN podcasts p ON p.id = hp.podcast_id
        WHERE hp.status = 'pending'`

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var pendingHosts []Host
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		h.Podcasts = []PodcastAssociation{{
			PodcastID: podcastID,
			Title:     podcastTitle,
			Role:      role,
			Status:    "pending",
		}}
		pendingHosts = append(pendingHosts, h)
	}

	// Get admin users
	adminRows, err := db.Query("SELECT id, username FROM admins ORDER BY username")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer adminRows.Close()

	var admins []Admin
	for adminRows.Next() {
		var admin Admin
		err := adminRows.Scan(&admin.ID, &admin.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		admins = append(admins, admin)
	}
	// In adminDashboardHandler, right before executing the template:
	log.Printf("Found %d pending hosts and %d admins", len(pendingHosts), len(admins))

	// Create combined data structure
	data := struct {
		PendingHosts []Host  `json:"pendingHosts"`
		Admins       []Admin `json:"admins"`
	}{
		PendingHosts: pendingHosts,
		Admins:       admins,
	}

	templates.ExecuteTemplate(w, "admin_dashboard", data)
}

func approveHostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	hostID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	// Update the status in host_podcasts table
	_, err = db.Exec(`
        UPDATE host_podcasts
        SET status = 'approved'
        WHERE host_id = ?
        AND status = 'pending'`,
		hostID)
	if err != nil {
		http.Error(w, "Failed to approve host", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// New handler for one-time approval links
func autoApproveHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]

	result, err := db.Exec(`
        UPDATE host_podcasts
        SET status = 'approved',
            approval_key = NULL,
            approval_key_expires_at = NULL
        WHERE approval_key = ?
        AND approval_key_expires_at > CURRENT_TIMESTAMP
        AND status = 'pending'`,
		key)

	if err != nil {
		http.Error(w, "Failed to process approval", http.StatusInternalServerError)
		return
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		http.Error(w, "Invalid or expired approval key", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func rejectHostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM hosts WHERE id = ?", hostID)
	if err != nil {
		http.Error(w, "Failed to reject host", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

func sendNotificationToAdmin(host Host) {
	// Generate approval key
	approvalKey, err := createHostApprovalKey(host.ID)
	if err != nil {
		log.Printf("Error generating approval key: %v", err)
		return
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		log.Printf("BASE_URL not set, defaulting to http://localhost:8085")
		baseURL = "http://localhost:8085"
	}

	// Build podcast associations string
	var podcastInfo string
	for _, p := range host.Podcasts {
		podcastInfo += fmt.Sprintf("\nPodcast: %s (Role: %s)", p.Title, p.Role)
	}

	message := fmt.Sprintf(`New host submission requires approval:
Host: %s
%s
Description: %s`,
		host.Name,
		podcastInfo,
		host.Description,
	)

	notificationURL := fmt.Sprintf("%s/%s", ntfyURL, ntfyTopic)
	req, err := http.NewRequest("POST", notificationURL, bytes.NewBufferString(message))
	if err != nil {
		log.Printf("Error creating notification request: %v", err)
		return
	}

	// Set the one-time approval link
	approvalURL := fmt.Sprintf("%s/admin/auto-approve/%s", baseURL, approvalKey)
	req.Header.Set("Title", "New Host Submission 🎙️")
	req.Header.Set("Priority", "default")
	req.Header.Set("Tags", "new,microphone,user")
	req.Header.Set("Click", fmt.Sprintf("%s/admin/dashboard", baseURL))
	if host.Img != "" {
		req.Header.Set("Attach", host.Img)
	}

	// Set one-time approval action
	req.Header.Set("Actions", fmt.Sprintf("http, Approve, %s, method=POST", approvalURL))

	// Send the notification
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Error response from ntfy: %s, %s", resp.Status, string(body))
		return
	}

	log.Printf("Successfully sent notification for host: %s", host.Name)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "home.html", nil)
}

func podcastHandler(w http.ResponseWriter, r *http.Request) {
	var podcastID string
	vars := mux.Vars(r)
	if id, ok := vars["id"]; ok {
		podcastID = id
	} else {
		podcastID = r.URL.Query().Get("id")
	}

	if podcastID == "" {
		http.Error(w, "Missing podcast ID", http.StatusBadRequest)
		return
	}

	podcast, err := getPodcastDetails(podcastID)
	if err != nil {
		log.Printf("Error getting podcast details: %v", err)
		http.Error(w, fmt.Sprintf("Error getting podcast details: %v", err), http.StatusInternalServerError)
		return
	}

	var hosts []Host
	if len(podcast.Hosts) == 0 {
		// If no <podcast:person> tags were found, fetch approved hosts from the database
		hosts, err = getApprovedHostsForPodcast(podcastID)
		if err != nil {
			log.Printf("Error getting hosts: %v", err)
			http.Error(w, fmt.Sprintf("Error getting hosts: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		// Convert Person structs to Host structs
		for _, person := range podcast.Hosts {
			host := Host{
				Name: person.Name,
				Img:  person.Img,
				Link: person.Href,
				Podcasts: []PodcastAssociation{{
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
	session, _ := store.Get(r, "session")
	isAdmin := false
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		isAdmin = true
	}

	data := struct {
		Podcast    Podcast
		Hosts      []Host
		PersonTags bool
		IsAdmin    bool
	}{
		Podcast:    podcast,
		Hosts:      hosts,
		PersonTags: len(podcast.Hosts) > 0,
		IsAdmin:    isAdmin,
	}

	err = templates.ExecuteTemplate(w, "podcast.html", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, fmt.Sprintf("Error rendering page: %v", err), http.StatusInternalServerError)
	}
}

func getApprovedHostsForPodcast(podcastID string) ([]Host, error) {
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
			PodcastID: parseInt(podcastID),
			Role:      role,
			Status:    "approved",
		}}

		hosts = append(hosts, h)
	}
	return hosts, nil
}

func isValidImageURL(url string) bool {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK && strings.HasPrefix(resp.Header.Get("Content-Type"), "image/")
}

func addHostHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	podcastID, _ := strconv.Atoi(r.Form.Get("podcastId"))
	imgURL := r.Form.Get("img")
	if imgURL != "" && !isValidImageURL(imgURL) {
		imgURL = ""
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Check if host exists
	var hostID int
	name := r.Form.Get("name")
	err = tx.QueryRow("SELECT id FROM hosts WHERE name = ?", name).Scan(&hostID)

	if err == sql.ErrNoRows {
		// Create new host
		result, err := tx.Exec(`
            INSERT INTO hosts (name, description, link, img)
            VALUES (?, ?, ?, ?)`,
			name, r.Form.Get("description"), r.Form.Get("link"), imgURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hostID64, _ := result.LastInsertId()
		hostID = int(hostID64)
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get podcast details and ensure it exists in podcasts table
	podcast, err := getPodcastDetails(strconv.Itoa(podcastID))
	if err != nil {
		http.Error(w, "Unable to fetch podcast details", http.StatusInternalServerError)
		return
	}

	// Insert or update podcast
	_, err = tx.Exec(`
        INSERT INTO podcasts (id, title, feed_url)
        VALUES (?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
        title = excluded.title,
        feed_url = excluded.feed_url`,
		podcastID, podcast.Title, podcast.FeedURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create host-podcast association
	_, err = tx.Exec(`
        INSERT INTO host_podcasts (host_id, podcast_id, role, status)
        VALUES (?, ?, ?, 'pending')
        ON CONFLICT (host_id, podcast_id) DO UPDATE SET
        role = excluded.role,
        status = 'pending'`,
		hostID, podcastID, r.Form.Get("role"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tx.Commit()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get complete host info for response
	host, err := getHostWithPodcasts(hostID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendNotificationToAdmin(host)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
}

func deleteHostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM hosts WHERE id = ?", hostID)
	if err != nil {
		http.Error(w, "Failed to delete host", http.StatusInternalServerError)
		return
	}

	// Return an empty response to indicate success
	w.WriteHeader(http.StatusOK)
}

func deduplicateHosts(persons []Person) []Person {
	uniqueHosts := make(map[string]*Person)
	for _, person := range persons {
		if existingPerson, found := uniqueHosts[person.Name]; found {
			// Prioritize "host" role
			if strings.Contains(strings.ToLower(person.Role), "host") {
				existingPerson.Role = "Host"
			} else if existingPerson.Role != "Host" {
				existingPerson.Role = "Guest"
			}
			// Append episode if it's not already in the list
			if len(person.Episodes) > 0 && !contains(existingPerson.Episodes, person.Episodes[0]) {
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

	result := make([]Person, 0, len(uniqueHosts))
	for _, person := range uniqueHosts {
		result = append(result, *person)
	}

	// Sort the result slice
	sort.Slice(result, func(i, j int) bool {
		return len(result[i].Episodes) > len(result[j].Episodes)
	})

	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getPodcastDetails(id string) (Podcast, error) {
	searchAPIURL := os.Getenv("SEARCH_API_URL")
	log.Printf("SEARCH_API_URL: %s", searchAPIURL) // Add this line

	if searchAPIURL == "" {
		return Podcast{}, fmt.Errorf("SEARCH_API_URL environment variable is not set")
	}

	url := fmt.Sprintf("%s/api/podcast?id=%s", searchAPIURL, id)
	resp, err := http.Get(url)
	if err != nil {
		return Podcast{}, fmt.Errorf("error making request to API: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Podcast{}, fmt.Errorf("error reading response body: %v", err)
	}

	var result struct {
		Feed Podcast `json:"feed"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return Podcast{}, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	log.Printf("Fetching podcast feed from URL: %s", result.Feed.FeedURL)
	feedResp, err := http.Get(result.Feed.FeedURL)
	if err != nil {
		return Podcast{}, fmt.Errorf("error fetching podcast feed: %v", err)
	}
	defer feedResp.Body.Close()

	// Log a sample of the feed content
	feedContent, _ := ioutil.ReadAll(feedResp.Body)
	if len(feedContent) > 1000 {
		log.Printf("First 1000 characters of feed content: %s", string(feedContent[:1000]))
	} else {
		log.Printf("Feed content (%d characters): %s", len(feedContent), string(feedContent))
	}
	feedResp.Body = ioutil.NopCloser(bytes.NewBuffer(feedContent))

	decoder := xml.NewDecoder(feedResp.Body)
	var persons []Person
	var currentEpisodeTitle string

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Podcast{}, fmt.Errorf("error parsing feed XML: %v", err)
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
				var person Person
				err = decoder.DecodeElement(&person, &se)
				if err != nil {
					return Podcast{}, fmt.Errorf("error decoding person element: %v", err)
				}
				if currentEpisodeTitle != "" {
					person.Episodes = []string{currentEpisodeTitle}
				}
				log.Printf("Decoded person: %+v", person)
				persons = append(persons, person)
			}
		}
	}

	log.Printf("Found %d persons in the podcast feed", len(persons))
	result.Feed.Hosts = deduplicateHosts(persons)
	return result.Feed, nil
}

func getHostsForPodcast(podcastID string) ([]Host, error) {
	query := `
        SELECT h.id, h.name, h.description, h.link, h.img, hp.role
        FROM hosts h
        JOIN host_podcasts hp ON h.id = hp.host_id
        WHERE hp.podcast_id = ?`

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
			PodcastID: parseInt(podcastID),
			Role:      role,
		}}

		hosts = append(hosts, h)
	}
	return hosts, nil
}

func parseInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func getPodcastFromIndexAPI(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	podcastID := vars["id"]

	podcast, err := getPodcastDetails(podcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(podcast)
}

func getHostsAPI(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	podcastID := vars["id"]

	hosts, err := getHostsForPodcast(podcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(hosts)
}

func downloadDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	// Open the database file
	dbPath := "/app/podpeople-data/podpeopledb.sqlite"
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
	w.Header().Set("Content-Disposition", "attachment; filename=podpeopledb.sqlite")
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))

	// Copy the file to the response writer
	_, err = io.Copy(w, dbFile)
	if err != nil {
		http.Error(w, "Error during file transfer", http.StatusInternalServerError)
		return
	}
}

type RecentHostsResponse struct {
	Hosts    []Host `json:"hosts"`
	Message  string `json:"message,omitempty"`
	Count    int    `json:"count"`
	MaxHosts int    `json:"maxHosts"`
}

func getRecentHostsHandler(w http.ResponseWriter, r *http.Request) {
	const maxHosts = 6

	query := `
        SELECT DISTINCT h.id, h.name, h.img, h.created_at,
               hp.role, hp.podcast_id, p.title
        FROM hosts h
        JOIN host_podcasts hp ON h.id = hp.host_id
        JOIN podcasts p ON p.id = hp.podcast_id
        WHERE hp.status = 'approved'
        ORDER BY h.created_at DESC
        LIMIT ?`

	rows, err := db.Query(query, maxHosts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
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

	data := struct {
		Hosts   []Host
		Message string
	}{
		Hosts: hosts,
	}

	if len(hosts) == 0 {
		data.Message = "No hosts have been added... yet!"
	}

	// Return HTML instead of JSON
	err = templates.ExecuteTemplate(w, "recent_hosts.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func searchHostsHandler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("name")
	log.Printf("Received search term: %s", term)

	if len(term) < 3 {
		log.Printf("Search term too short, returning empty result")
		return
	}

	query := `
        SELECT DISTINCT h.id, h.name, hp.role, h.description, h.link, h.img, hp.podcast_id, p.title
        FROM hosts h
        JOIN host_podcasts hp ON h.id = hp.host_id
        JOIN podcasts p ON p.id = hp.podcast_id
        WHERE hp.status = 'approved'
        AND h.name LIKE ?
        ORDER BY h.name
        LIMIT 5`

	searchTerm := "%" + term + "%"
	log.Printf("Executing query: %s with term: %s", query, searchTerm)

	rows, err := db.Query(query, searchTerm)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var role string // Separate variable for role
		var podcastID int
		var podcastTitle string

		err := rows.Scan(
			&h.ID,
			&h.Name,
			&role, // Scan into role variable
			&h.Description,
			&h.Link,
			&h.Img,
			&podcastID,
			&podcastTitle,
		)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Add podcast info to host
		h.Podcasts = append(h.Podcasts, PodcastAssociation{
			PodcastID: podcastID,
			Title:     podcastTitle,
			Role:      role, // Use the role variable
			Status:    "approved",
		})

		hosts = append(hosts, h)
	}

	log.Printf("Found %d matching hosts", len(hosts))

	if t := templates.Lookup("host-suggestions"); t == nil {
		log.Printf("Template 'host-suggestions' not found!")
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	err = templates.ExecuteTemplate(w, "host-suggestions", hosts)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully executed template")
}

func getHostDetailsHandler(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("id")
	if hostID == "" {
		http.Error(w, "Host ID is required", http.StatusBadRequest)
		return
	}

	host, err := getHostWithPodcasts(parseInt(hostID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
}

func getHostWithPodcasts(hostID int) (Host, error) {
	var host Host
	err := db.QueryRow(`
        SELECT id, name, description, link, img
        FROM hosts
        WHERE id = ?`,
		hostID).Scan(&host.ID, &host.Name, &host.Description, &host.Link, &host.Img)
	if err != nil {
		return host, err
	}

	rows, err := db.Query(`
        SELECT hp.podcast_id, p.title, hp.role, hp.status
        FROM host_podcasts hp
        JOIN podcasts p ON p.id = hp.podcast_id
        WHERE hp.host_id = ?`,
		hostID)
	if err != nil {
		return host, err
	}
	defer rows.Close()

	for rows.Next() {
		var pa PodcastAssociation
		err := rows.Scan(&pa.PodcastID, &pa.Title, &pa.Role, &pa.Status)
		if err != nil {
			return host, err
		}
		host.Podcasts = append(host.Podcasts, pa)
	}

	return host, nil
}

// Add this handler
func proxyImageHandler(w http.ResponseWriter, r *http.Request) {
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

func editHostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if user is admin
	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hostID, _ := strconv.Atoi(r.Form.Get("hostId"))

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Update host details
	_, err = tx.Exec(`
        UPDATE hosts
        SET name = ?, description = ?, link = ?, img = ?
        WHERE id = ?`,
		r.Form.Get("name"),
		r.Form.Get("description"),
		r.Form.Get("link"),
		r.Form.Get("img"),
		hostID,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update role in host_podcasts table
	_, err = tx.Exec(`
        UPDATE host_podcasts
        SET role = ?
        WHERE host_id = ?`,
		r.Form.Get("role"),
		hostID,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tx.Commit()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return updated host data
	host, err := getHostWithPodcasts(hostID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the updated host HTML
	err = templates.ExecuteTemplate(w, "host-item", host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func addAdminHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Add admin request received")

	if r.Method != http.MethodPost {
		log.Printf("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	log.Printf("Received username: %s (password length: %d)", username, len(password))

	if username == "" || password == "" {
		log.Printf("Missing required fields")
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	// Insert new admin
	_, err = db.Exec("INSERT INTO admins (username, password) VALUES (?, ?)",
		username, string(hashedPassword))
	if err != nil {
		log.Printf("Error inserting admin: %v", err)
		http.Error(w, "Error creating admin user", http.StatusInternalServerError)
		return
	}

	// Get updated list of admins
	adminRows, err := db.Query("SELECT id, username FROM admins ORDER BY username")
	if err != nil {
		log.Printf("Error querying admins: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer adminRows.Close()

	var admins []Admin
	for adminRows.Next() {
		var admin Admin
		err := adminRows.Scan(&admin.ID, &admin.Username)
		if err != nil {
			log.Printf("Error scanning admin row: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		admins = append(admins, admin)
	}

	log.Printf("Successfully added admin, returning updated list of %d admins", len(admins))

	// Set content type
	w.Header().Set("Content-Type", "text/html")

	// Return just the admin list HTML
	err = templates.ExecuteTemplate(w, "admin-users-list", admins)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func editAdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	adminID := r.FormValue("adminId")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if adminID == "" || username == "" {
		http.Error(w, "Admin ID and username are required", http.StatusBadRequest)
		return
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if password != "" {
		// Update username and password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return
		}

		_, err = tx.Exec("UPDATE admins SET username = ?, password = ? WHERE id = ?",
			username, string(hashedPassword), adminID)
	} else {
		// Update username only
		_, err = tx.Exec("UPDATE admins SET username = ? WHERE id = ?",
			username, adminID)
	}

	if err != nil {
		http.Error(w, "Error updating admin user", http.StatusInternalServerError)
		return
	}

	err = tx.Commit()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

func deleteAdminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	adminID := vars["id"]

	// Don't allow deleting the last admin
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count <= 1 {
		http.Error(w, "Cannot delete the last admin user", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM admins WHERE id = ?", adminID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
