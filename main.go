package main

import (
	"bytes"
	"database/sql"
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
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Description string `json:"description"`
	Link        string `json:"link"`
	Img         string `json:"img"`
	PodcastID   int    `json:"podcastId"`
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
)

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

	// Public routes
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/podcast/{id}", podcastHandler)
	r.HandleFunc("/podcast/", podcastHandler)
	r.HandleFunc("/add-host", addHostHandler).Methods("POST")

	// Admin routes
	r.HandleFunc("/admin/login", adminLoginHandler).Methods("GET", "POST")
	r.HandleFunc("/admin/dashboard", adminAuthMiddleware(adminDashboardHandler))
	r.HandleFunc("/admin/approve/{id}", adminAuthMiddleware(approveHostHandler)).Methods("POST")
	r.HandleFunc("/admin/reject/{id}", adminAuthMiddleware(rejectHostHandler)).Methods("POST")

	// API routes
	r.HandleFunc("/api/podcast/{id}", getPodcastFromIndexAPI)
	r.HandleFunc("/api/hosts/{id}", getHostsAPI)

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	fmt.Println("Server is running on http://localhost:8085")
	log.Fatal(http.ListenAndServe(":8085", r))
}

func initDB() {
	_, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            role TEXT,
            description TEXT,
            link TEXT,
            img TEXT,
            podcast_id INTEGER,
            status TEXT DEFAULT 'pending'
        );
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        );
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
	rows, err := db.Query("SELECT id, name, role, description, link, img, podcast_id FROM hosts WHERE status = 'pending'")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var pendingHosts []Host
	for rows.Next() {
		var h Host
		err := rows.Scan(&h.ID, &h.Name, &h.Role, &h.Description, &h.Link, &h.Img, &h.PodcastID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		pendingHosts = append(pendingHosts, h)
	}

	templates.ExecuteTemplate(w, "admin_dashboard.html", pendingHosts)
}

func approveHostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid host ID", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE hosts SET status = 'approved' WHERE id = ?", hostID)
	if err != nil {
		http.Error(w, "Failed to approve host", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
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
	// Implement your notification system here (e.g., email, push notification)
	log.Printf("New host submission: %s for podcast %d", host.Name, host.PodcastID)
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
	rows, err := db.Query("SELECT id, name, role, description, link, img FROM hosts WHERE podcast_id = ? AND status = 'approved'", podcastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		err := rows.Scan(&h.ID, &h.Name, &h.Role, &h.Description, &h.Link, &h.Img)
		if err != nil {
			return nil, err
		}
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
		imgURL = "" // Clear the URL if it's invalid
	}

	host := Host{
		Name:        r.Form.Get("name"),
		Role:        r.Form.Get("role"),
		Description: r.Form.Get("description"),
		Link:        r.Form.Get("link"),
		Img:         imgURL,
		PodcastID:   podcastID,
	}

	result, err := db.Exec("INSERT INTO hosts (name, role, description, link, img, podcast_id, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
		host.Name, host.Role, host.Description, host.Link, host.Img, host.PodcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hostID, _ := result.LastInsertId()
	host.ID = int(hostID)

	// Send notification (implement this function)
	sendNotificationToAdmin(host)

	// Return JSON response
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
	log.Printf("First 1000 characters of feed content: %s", string(feedContent[:1000]))
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
	rows, err := db.Query("SELECT id, name, role, description, link, img FROM hosts WHERE podcast_id = ?", podcastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		err := rows.Scan(&h.ID, &h.Name, &h.Role, &h.Description, &h.Link, &h.Img)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
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
