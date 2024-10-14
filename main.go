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
	"strconv"
	"strings"
	"time"

	"encoding/xml"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
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

var db *sql.DB
var templates *template.Template

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./podpeopledb.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	initDB()

	templates = template.Must(template.ParseGlob("templates/*.html"))

	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler)
	r.HandleFunc("/podcast/{id}", podcastHandler)
	r.HandleFunc("/podcast/", podcastHandler) // This will handle query parameters
	r.HandleFunc("/add-host", addHostHandler).Methods("POST")
	r.HandleFunc("/delete-host/{id}", deleteHostHandler).Methods("DELETE")
	r.HandleFunc("/api/podcast/{id}", getPodcastFromIndexAPI)
	r.HandleFunc("/api/hosts/{id}", getHostsAPI)

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
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
            podcast_id INTEGER
        )
    `)
	if err != nil {
		log.Fatal(err)
	}
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
		// If no <podcast:person> tags were found, fetch hosts from the database
		hosts, err = getHostsForPodcast(podcastID)
		if err != nil {
			log.Printf("Error getting hosts: %v", err)
			http.Error(w, fmt.Sprintf("Error getting hosts: %v", err), http.StatusInternalServerError)
			return
		}
	}

	data := struct {
		Podcast    Podcast
		Hosts      []Host
		PersonTags bool
	}{
		Podcast:    podcast,
		Hosts:      hosts,
		PersonTags: len(podcast.Hosts) > 0,
	}

	err = templates.ExecuteTemplate(w, "podcast.html", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, fmt.Sprintf("Error rendering page: %v", err), http.StatusInternalServerError)
	}
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

	result, err := db.Exec("INSERT INTO hosts (name, role, description, link, img, podcast_id) VALUES (?, ?, ?, ?, ?, ?)",
		host.Name, host.Role, host.Description, host.Link, host.Img, host.PodcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hostID, _ := result.LastInsertId()
	host.ID = int(hostID)

	templates.ExecuteTemplate(w, "host-item", host)
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
			// Merge roles if they're different
			if existingPerson.Role != person.Role {
				existingPerson.Role += ", " + person.Role
			}
			// Append episode if it's not already in the list
			if len(person.Episodes) > 0 && !contains(existingPerson.Episodes, person.Episodes[0]) {
				existingPerson.Episodes = append(existingPerson.Episodes, person.Episodes...)
			}
		} else {
			personCopy := person
			uniqueHosts[person.Name] = &personCopy
		}
	}

	result := make([]Person, 0, len(uniqueHosts))
	for _, person := range uniqueHosts {
		result = append(result, *person)
	}

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
	url := fmt.Sprintf("http://localhost:5000/api/podcast?id=%s", id)
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
