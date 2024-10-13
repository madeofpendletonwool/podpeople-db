package main

import (
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	// "os"
	"strconv"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

type Podcast struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	FeedURL     string `json:"feedUrl"`
}

type Host struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Link        string `json:"link"`
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
	r.HandleFunc("/add-host", addHostHandler).Methods("POST")
	r.HandleFunc("/api/podcast/{id}", getPodcastFromIndexAPI)

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func initDB() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT,
			description TEXT,
			link TEXT,
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
	vars := mux.Vars(r)
	podcastID := vars["id"]

	podcast, err := getPodcastDetails(podcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hosts, err := getHostsForPodcast(podcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Podcast Podcast
		Hosts   []Host
	}{
		Podcast: podcast,
		Hosts:   hosts,
	}

	templates.ExecuteTemplate(w, "podcast.html", data)
}

func addHostHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	podcastID, _ := strconv.Atoi(r.Form.Get("podcastId"))
	host := Host{
		Name:        r.Form.Get("name"),
		Description: r.Form.Get("description"),
		Link:        r.Form.Get("link"),
		PodcastID:   podcastID,
	}

	_, err = db.Exec("INSERT INTO hosts (name, description, link, podcast_id) VALUES (?, ?, ?, ?)",
		host.Name, host.Description, host.Link, host.PodcastID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/podcast/%d", podcastID), http.StatusSeeOther)
}

func getPodcastDetails(id string) (Podcast, error) {
	// This is a placeholder. In a real application, you would call the Podcast Index API here.
	return Podcast{
		ID:          1,
		Title:       "Example Podcast",
		Description: "This is an example podcast",
		FeedURL:     "http://example.com/feed",
	}, nil
}

func getHostsForPodcast(podcastID string) ([]Host, error) {
	rows, err := db.Query("SELECT id, name, description, link FROM hosts WHERE podcast_id = ?", podcastID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		err := rows.Scan(&h.ID, &h.Name, &h.Description, &h.Link)
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

	apiKey := os.Getenv("API_KEY")
	apiSecret := os.Getenv("API_SECRET")
	apiHeaderTime := strconv.FormatInt(time.Now().Unix(), 10)

	// Create the authorization hash
	hash := sha1.New()
	hash.Write([]byte(apiKey + apiSecret + apiHeaderTime))
	authHeader := fmt.Sprintf("%x", hash.Sum(nil))

	// Create the request
	url := fmt.Sprintf("https://api.podcastindex.org/api/1.0/podcasts/byfeedid?id=%s", podcastID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the required headers
	req.Header.Set("User-Agent", "PodPeopleDB/1.0")
	req.Header.Set("X-Auth-Key", apiKey)
	req.Header.Set("X-Auth-Date", apiHeaderTime)
	req.Header.Set("Authorization", authHeader)

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var result struct {
		Feed Podcast `json:"feed"`
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the podcast data
	json.NewEncoder(w).Encode(result.Feed)
}
