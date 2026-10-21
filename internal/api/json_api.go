package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/madeofpendletonwool/podpeople-db/internal/models"
)

// writeJSON encodes v as a JSON response.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// parseLimit reads a `limit` query param, clamped to [1, max], defaulting to def.
func parseLimit(r *http.Request, def, max int) int {
	limit := def
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > max {
		limit = max
	}
	return limit
}

// --- C1: JSON discovery endpoints (counterparts to the HTML handlers) ---

// RecentHostsAPIHandler returns recently added hosts as JSON.
func (s *Server) RecentHostsAPIHandler(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.HostService.GetRecentHosts(parseLimit(r, 12, 50))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []models.Host{}
	}
	writeJSON(w, hosts)
}

// PopularPodcastsAPIHandler returns popular podcasts as JSON.
func (s *Server) PopularPodcastsAPIHandler(w http.ResponseWriter, r *http.Request) {
	podcasts, err := s.HostService.GetPopularPodcasts(parseLimit(r, 12, 50))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if podcasts == nil {
		podcasts = []models.PodcastSummary{}
	}
	writeJSON(w, podcasts)
}

// StatsAPIHandler returns database stats as JSON.
func (s *Server) StatsAPIHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := s.HostService.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, stats)
}

// TopHostsAPIHandler returns hosts ranked by number of podcasts, as JSON (browse grid).
func (s *Server) TopHostsAPIHandler(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.HostService.GetTopHosts(parseLimit(r, 24, 100))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if hosts == nil {
		hosts = []models.HostRanked{}
	}
	writeJSON(w, hosts)
}

// --- B5: delta sync ---

// ChangesAPIHandler returns approved records changed since the `since` query param (RFC3339 or
// Unix seconds) for incremental dataset sync by self-hosters.
func (s *Server) ChangesAPIHandler(w http.ResponseWriter, r *http.Request) {
	sinceStr := r.URL.Query().Get("since")
	if sinceStr == "" {
		http.Error(w, "missing required 'since' parameter (RFC3339 or Unix seconds)", http.StatusBadRequest)
		return
	}

	var since time.Time
	if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
		since = t
	} else if unix, err := strconv.ParseInt(sinceStr, 10, 64); err == nil {
		since = time.Unix(unix, 0).UTC()
	} else {
		http.Error(w, "invalid 'since' parameter; use RFC3339 or Unix seconds", http.StatusBadRequest)
		return
	}

	changes, err := s.HostService.GetChangesSince(since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, changes)
}

// --- A2: admin merge tool ---

// DuplicateHostsAPIHandler lists groups of hosts sharing a normalized name (merge candidates).
func (s *Server) DuplicateHostsAPIHandler(w http.ResponseWriter, r *http.Request) {
	groups, err := s.HostService.GetDuplicateHostGroups()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if groups == nil {
		groups = []models.DuplicateHostGroup{}
	}
	writeJSON(w, groups)
}

// MergeHostsHandler folds a duplicate host into a canonical one (admin only).
func (s *Server) MergeHostsHandler(w http.ResponseWriter, r *http.Request) {
	canonicalID, err := strconv.Atoi(r.FormValue("canonical_id"))
	if err != nil {
		http.Error(w, "invalid canonical_id", http.StatusBadRequest)
		return
	}
	duplicateID, err := strconv.Atoi(r.FormValue("duplicate_id"))
	if err != nil {
		http.Error(w, "invalid duplicate_id", http.StatusBadRequest)
		return
	}

	if err := s.HostService.MergeHosts(canonicalID, duplicateID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, map[string]interface{}{
		"success":      true,
		"canonical_id": canonicalID,
		"merged_id":    duplicateID,
	})
}
