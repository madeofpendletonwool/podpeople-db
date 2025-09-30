package api

import (
	"net/http"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/madeofpendletonwool/podpeople-db/internal/config"
	"github.com/madeofpendletonwool/podpeople-db/internal/db"
	"github.com/madeofpendletonwool/podpeople-db/internal/services"
	"github.com/madeofpendletonwool/podpeople-db/internal/templates"
)

// Server represents the HTTP server
type Server struct {
	Router          *chi.Mux
	TemplateManager *templates.TemplateManager
	SessionManager  *scs.SessionManager
	Config          *config.Config
	PodcastService  *services.PodcastService
	HostService     *services.HostService
	AdminService    *services.AdminService
	EpisodeService  *services.EpisodeService
}

// NewServer creates a new HTTP server
func NewServer(
	cfg *config.Config,
	tmpl *templates.TemplateManager,
	podcastSvc *services.PodcastService,
	hostSvc *services.HostService,
	adminSvc *services.AdminService,
	episodeSvc *services.EpisodeService,
) *Server {
	// Initialize session manager
	sessionManager := scs.New()
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Store = sqlite3store.New(db.DB)
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	
	// Dynamic cookie security based on request context
	sessionManager.Cookie.Secure = false // Will be set per-request

	// Create router
	r := chi.NewRouter()

	// Add middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(sessionManager.LoadAndSave)
	r.Use(corsMiddleware)

	server := &Server{
		Router:          r,
		TemplateManager: tmpl,
		SessionManager:  sessionManager,
		Config:          cfg,
		PodcastService:  podcastSvc,
		HostService:     hostSvc,
		AdminService:    adminSvc,
		EpisodeService:  episodeSvc,
	}

	// Register routes
	server.registerRoutes()

	return server
}

// ServeHTTP implements the http.Handler interface
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Router.ServeHTTP(w, r)
}

// ReinitializeSessionManager reinitializes the session manager with the new database connection
func (s *Server) ReinitializeSessionManager() {
	s.SessionManager.Lifetime = 24 * time.Hour
	s.SessionManager.Store = sqlite3store.New(db.DB)
	s.SessionManager.Cookie.HttpOnly = true
	s.SessionManager.Cookie.SameSite = http.SameSiteLaxMode
	s.SessionManager.Cookie.Secure = false
}
