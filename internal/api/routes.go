package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// registerRoutes registers all application routes
func (s *Server) registerRoutes() {
	// Public routes
	s.Router.Get("/", s.HomeHandler)
	s.Router.Get("/search", s.SearchPageHandler)
	s.Router.Get("/podcast/{id}", s.PodcastHandler)
	s.Router.Get("/podcast/", s.PodcastHandler) // For query param version
	s.Router.Post("/add-host", s.AddHostHandler)
	s.Router.Post("/add-episode-guest", s.AddEpisodeGuestHandler)
	s.Router.Get("/search-hosts", s.SearchHostsHandler)
	s.Router.Get("/get-host-details", s.GetHostDetailsHandler)
	s.Router.Get("/proxy-image", s.ProxyImageHandler)

	// Add this line to register the edit-host endpoint for PUT requests
	s.Router.Put("/edit-host", s.EditHostHandler)
	// Add this line for DELETE route
	s.Router.Delete("/delete-host/{id}", s.DeleteHostHandler)

	// Admin routes (with auth middleware)
	s.Router.Route("/admin", func(r chi.Router) {
		// Login route (no auth required)
		r.Get("/login", s.AdminLoginPageHandler)
		r.Post("/login", s.AdminLoginHandler)

		// Routes that require authentication
		r.Group(func(r chi.Router) {
			r.Use(s.AdminAuthMiddleware)

			r.Get("/dashboard", s.AdminDashboardHandler)
			r.Post("/approve/{id}", s.ApproveHostHandler)
			r.Post("/reject/{id}", s.RejectHostHandler)
			r.Post("/approve-episode-guest/{id}", s.ApproveEpisodeGuestHandler)
			r.Post("/reject-episode-guest/{id}", s.RejectEpisodeGuestHandler)
			r.Post("/add-admin", s.AddAdminHandler)
			r.Put("/edit-admin", s.EditAdminHandler)
			r.Delete("/delete-admin/{id}", s.DeleteAdminHandler)
			r.Put("/edit-host", s.EditHostHandler)
			r.Delete("/delete-host/{id}", s.DeleteHostHandler)
			r.Post("/import-database", s.ImportDatabaseHandler)
			r.Get("/export-full-database", s.AdminExportFullDatabaseHandler)
		})

		// Auto-approve route (special case, uses approval key)
		r.Post("/auto-approve/{key}", s.AutoApproveHandler)
	})

	// API routes
	s.Router.Route("/api", func(r chi.Router) {
		r.Get("/podcast/{id}", s.GetPodcastAPI)
		r.Get("/podcast/{id}/episodes", s.GetEpisodesHandler)
		r.Get("/hosts/{id}", s.GetHostsAPI)
		r.Get("/download-database", s.DownloadDatabaseHandler)
		r.Get("/public-dataset", s.PublicDatasetExportHandler)
		r.Get("/recent-hosts", s.GetRecentHostsHandler)
		r.Get("/search-podcasts", s.SearchPodcastsHandler)
		r.Get("/stats", s.GetStatsHandler)
		r.Get("/popular-podcasts", s.GetPopularPodcastsHandler)
	})

	// Documentation routes
	s.Router.Route("/docs", func(r chi.Router) {
		r.Get("/what-is-this-for", s.DocsWhatIsThisForHandler)
		r.Get("/adding-hosts", s.DocsAddingHostsHandler)
		r.Get("/integration", s.DocsIntegrationHandler)
		r.Get("/self-host", s.DocsSelfHostHandler)
	})

	// Static files
	fileServer := http.FileServer(http.Dir("./static"))
	s.Router.Handle("/static/*", http.StripPrefix("/static/", fileServer))
}

// AdminAuthMiddleware is a middleware that checks if the user is authenticated
func (s *Server) AdminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.SessionManager.GetBool(r.Context(), "authenticated") {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
