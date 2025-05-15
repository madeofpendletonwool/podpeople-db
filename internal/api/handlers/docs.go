package api

import (
	"net/http"
)

// DocsWhatIsThisForHandler handles the "What is this for" documentation page
func (s *Server) DocsWhatIsThisForHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.TemplateManager.Render(w, "docs_what_is_this_for.html", nil); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// DocsAddingHostsHandler handles the "Adding hosts" documentation page
func (s *Server) DocsAddingHostsHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.TemplateManager.Render(w, "docs_adding_hosts.html", nil); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// DocsIntegrationHandler handles the "Integration" documentation page
func (s *Server) DocsIntegrationHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.TemplateManager.Render(w, "docs_integration.html", nil); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// DocsSelfHostHandler handles the "Self-host" documentation page
func (s *Server) DocsSelfHostHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.TemplateManager.Render(w, "docs_self_host.html", nil); err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}
