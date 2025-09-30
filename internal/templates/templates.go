package templates

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TemplateManager manages HTML templates
type TemplateManager struct {
	Templates *template.Template
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(templateDir string) (*TemplateManager, error) {
	// Define custom template functions
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"sub": func(a, b int) int {
			return a - b
		},
		"js": func(s string) template.JS {
			return template.JS(s)
		},
		"DurationMinutes": func(seconds int) float64 {
			return float64(seconds) / 60.0
		},
		"Truncate": func(text string, length int) string {
			if len(text) <= length {
				return text
			}
			return text[:length] + "..."
		},
		"FormatDate": func(t time.Time) string {
			return t.Format("Jan 2, 2006")
		},
		"urlquery": func(s string) string {
			return url.QueryEscape(s)
		},
	}

	// Parse templates
	templates, err := template.New("").Funcs(funcMap).ParseGlob(templateDir + "/*.html")
	if err != nil {
		return nil, err
	}

	log.Printf("Loaded %d templates from %s", len(templates.Templates()), templateDir)

	return &TemplateManager{
		Templates: templates,
	}, nil
}

// Render renders a template with the given data
func (tm *TemplateManager) Render(w http.ResponseWriter, name string, data interface{}) error {
	return tm.Templates.ExecuteTemplate(w, name, data)
}
