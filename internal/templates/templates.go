package templates

import (
	"html/template"
	"log"
	"net/http"
	"strings"
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
