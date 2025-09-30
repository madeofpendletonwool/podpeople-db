package api

import (
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5/middleware"
)

// Middleware returns common middleware for the application
func Middleware(sessionManager *scs.SessionManager) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		middleware.Logger,
		middleware.Recoverer,
		middleware.StripSlashes,
		dynamicSecureMiddleware(sessionManager),
		sessionManager.LoadAndSave,
		corsMiddleware,
	}
}

// AdminAuthMiddleware ensures the user is logged in as an admin
func AdminAuthMiddleware(sessionManager *scs.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if user is authenticated
			if !sessionManager.GetBool(r.Context(), "authenticated") {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// corsMiddleware enables CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from all origins
		w.Header().Set("Access-Control-Allow-Origin", "*")
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

// dynamicSecureMiddleware dynamically sets cookie security based on request headers
func dynamicSecureMiddleware(sessionManager *scs.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Detect HTTPS from various sources
			isHTTPS := r.TLS != nil ||
				r.Header.Get("X-Forwarded-Proto") == "https" ||
				r.Header.Get("X-Forwarded-Ssl") == "on" ||
				r.Header.Get("X-Scheme") == "https"
			
			// Set secure cookie flag dynamically
			sessionManager.Cookie.Secure = isHTTPS
			
			next.ServeHTTP(w, r)
		})
	}
}

// LoggingMiddleware logs requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s - %s %s %s", r.RemoteAddr, r.Proto, r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}
