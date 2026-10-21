package api

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

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

// rateLimiter is a small in-memory sliding-window limiter keyed by client IP. Used to protect the
// public, unauthenticated submission endpoints from abuse without pulling in an external
// dependency or a shared store (podpeople is single-instance + SQLite).
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	// Periodically evict stale buckets so the map doesn't grow unbounded.
	go func() {
		ticker := time.NewTicker(window)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)
	for ip, times := range rl.requests {
		kept := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = kept
		}
	}
}

// allow records a hit for ip and reports whether it is within the limit.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)

	kept := rl.requests[ip][:0]
	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.requests[ip] = kept
		return false
	}
	rl.requests[ip] = append(kept, now)
	return true
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// First entry is the original client.
		if i := strings.IndexByte(fwd, ','); i >= 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// rateLimitMiddleware returns middleware that limits each client IP to `limit` requests per
// `window`, responding 429 when exceeded. Scope it to specific routes (e.g. submissions).
func rateLimitMiddleware(limit int, window time.Duration) func(http.Handler) http.Handler {
	rl := newRateLimiter(limit, window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.allow(clientIP(r)) {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
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
