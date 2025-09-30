package utils

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// ParseInt safely parses a string to an integer with a default value
func ParseInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}

	i, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return i
}

// TruncateString truncates a string to a maximum length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	return s[:maxLen-3] + "..."
}

// Contains checks if a slice contains a string
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveQuotes removes surrounding quotes from a string
func RemoveQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// JSONResponse writes a JSON response with the given status code
func JSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		}
	}
}

// ErrorResponse writes a JSON error response
func ErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	type errorResponse struct {
		Error string `json:"error"`
	}

	JSONResponse(w, errorResponse{Error: message}, statusCode)
}
