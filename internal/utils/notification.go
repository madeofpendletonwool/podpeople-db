package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/madeofpendletonwool/podpeople-db/internal/config"
	"github.com/madeofpendletonwool/podpeople-db/internal/models"
)

// NotificationService handles sending notifications
type NotificationService struct {
	Config *config.Config
}

// NewNotificationService creates a new notification service
func NewNotificationService(cfg *config.Config) *NotificationService {
	return &NotificationService{
		Config: cfg,
	}
}

// SendNewHostNotification sends a notification about a new host submission
func (s *NotificationService) SendNewHostNotification(host models.Host, approvalKey string) error {
	// If ntfy topic is not configured, skip notification
	if s.Config.Ntfy.Topic == "" {
		log.Println("NTFY_TOPIC not configured, skipping notification")
		return nil
	}

	// Build podcast associations string
	var podcastInfo string
	for _, p := range host.Podcasts {
		podcastInfo += fmt.Sprintf("\nPodcast: %s (Role: %s)", p.Title, p.Role)
	}

	message := fmt.Sprintf(`New host submission requires approval:
Host: %s
%s
Description: %s`,
		host.Name,
		podcastInfo,
		host.Description,
	)

	notificationURL := fmt.Sprintf("%s/%s", s.Config.Ntfy.URL, s.Config.Ntfy.Topic)
	req, err := http.NewRequest("POST", notificationURL, bytes.NewBufferString(message))
	if err != nil {
		return fmt.Errorf("error creating notification request: %w", err)
	}

	// Set the one-time approval link
	approvalURL := fmt.Sprintf("%s/admin/auto-approve/%s", s.Config.Server.BaseURL, approvalKey)
	req.Header.Set("Title", "New Host Submission 🎙️")
	req.Header.Set("Priority", "default")
	req.Header.Set("Tags", "new,microphone,user")
	req.Header.Set("Click", fmt.Sprintf("%s/admin/dashboard", s.Config.Server.BaseURL))
	if host.Img != "" {
		req.Header.Set("Attach", host.Img)
	}

	// Set one-time approval action
	req.Header.Set("Actions", fmt.Sprintf("http, Approve, %s, method=POST", approvalURL))

	// Send the notification
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("error response from ntfy: %s, %s", resp.Status, string(body))
	}

	log.Printf("Successfully sent notification for host: %s", host.Name)
	return nil
}

// GenerateApprovalKey generates a random approval key
func GenerateApprovalKey() (string, error) {
	bytes := make([]byte, 32) // 256 bits of randomness
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// IsValidImageURL checks if a URL points to a valid image
func IsValidImageURL(url string) bool {
	if url == "" {
		return false
	}

	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	return resp.StatusCode == http.StatusOK &&
		(contentType == "image/jpeg" ||
			contentType == "image/png" ||
			contentType == "image/gif" ||
			contentType == "image/webp" ||
			contentType == "image/svg+xml")
}
