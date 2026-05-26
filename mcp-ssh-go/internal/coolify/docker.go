package coolify

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds credentials and base URL for Coolify API.
type Config struct {
	BaseURL       string // e.g. "http://192.168.1.150:8000" or "https://coolify.yourdomain.com"
	Token         string // Bearer token
	SkipTLSVerify bool
}

// Client is the client for the Coolify REST API.
type Client struct {
	config Config
	client *http.Client
}

// NewClientFromEnv initializes the Coolify client using environment variables.
func NewClientFromEnv() (*Client, error) {
	baseURL := os.Getenv("COOLIFY_URL")
	token := os.Getenv("COOLIFY_TOKEN")
	skipVerifyStr := os.Getenv("COOLIFY_SKIP_TLS_VERIFY")

	if baseURL == "" {
		return nil, fmt.Errorf("COOLIFY_URL is not set")
	}
	if token == "" {
		return nil, fmt.Errorf("COOLIFY_TOKEN is not set")
	}

	// Clean trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	skipVerify := true
	if strings.ToLower(skipVerifyStr) == "false" {
		skipVerify = false
	}

	cfg := Config{
		BaseURL:       baseURL,
		Token:         token,
		SkipTLSVerify: skipVerify,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify},
	}

	return &Client{
		config: cfg,
		client: &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		},
	}, nil
}

// Application represents the application structure returned by Coolify.
type Application struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	FQDN        string `json:"fqdn,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`
}

// ListApplications fetches all applications from the Coolify instance.
func (c *Client) ListApplications() ([]Application, error) {
	reqURL := fmt.Sprintf("%s/api/v1/applications", c.config.BaseURL)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %s: %s", resp.Status, string(bodyBytes))
	}

	var applications []Application
	if err := json.NewDecoder(resp.Body).Decode(&applications); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return applications, nil
}

// GetApplication fetches a single application by UUID.
func (c *Client) GetApplication(uuid string) (*Application, error) {
	if uuid == "" {
		return nil, fmt.Errorf("application UUID cannot be empty")
	}

	escapedUUID := url.PathEscape(uuid)
	reqURL := fmt.Sprintf("%s/api/v1/applications/%s", c.config.BaseURL, escapedUUID)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %s: %s", resp.Status, string(bodyBytes))
	}

	var app Application
	if err := json.NewDecoder(resp.Body).Decode(&app); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return &app, nil
}

// GetApplicationLogs fetches container logs for the application.
func (c *Client) GetApplicationLogs(uuid string) (string, error) {
	if uuid == "" {
		return "", fmt.Errorf("application UUID cannot be empty")
	}

	escapedUUID := url.PathEscape(uuid)
	reqURL := fmt.Sprintf("%s/api/v1/applications/%s/logs", c.config.BaseURL, escapedUUID)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status %s: %s", resp.Status, string(bodyBytes))
	}

	// Logs could be returned as JSON or raw text depending on API configuration.
	// We check if it is valid JSON, and if so, try to format it, otherwise return as-is.
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jsonResponse); err == nil {
		// If it's a JSON response, maybe logs are in a field (like "logs" or similar)
		if logsField, ok := jsonResponse["logs"].(string); ok {
			return logsField, nil
		}
		// Return pretty formatted JSON representation
		prettyJSON, err := json.MarshalIndent(jsonResponse, "", "  ")
		if err == nil {
			return string(prettyJSON), nil
		}
	}

	return string(bodyBytes), nil
}
