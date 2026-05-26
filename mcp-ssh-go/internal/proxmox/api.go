package proxmox

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config represents Proxmox credentials and API URL.
type Config struct {
	BaseURL        string // e.g. "https://192.168.1.100:8006"
	TokenID        string // e.g. "root@pam!sre"
	TokenValue     string // e.g. "uuid-token"
	SkipTLSVerify  bool
}

// Client represents the Proxmox API client.
type Client struct {
	config Config
	client *http.Client
}

// NewClientFromEnv initializes the client using environment variables.
func NewClientFromEnv() (*Client, error) {
	baseURL := os.Getenv("PROXMOX_URL")
	tokenID := os.Getenv("PROXMOX_TOKEN_ID")
	tokenValue := os.Getenv("PROXMOX_TOKEN_VALUE")
	skipVerifyStr := os.Getenv("PROXMOX_SKIP_TLS_VERIFY")

	if baseURL == "" {
		return nil, fmt.Errorf("PROXMOX_URL is not set")
	}
	if tokenID == "" {
		return nil, fmt.Errorf("PROXMOX_TOKEN_ID is not set")
	}
	if tokenValue == "" {
		return nil, fmt.Errorf("PROXMOX_TOKEN_VALUE is not set")
	}

	// Clean trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	skipVerify := true
	if strings.ToLower(skipVerifyStr) == "false" {
		skipVerify = false
	}

	cfg := Config{
		BaseURL:       baseURL,
		TokenID:       tokenID,
		TokenValue:    tokenValue,
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

// NodeStatusData represents the response data for node status.
type NodeStatusData struct {
	CPU     float64 `json:"cpu"`
	Uptime  int64   `json:"uptime"`
	Memory  struct {
		Free  int64 `json:"free"`
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"memory"`
	RootFS struct {
		Free  int64 `json:"free"`
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"rootfs"`
	Swap struct {
		Free  int64 `json:"free"`
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"swap"`
	LoadAvg []float64 `json:"loadavg"`
}

type NodeStatusResponse struct {
	Data NodeStatusData `json:"data"`
}

// GetNodeStatus fetches the status of the specified Proxmox node.
func (c *Client) GetNodeStatus(node string) (*NodeStatusData, error) {
	if node == "" {
		return nil, fmt.Errorf("node name cannot be empty")
	}

	// Safely encode node name in URL
	escapedNode := url.PathEscape(node)
	reqURL := fmt.Sprintf("%s/api2/json/nodes/%s/status", c.config.BaseURL, escapedNode)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add Authorization Header for Proxmox API Token
	// Format: PVEAPIToken=USER@REALM!TOKENID=SECRET
	headerVal := fmt.Sprintf("PVEAPIToken=%s=%s", c.config.TokenID, c.config.TokenValue)
	req.Header.Set("Authorization", headerVal)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	var response NodeStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %w", err)
	}

	return &response.Data, nil
}
