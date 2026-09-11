package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/user/auth-cli-system/internal/api/handlers"
)

// APIClient manages HTTP communication with the backend auth server
type APIClient struct {
	baseURL      string
	httpClient   *http.Client
	sessionToken string
}

// NewAPIClient creates an API client pointing to the backend server
func NewAPIClient(baseURL string) *APIClient {
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	return &APIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SetSessionToken sets the active session token
func (c *APIClient) SetSessionToken(token string) {
	c.sessionToken = token
}

// ClearSessionToken clears the active session token
func (c *APIClient) ClearSessionToken() {
	c.sessionToken = ""
}

// HasSession returns whether a session token is set
func (c *APIClient) HasSession() bool {
	return c.sessionToken != ""
}

// APIError represents an error returned by the backend API
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

func (c *APIClient) doRequest(method, endpoint string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequest(method, c.baseURL+endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.sessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.sessionToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to connect to authentication server at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if jsonErr := json.Unmarshal(respBytes, &errResp); jsonErr == nil && errResp.Error != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: errResp.Error}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBytes))}
	}

	if result != nil {
		if err := json.Unmarshal(respBytes, result); err != nil {
			return fmt.Errorf("failed to parse response JSON: %w", err)
		}
	}

	return nil
}

// Register calls POST /api/v1/auth/register
func (c *APIClient) Register(username, password string) error {
	req := handlers.RegisterRequest{
		Username: username,
		Password: password,
	}
	return c.doRequest(http.MethodPost, "/api/v1/auth/register", req, nil)
}

// LoginResultDTO holds the login response data
type LoginResultDTO struct {
	Status      string               `json:"status"`
	Message     string               `json:"message"`
	Token       string               `json:"token"`
	TOTPEnabled bool                 `json:"totp_enabled"`
	User        handlers.UserSummary `json:"user"`
}

// Login calls POST /api/v1/auth/login
func (c *APIClient) Login(username, password, totpCode string) (*LoginResultDTO, error) {
	req := handlers.LoginRequest{
		Username: username,
		Password: password,
		TOTPCode: totpCode,
	}
	var res LoginResultDTO
	if err := c.doRequest(http.MethodPost, "/api/v1/auth/login", req, &res); err != nil {
		return nil, err
	}
	if res.Status == "success" && res.Token != "" {
		c.SetSessionToken(res.Token)
	}
	return &res, nil
}

// Logout calls POST /api/v1/auth/logout
func (c *APIClient) Logout() error {
	if !c.HasSession() {
		return errors.New("no active session to log out")
	}
	err := c.doRequest(http.MethodPost, "/api/v1/auth/logout", nil, nil)
	c.ClearSessionToken()
	return err
}

// WhoAmI calls GET /api/v1/user/me
func (c *APIClient) WhoAmI() (*handlers.UserSummary, error) {
	var summary handlers.UserSummary
	if err := c.doRequest(http.MethodGet, "/api/v1/user/me", nil, &summary); err != nil {
		return nil, err
	}
	return &summary, nil
}

// MFAGenerateResponse holds the generated 2FA secret and setup URI
type MFAGenerateResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// GenerateMFA calls POST /api/v1/mfa/generate
func (c *APIClient) GenerateMFA() (*MFAGenerateResponse, error) {
	var res MFAGenerateResponse
	if err := c.doRequest(http.MethodPost, "/api/v1/mfa/generate", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// EnableMFA calls POST /api/v1/mfa/enable
func (c *APIClient) EnableMFA(code string) error {
	req := handlers.EnableMFARequest{Code: code}
	return c.doRequest(http.MethodPost, "/api/v1/mfa/enable", req, nil)
}

// DisableMFA calls POST /api/v1/mfa/disable
func (c *APIClient) DisableMFA() error {
	return c.doRequest(http.MethodPost, "/api/v1/mfa/disable", nil, nil)
}
