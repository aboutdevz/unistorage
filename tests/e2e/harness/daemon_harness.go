package harness

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// DaemonClient provides convenient, opaque-box HTTP client operations against the UniStorage loopback daemon.
type DaemonClient struct {
	BaseURL    string
	Bearer     string
	HTTPClient *http.Client
	t          *testing.T
}

// NewDaemonClient creates a new daemon client.
func (h *Harness) NewDaemonClient(token string) *DaemonClient {
	return &DaemonClient{
		BaseURL: "http://" + h.DaemonAddr,
		Bearer:  token,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		t: h.t,
	}
}

// Do sends an HTTP request with customized headers and returns the response.
func (c *DaemonClient) Do(req *http.Request) (*http.Response, error) {
	if c.Bearer != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	return c.HTTPClient.Do(req)
}

// Get sends an authenticated GET request.
func (c *DaemonClient) Get(endpoint string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// PostJSON sends an authenticated POST request with JSON payload.
func (c *DaemonClient) PostJSON(endpoint string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.Do(req)
}

// PutStream sends an authenticated PUT request streaming binary data.
func (c *DaemonClient) PutStream(endpoint string, r io.Reader, size int64) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPut, c.BaseURL+endpoint, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if size >= 0 {
		req.ContentLength = size
	}
	return c.Do(req)
}

// Delete sends an authenticated DELETE request.
func (c *DaemonClient) Delete(endpoint string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// TestHostHeader sends a request with an explicit Host header to test anti-DNS rebinding defenses.
func (c *DaemonClient) TestHostHeader(endpoint, host string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	return c.Do(req)
}

// TestCORSOrigin sends a request with an explicit Origin header to test CORS origin rejection.
func (c *DaemonClient) TestCORSOrigin(endpoint, origin string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", origin)
	return c.Do(req)
}
