package harness

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// WebhookPayload represents the structured alert payload sent by UniStorage telemetry.
type WebhookPayload struct {
	Event        string         `json:"event"`
	AlertID      string         `json:"alert_id"`
	Severity     string         `json:"severity"`
	Rule         string         `json:"rule"`
	Threshold    float64        `json:"threshold"`
	CurrentValue float64        `json:"current_value"`
	Unit         string         `json:"unit"`
	Target       string         `json:"target"`
	Message      string         `json:"message"`
	Timestamp    time.Time      `json:"timestamp"`
	Details      map[string]any `json:"details"`
}

// CapturedWebhook holds a received alert payload along with raw headers and HMAC signature.
type CapturedWebhook struct {
	Payload   WebhookPayload
	RawBody   []byte
	Signature string
	Received  time.Time
}

// WebhookMockServer captures incoming webhook alerts for assertion.
type WebhookMockServer struct {
	server   *httptest.Server
	secret   string
	mu       sync.Mutex
	captured []CapturedWebhook
}

// NewWebhookMockServer creates a new mock webhook receiver.
func NewWebhookMockServer(secret string) *WebhookMockServer {
	w := &WebhookMockServer{
		secret:   secret,
		captured: make([]CapturedWebhook, 0),
	}
	w.server = httptest.NewServer(http.HandlerFunc(w.handler))
	return w
}

// URL returns the mock webhook endpoint URL.
func (w *WebhookMockServer) URL() string {
	return w.server.URL
}

// Close shuts down the mock receiver.
func (w *WebhookMockServer) Close() {
	w.server.Close()
}

// GetCaptured returns a copy of all captured webhooks.
func (w *WebhookMockServer) GetCaptured() []CapturedWebhook {
	w.mu.Lock()
	defer w.mu.Unlock()
	res := make([]CapturedWebhook, len(w.captured))
	copy(res, w.captured)
	return res
}

// Clear removes previously captured webhooks.
func (w *WebhookMockServer) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.captured = make([]CapturedWebhook, 0)
}

// VerifyHMAC validates the X-UniStorage-Signature header against the raw request body.
func (w *WebhookMockServer) VerifyHMAC(cw CapturedWebhook) bool {
	if w.secret == "" {
		return true
	}
	sigHeader := cw.Signature
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	expectedHex := strings.TrimPrefix(sigHeader, "sha256=")

	mac := hmac.New(sha256.New, []byte(w.secret))
	mac.Write(cw.RawBody)
	actualHex := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedHex), []byte(actualHex))
}

func (w *WebhookMockServer) handler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	cw := CapturedWebhook{
		Payload:   payload,
		RawBody:   body,
		Signature: r.Header.Get("X-UniStorage-Signature"),
		Received:  time.Now(),
	}

	w.mu.Lock()
	w.captured = append(w.captured, cw)
	w.mu.Unlock()

	rw.WriteHeader(http.StatusOK)
}
