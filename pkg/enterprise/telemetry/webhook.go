package telemetry

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	SeverityWarning  = "WARNING"
	SeverityCritical = "CRITICAL"
	SeverityResolved = "RESOLVED"
	SeverityOK       = "OK"

	DefaultCooldown = 15 * time.Minute
)

// AlertPayload defines the structured JSON body sent to the webhook receiver.
type AlertPayload struct {
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
	Details      map[string]any `json:"details,omitempty"`
}

type targetState struct {
	severity               string
	lastDispatchedAt       time.Time
	lastDispatchedSeverity string
}

// WebhookDispatcher manages alert rules, hysteresis bands, cooldowns, and HMAC signed HTTP delivery.
type WebhookDispatcher struct {
	mu           sync.Mutex
	webhookURL   string
	secretKey    string
	httpClient   *http.Client
	cooldown     time.Duration
	retryBackoff time.Duration
	states       map[string]*targetState
	metrics      *MetricsRegistry
}

// NewWebhookDispatcher constructs a webhook dispatcher.
func NewWebhookDispatcher(webhookURL, secretKey string, metrics *MetricsRegistry) *WebhookDispatcher {
	return &WebhookDispatcher{
		webhookURL:   webhookURL,
		secretKey:    secretKey,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		cooldown:     DefaultCooldown,
		retryBackoff: 50 * time.Millisecond,
		states:       make(map[string]*targetState),
		metrics:      metrics,
	}
}

// SetCooldown overrides the cooldown duration (helpful for tests).
func (w *WebhookDispatcher) SetCooldown(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cooldown = d
}

// SetHTTPClient overrides the default HTTP client.
func (w *WebhookDispatcher) SetHTTPClient(client *http.Client) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.httpClient = client
}

// EvaluateDisk evaluates disk usage against WARNING (>80%) and CRITICAL (>90%) thresholds with 5% hysteresis.
func (w *WebhookDispatcher) EvaluateDisk(usage *DiskUsage) *AlertPayload {
	if usage == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	targetKey := "disk:" + usage.Path
	state := w.states[targetKey]
	if state == nil {
		state = &targetState{severity: SeverityOK}
		w.states[targetKey] = state
	}

	now := time.Now().UTC()
	pct := usage.UsedPercent

	var newSeverity string
	var rule string
	var threshold float64

	switch state.severity {
	case SeverityOK:
		if pct > 90.0 {
			newSeverity = SeverityCritical
			rule = "disk_capacity_critical"
			threshold = 90.0
		} else if pct > 80.0 {
			newSeverity = SeverityWarning
			rule = "disk_capacity_warning"
			threshold = 80.0
		}
	case SeverityWarning:
		if pct > 90.0 {
			// Severity escalation: warning -> critical
			newSeverity = SeverityCritical
			rule = "disk_capacity_critical"
			threshold = 90.0
		} else if pct <= 75.0 {
			// 5% hysteresis band below 80% (80 - 5 = 75)
			newSeverity = SeverityResolved
			rule = "disk_capacity_resolved"
			threshold = 75.0
		} else {
			newSeverity = SeverityWarning
			rule = "disk_capacity_warning"
			threshold = 80.0
		}
	case SeverityCritical:
		if pct <= 75.0 {
			newSeverity = SeverityResolved
			rule = "disk_capacity_resolved"
			threshold = 75.0
		} else if pct <= 85.0 {
			// 5% hysteresis band below 90% (90 - 5 = 85)
			newSeverity = SeverityWarning
			rule = "disk_capacity_warning"
			threshold = 80.0
		} else {
			newSeverity = SeverityCritical
			rule = "disk_capacity_critical"
			threshold = 90.0
		}
	}

	if newSeverity == "" {
		return nil
	}

	// Determine if cooldown or escalation applies
	shouldSend := false
	if newSeverity == SeverityResolved {
		shouldSend = true
		state.severity = SeverityOK
	} else if isEscalation(state.lastDispatchedSeverity, newSeverity) {
		shouldSend = true
		state.severity = newSeverity
	} else if now.Sub(state.lastDispatchedAt) >= w.cooldown {
		shouldSend = true
		state.severity = newSeverity
	}

	if !shouldSend {
		return nil
	}

	state.lastDispatchedAt = now
	state.lastDispatchedSeverity = newSeverity

	alertID := fmt.Sprintf("alert-disk-%s-%s", strings.ToLower(newSeverity), sanitizeTarget(usage.Path))
	msg := fmt.Sprintf("Storage volume %s has reached %.1f%% capacity", usage.Path, pct)
	if newSeverity == SeverityResolved {
		msg = fmt.Sprintf("Storage volume %s capacity has returned to normal (%.1f%%)", usage.Path, pct)
	}

	return &AlertPayload{
		Event:        "alert.threshold_breach",
		AlertID:      alertID,
		Severity:     newSeverity,
		Rule:         rule,
		Threshold:    threshold,
		CurrentValue: pct,
		Unit:         "percent",
		Target:       usage.Path,
		Message:      msg,
		Timestamp:    now,
		Details: map[string]any{
			"total_bytes": usage.TotalBytes,
			"free_bytes":  usage.FreeBytes,
			"used_bytes":  usage.UsedBytes,
		},
	}
}

// EvaluateS3 evaluates an S3 probe result for reachability failures (>= 3 consecutive downs).
func (w *WebhookDispatcher) EvaluateS3(res ProbeResult) *AlertPayload {
	w.mu.Lock()
	defer w.mu.Unlock()

	targetKey := "s3:" + res.Remote + "/" + res.Bucket
	state := w.states[targetKey]
	if state == nil {
		state = &targetState{severity: SeverityOK}
		w.states[targetKey] = state
	}

	now := time.Now().UTC()
	targetName := res.Remote + ":" + res.Bucket

	if !res.Up && res.ConsecutiveFailures >= 3 {
		if state.severity != SeverityCritical || now.Sub(state.lastDispatchedAt) >= w.cooldown {
			state.severity = SeverityCritical
			state.lastDispatchedAt = now
			state.lastDispatchedSeverity = SeverityCritical

			errStr := ""
			if res.Error != nil {
				errStr = res.Error.Error()
			}

			return &AlertPayload{
				Event:        "alert.threshold_breach",
				AlertID:      fmt.Sprintf("alert-s3-critical-%s", sanitizeTarget(targetName)),
				Severity:     SeverityCritical,
				Rule:         "s3_probe_consecutive_failures",
				Threshold:    3.0,
				CurrentValue: float64(res.ConsecutiveFailures),
				Unit:         "failures",
				Target:       targetName,
				Message:      fmt.Sprintf("S3 backend %s is DOWN for %d consecutive probes", targetName, res.ConsecutiveFailures),
				Timestamp:    now,
				Details: map[string]any{
					"latency_seconds":      res.LatencySeconds,
					"consecutive_failures": res.ConsecutiveFailures,
					"error":                errStr,
				},
			}
		}
	} else if res.Up && state.severity == SeverityCritical {
		state.severity = SeverityOK
		state.lastDispatchedAt = now
		state.lastDispatchedSeverity = SeverityResolved

		return &AlertPayload{
			Event:        "alert.resolved",
			AlertID:      fmt.Sprintf("alert-s3-resolved-%s", sanitizeTarget(targetName)),
			Severity:     SeverityResolved,
			Rule:         "s3_probe_resolved",
			Threshold:    0.0,
			CurrentValue: 0.0,
			Unit:         "failures",
			Target:       targetName,
			Message:      fmt.Sprintf("S3 backend %s connectivity has been restored (latency %.3fs)", targetName, res.LatencySeconds),
			Timestamp:    now,
			Details: map[string]any{
				"latency_seconds": res.LatencySeconds,
			},
		}
	}

	return nil
}

func isEscalation(oldSev, newSev string) bool {
	if oldSev == "" || oldSev == SeverityOK {
		return true
	}
	if oldSev == SeverityWarning && newSev == SeverityCritical {
		return true
	}
	return false
}

func sanitizeTarget(t string) string {
	t = strings.ReplaceAll(t, "\\", "-")
	t = strings.ReplaceAll(t, "/", "-")
	t = strings.ReplaceAll(t, ":", "-")
	return strings.ToLower(strings.Trim(t, "-"))
}

// ComputeSignature calculates the HMAC-SHA256 hex digest of the payload.
func ComputeSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Dispatch sends the alert JSON payload to the webhook endpoint with HMAC signature and retries.
func (w *WebhookDispatcher) Dispatch(ctx context.Context, payload *AlertPayload) error {
	if payload == nil {
		return nil
	}
	if w.webhookURL == "" {
		return fmt.Errorf("no webhook URL configured")
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert payload: %w", err)
	}

	sigHex := ComputeSignature(w.secretKey, bodyBytes)
	sigHeader := "sha256=" + sigHex

	var lastErr error
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.webhookURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("failed to construct alert request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-UniStorage-Signature", sigHeader)

		resp, err := w.httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// Successful delivery
				if w.metrics != nil {
					w.metrics.IncAlertsDispatched(payload.Severity, payload.Target)
				}
				return nil
			}

			// 4xx errors are client errors, do not retry
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return fmt.Errorf("webhook endpoint returned client error HTTP %d", resp.StatusCode)
			}

			lastErr = fmt.Errorf("webhook endpoint returned HTTP %d", resp.StatusCode)
		}

		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * w.retryBackoff):
			}
		}
	}

	return fmt.Errorf("alert dispatch failed after %d attempts: %w", maxRetries, lastErr)
}
