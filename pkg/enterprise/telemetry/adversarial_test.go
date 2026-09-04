package telemetry_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/telemetry"
)

// 1. Stress-test Disk Usage Syscalls: host volumes, empty/invalid paths, zero-div resilience
func TestAdversarial_DiskUsageSyscalls(t *testing.T) {
	// A. Host volume accuracy (C:\ on Windows, / on Unix)
	targetPath := "C:\\"
	usage, err := telemetry.GetDiskUsage(targetPath)
	if err != nil {
		// Fallback to relative if C:\ is not available (e.g. Unix CI environment)
		targetPath = "."
		usage, err = telemetry.GetDiskUsage(targetPath)
		if err != nil {
			t.Fatalf("GetDiskUsage failed on valid path: %v", err)
		}
	}

	if usage.TotalBytes == 0 {
		t.Fatalf("expected TotalBytes > 0 on host volume, got 0")
	}
	if usage.FreeBytes > usage.TotalBytes {
		t.Fatalf("FreeBytes (%d) cannot exceed TotalBytes (%d)", usage.FreeBytes, usage.TotalBytes)
	}
	if usage.UsedBytes > usage.TotalBytes {
		t.Fatalf("UsedBytes (%d) cannot exceed TotalBytes (%d)", usage.UsedBytes, usage.TotalBytes)
	}
	if usage.UsedPercent < 0.0 || usage.UsedPercent > 100.0 {
		t.Fatalf("UsedPercent (%.2f) out of range [0, 100]", usage.UsedPercent)
	}

	// B. Empty path must default to current directory without panic
	emptyUsage, err := telemetry.GetDiskUsage("")
	if err != nil {
		t.Fatalf("GetDiskUsage(\"\") failed: %v", err)
	}
	if emptyUsage.TotalBytes == 0 {
		t.Fatalf("expected empty path to resolve to current dir with TotalBytes > 0")
	}

	// C. Invalid and non-existent paths must return an error without panicking
	for _, badPath := range []string{
		"Z:\\nonexistent_storage_drive_98765",
		"\\\\invalid-network-unc\\share",
		"badpath\x00with_null_byte",
	} {
		_, err := telemetry.GetDiskUsage(badPath)
		if err == nil {
			t.Errorf("expected error for invalid path %q, got nil", badPath)
		}
	}

	// D. Zero-division defense in metrics calculation:
	// If a synthetic volume has TotalBytes == 0, UsedPercent must be 0.0 and never panic or produce NaN.
	syntheticZeroUsage := &telemetry.DiskUsage{
		Path:        "/virtual/zero",
		TotalBytes:  0,
		FreeBytes:   0,
		AvailBytes:  0,
		UsedBytes:   0,
		UsedPercent: 0.0,
	}
	reg := telemetry.NewMetricsRegistry()
	reg.SetDiskMetrics(syntheticZeroUsage)
	exposition := reg.Format()
	if !strings.Contains(exposition, "unistorage_disk_used_percent{path=\"/virtual/zero\"} 0") {
		t.Fatalf("expected UsedPercent 0 for zero capacity volume, got:\n%s", exposition)
	}
}

// 2. Stress-test Webhook alert flapping & 5% hysteresis band
// Oscillation scenario: 79.9% -> 80.1% -> 79.9% -> 77.0% -> 75.1% -> 75.0% -> 74.0%
func TestAdversarial_WebhookFlappingAndHysteresis(t *testing.T) {
	dispatcher := telemetry.NewWebhookDispatcher("http://mock-webhook", "secret-key", nil)
	// Long cooldown so cooldown doesn't interfere with hysteresis test
	dispatcher.SetCooldown(1 * time.Hour)

	vol := "/data/volume1"

	// Step 1: 79.9% -> Below WARNING (80.0%), initial state OK -> NO ALERT
	p1 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 79.9})
	if p1 != nil {
		t.Fatalf("Step 1 failed: expected no alert at 79.9%%, got severity=%s", p1.Severity)
	}

	// Step 2: 80.1% -> Crosses 80.0% -> WARNING alert EMITTED
	p2 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 80.1})
	if p2 == nil || p2.Severity != telemetry.SeverityWarning {
		t.Fatalf("Step 2 failed: expected WARNING alert at 80.1%%, got %v", p2)
	}
	if p2.Threshold != 80.0 {
		t.Fatalf("Step 2 failed: expected threshold 80.0, got %f", p2.Threshold)
	}

	// Step 3: 79.9% -> Oscillates back below 80.0%, but inside 5% hysteresis band (80.0 - 5.0 = 75.0%)
	// MUST NOT emit RESOLVED or WARNING (anti-flapping suppression)
	p3 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 79.9})
	if p3 != nil {
		t.Fatalf("Step 3 failed: expected suppression in hysteresis band at 79.9%%, got %v", p3)
	}

	// Step 4: 77.0% -> Drops further, but still strictly above 75.0% -> NO ALERT
	p4 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 77.0})
	if p4 != nil {
		t.Fatalf("Step 4 failed: expected suppression in hysteresis band at 77.0%%, got %v", p4)
	}

	// Step 5: 75.1% -> Still strictly above 75.0% -> NO ALERT
	p5 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 75.1})
	if p5 != nil {
		t.Fatalf("Step 5 failed: expected suppression in hysteresis band at 75.1%%, got %v", p5)
	}

	// Step 6: 75.0% -> Drops to <= 75.0% (exit of hysteresis band) -> RESOLVED alert EMITTED!
	p6 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 75.0})
	if p6 == nil || p6.Severity != telemetry.SeverityResolved {
		t.Fatalf("Step 6 failed: expected RESOLVED alert at 75.0%%, got %v", p6)
	}
	if p6.Threshold != 75.0 {
		t.Fatalf("Step 6 failed: expected resolved threshold 75.0, got %f", p6.Threshold)
	}

	// Step 7: 74.0% -> Further drop below 75.0% while already in OK state -> NO DUPLICATE ALERT
	p7 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 74.0})
	if p7 != nil {
		t.Fatalf("Step 7 failed: expected no duplicate alert in OK state at 74.0%%, got %v", p7)
	}
}

// 3. Stress-test Alert Cooldown & Immediate Escalation
func TestAdversarial_AlertCooldownAndEscalation(t *testing.T) {
	dispatcher := telemetry.NewWebhookDispatcher("http://mock-webhook", "secret-key", nil)
	// Default cooldown is 15 minutes
	if dispatcher == nil {
		t.Fatalf("dispatcher creation failed")
	}

	vol := "/data/volume2"

	// 1. Initial breach to 80.5% -> Emits WARNING
	w1 := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 80.5})
	if w1 == nil || w1.Severity != telemetry.SeverityWarning {
		t.Fatalf("expected initial WARNING at 80.5%%, got %v", w1)
	}

	// 2. Repeated WARNINGs within cooldown window (e.g. 81.0%, 85.0%, 88.0%) -> Suppressed
	for _, pct := range []float64{81.0, 85.0, 88.0, 89.9} {
		suppressed := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: pct})
		if suppressed != nil {
			t.Fatalf("expected suppression during 15-minute cooldown at %.1f%%, got %v", pct, suppressed)
		}
	}

	// 3. Immediate escalation to CRITICAL (90.1%) -> Bypasses 15m cooldown!
	crit := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 90.1})
	if crit == nil || crit.Severity != telemetry.SeverityCritical {
		t.Fatalf("expected immediate CRITICAL escalation bypassing cooldown at 90.1%%, got %v", crit)
	}
	if crit.Threshold != 90.0 {
		t.Fatalf("expected CRITICAL threshold 90.0, got %f", crit.Threshold)
	}

	// 4. Repeated CRITICALs within cooldown (e.g. 91.0%, 94.0%) -> Suppressed
	for _, pct := range []float64{91.0, 94.0, 95.5} {
		suppressed := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: pct})
		if suppressed != nil {
			t.Fatalf("expected suppression of repeated CRITICAL at %.1f%%, got %v", pct, suppressed)
		}
	}

	// 5. Verify cooldown expiration allows re-dispatch:
	// Set small cooldown for test validation
	dispatcher.SetCooldown(30 * time.Millisecond)
	time.Sleep(40 * time.Millisecond)

	// Now a repeated CRITICAL alert should be dispatched after cooldown expires
	critAfterCooldown := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: vol, UsedPercent: 95.5})
	if critAfterCooldown == nil || critAfterCooldown.Severity != telemetry.SeverityCritical {
		t.Fatalf("expected alert dispatch after cooldown elapsed, got %v", critAfterCooldown)
	}
}

// 4. Stress-test HMAC-SHA256 signature tampering & secret mismatch
func TestAdversarial_HMACSignatureTampering(t *testing.T) {
	correctSecret := "top-secret-signing-key-9988"
	wrongSecret := "wrong-secret-key-1122"

	// Mock webhook receiver validating HMAC
	receiverWithSecret := func(expectedSecret string) (*httptest.Server, *int) {
		validCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			sigHeader := r.Header.Get("X-UniStorage-Signature")
			if !strings.HasPrefix(sigHeader, "sha256=") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"missing sha256 prefix"}`))
				return
			}

			providedHex := strings.TrimPrefix(sigHeader, "sha256=")
			expectedHex := telemetry.ComputeSignature(expectedSecret, body)

			if !hmac.Equal([]byte(providedHex), []byte(expectedHex)) {
				w.WriteHeader(http.StatusUnauthorized) // 401 Unauthorized
				_, _ = w.Write([]byte(`{"error":"hmac signature mismatch"}`))
				return
			}

			validCount++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		return server, &validCount
	}

	// Test A: Legitimate delivery succeeds
	srvA, countA := receiverWithSecret(correctSecret)
	defer srvA.Close()

	dispatcherValid := telemetry.NewWebhookDispatcher(srvA.URL, correctSecret, nil)
	payload := &telemetry.AlertPayload{
		AlertID:   "alert-legit-1",
		Severity:  telemetry.SeverityWarning,
		Message:   "Valid test alert",
		Timestamp: time.Now().UTC(),
	}

	err := dispatcherValid.Dispatch(context.Background(), payload)
	if err != nil {
		t.Fatalf("expected legitimate dispatch to succeed, got: %v", err)
	}
	if *countA != 1 {
		t.Fatalf("expected 1 valid dispatch, got %d", *countA)
	}

	// Test B: Secret key mismatch (sender uses wrongSecret) -> receiver rejects with HTTP 401 (client error, no retry)
	srvB, countB := receiverWithSecret(correctSecret)
	defer srvB.Close()

	dispatcherWrongSecret := telemetry.NewWebhookDispatcher(srvB.URL, wrongSecret, nil)
	err = dispatcherWrongSecret.Dispatch(context.Background(), payload)
	if err == nil {
		t.Fatalf("expected dispatch with wrong secret to fail, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected HTTP 401 in error message, got: %v", err)
	}
	if *countB != 0 {
		t.Fatalf("expected 0 valid dispatches with mismatched secret, got %d", *countB)
	}

	// Test C: Tampered bytes in transit (altering 1 byte of payload JSON)
	srvC, _ := receiverWithSecret(correctSecret)
	defer srvC.Close()

	tamperedClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// Tamper body bytes while leaving original signature header
			originalBody, _ := io.ReadAll(req.Body)
			tamperedBody := bytes.Replace(originalBody, []byte("alert-legit-1"), []byte("alert-forged-9"), 1)
			req.Body = io.NopCloser(bytes.NewReader(tamperedBody))
			req.ContentLength = int64(len(tamperedBody))
			return http.DefaultTransport.RoundTrip(req)
		}),
	}

	dispatcherTampered := telemetry.NewWebhookDispatcher(srvC.URL, correctSecret, nil)
	dispatcherTampered.SetHTTPClient(tamperedClient)

	err = dispatcherTampered.Dispatch(context.Background(), payload)
	if err == nil {
		t.Fatalf("expected tampered payload to be rejected by receiver, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected HTTP 401 rejection for tampered payload, got: %v", err)
	}
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// 5. Stress-test Prometheus Exposition Format
func TestAdversarial_PrometheusExpositionFormat(t *testing.T) {
	reg := telemetry.NewMetricsRegistry()

	// Populate standard and edge-case metrics
	reg.SetDiskMetrics(&telemetry.DiskUsage{
		Path:        "C:\\Storage\\Data Space",
		TotalBytes:  500123456789,
		FreeBytes:   100987654321,
		UsedPercent: 79.807,
	})

	reg.SetS3ProbeMetrics(telemetry.ProbeResult{
		Remote:         "remote-backup-01",
		Bucket:         "bucket-\"quoted\"\\escaped",
		Up:             true,
		LatencySeconds: 0.123456,
	})

	reg.IncTransfers("upload", "success", 12345)
	reg.AddTransferBytes("upload", 9876543210)
	reg.IncBackupRuns("hourly-db", "success", 42)
	reg.IncBackupSkippedOverlap("hourly-db")
	reg.IncRetentionPruned("hourly-db", 7)
	reg.IncAlertsDispatched("CRITICAL", "C:\\Storage\\Data Space")

	// Custom metric with special characters in labels
	reg.SetGauge("unistorage_custom_metric", 42.5, map[string]string{
		"node":        "worker-01",
		"special":     "val-with-\"quotes\"-and-\\backslashes\nand-newline",
	})

	rawOutput := reg.Format()

	// Validation 1: Parse every line adhering to Prometheus text format spec
	lines := strings.Split(strings.TrimRight(rawOutput, "\n"), "\n")
	if len(lines) == 0 {
		t.Fatalf("empty metrics output")
	}

	helpSeen := make(map[string]bool)
	typeSeen := make(map[string]string)
	metricLineRegex := regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([+-]?(?:[0-9]*[.])?[0-9]+(?:[eE][+-]?[0-9]+)?)$`)

	for lineIdx, line := range lines {
		if strings.HasPrefix(line, "# HELP ") {
			parts := strings.SplitN(strings.TrimPrefix(line, "# HELP "), " ", 2)
			metricName := parts[0]
			if helpSeen[metricName] {
				t.Fatalf("line %d: duplicate # HELP declaration for metric %s", lineIdx+1, metricName)
			}
			helpSeen[metricName] = true
		} else if strings.HasPrefix(line, "# TYPE ") {
			parts := strings.SplitN(strings.TrimPrefix(line, "# TYPE "), " ", 2)
			metricName := parts[0]
			mtype := parts[1]
			if typeSeen[metricName] != "" {
				t.Fatalf("line %d: duplicate # TYPE declaration for metric %s", lineIdx+1, metricName)
			}
			if mtype != "gauge" && mtype != "counter" {
				t.Fatalf("line %d: unsupported metric type %s", lineIdx+1, mtype)
			}
			typeSeen[metricName] = mtype
		} else {
			// Sample line: metric_name{labels} value
			matches := metricLineRegex.FindStringSubmatch(line)
			if len(matches) < 4 {
				t.Fatalf("line %d: invalid Prometheus sample line syntax: %q", lineIdx+1, line)
			}
			metricName := matches[1]
			valStr := matches[3]

			// Metric must have been declared with TYPE
			if typeSeen[metricName] == "" {
				t.Fatalf("line %d: metric %s encountered without prior # TYPE declaration", lineIdx+1, metricName)
			}

			// Value must be valid float64
			if _, err := strconv.ParseFloat(valStr, 64); err != nil {
				t.Fatalf("line %d: invalid numeric float value %q: %v", lineIdx+1, valStr, err)
			}
		}
	}

	// Validation 2: Verify HTTP /metrics endpoint returns HTTP 200 with standard content type
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from /metrics, got %d", rec.Code)
	}
	expectedCT := "text/plain; version=0.0.4; charset=utf-8"
	if rec.Header().Get("Content-Type") != expectedCT {
		t.Fatalf("expected Content-Type %q, got %q", expectedCT, rec.Header().Get("Content-Type"))
	}
}
