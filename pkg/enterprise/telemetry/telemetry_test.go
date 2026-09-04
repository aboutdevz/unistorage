package telemetry_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/telemetry"
	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

func TestGetDiskUsage(t *testing.T) {
	currDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}

	usage, err := telemetry.GetDiskUsage(currDir)
	if err != nil {
		t.Fatalf("GetDiskUsage failed: %v", err)
	}

	if usage.TotalBytes == 0 {
		t.Fatalf("expected TotalBytes > 0, got 0")
	}
	if usage.FreeBytes > usage.TotalBytes {
		t.Fatalf("FreeBytes (%d) cannot exceed TotalBytes (%d)", usage.FreeBytes, usage.TotalBytes)
	}
	if usage.UsedPercent < 0.0 || usage.UsedPercent > 100.0 {
		t.Fatalf("UsedPercent (%f) out of range [0, 100]", usage.UsedPercent)
	}
}

type failingDriver struct {
	failCount int
	calls     int
}

func (f *failingDriver) Name() string                                              { return "failing" }
func (f *failingDriver) Read(ctx context.Context, path string) (io.ReadCloser, error) { return nil, errors.New("io error") }
func (f *failingDriver) Write(ctx context.Context, path string, r io.Reader, size int64) error { return errors.New("io error") }
func (f *failingDriver) List(ctx context.Context, prefix string) ([]storage.ObjectInfo, error) {
	f.calls++
	if f.calls <= f.failCount {
		return nil, errors.New("backend timeout")
	}
	return []storage.ObjectInfo{}, nil
}
func (f *failingDriver) Delete(ctx context.Context, path string) error             { return nil }
func (f *failingDriver) Stat(ctx context.Context, path string) (*storage.ObjectInfo, error) { return nil, nil }
func (f *failingDriver) Stream(ctx context.Context, path string, w io.Writer) error { return nil }

func TestS3Probe(t *testing.T) {
	probe := telemetry.NewS3Probe(2 * time.Second)
	ctx := context.Background()

	// 1. Successful probe using local driver
	tempDir, _ := os.MkdirTemp("", "probe-test-*")
	defer os.RemoveAll(tempDir)
	localDrv, _ := local.New(tempDir)

	res := probe.Probe(ctx, localDrv, "s3-mock", "test-bucket")
	if !res.Up {
		t.Fatalf("expected probe to be up, got down with err: %v", res.Error)
	}
	if res.LatencySeconds < 0 {
		t.Fatalf("expected non-negative latency, got %f", res.LatencySeconds)
	}
	if res.ConsecutiveFailures != 0 {
		t.Fatalf("expected 0 consecutive failures, got %d", res.ConsecutiveFailures)
	}

	// 2. Failing probe tracking consecutive failures
	failDrv := &failingDriver{failCount: 3}

	res1 := probe.Probe(ctx, failDrv, "s3-failing", "bucket")
	if res1.Up || res1.ConsecutiveFailures != 1 {
		t.Fatalf("expected failure 1, got up=%v count=%d", res1.Up, res1.ConsecutiveFailures)
	}

	res2 := probe.Probe(ctx, failDrv, "s3-failing", "bucket")
	if res2.Up || res2.ConsecutiveFailures != 2 {
		t.Fatalf("expected failure 2, got up=%v count=%d", res2.Up, res2.ConsecutiveFailures)
	}

	res3 := probe.Probe(ctx, failDrv, "s3-failing", "bucket")
	if res3.Up || res3.ConsecutiveFailures != 3 {
		t.Fatalf("expected failure 3, got up=%v count=%d", res3.Up, res3.ConsecutiveFailures)
	}

	// 4th probe succeeds (failCount was 3)
	res4 := probe.Probe(ctx, failDrv, "s3-failing", "bucket")
	if !res4.Up || res4.ConsecutiveFailures != 0 {
		t.Fatalf("expected recovery, got up=%v count=%d", res4.Up, res4.ConsecutiveFailures)
	}
}

func TestMetricsRegistryAndExposition(t *testing.T) {
	reg := telemetry.NewMetricsRegistry()

	reg.SetDiskMetrics(&telemetry.DiskUsage{
		Path:        "/data",
		TotalBytes:  1000000000,
		FreeBytes:   200000000,
		UsedPercent: 80.0,
	})

	reg.SetS3ProbeMetrics(telemetry.ProbeResult{
		Remote:         "aws-s3",
		Bucket:         "production-backups",
		Up:             true,
		LatencySeconds: 0.042,
	})

	reg.IncTransfers("upload", "success", 10)
	reg.AddTransferBytes("upload", 5242880)
	reg.IncBackupRuns("daily-postgres", "success", 1)
	reg.IncBackupSkippedOverlap("daily-postgres")
	reg.IncRetentionPruned("daily-postgres", 2)
	reg.IncAlertsDispatched("WARNING", "/data")

	output := reg.Format()

	// Verify all expected metrics are present in Prometheus text format
	expectedSubstrings := []string{
		"unistorage_disk_total_bytes{path=\"/data\"} 1000000000",
		"unistorage_disk_free_bytes{path=\"/data\"} 200000000",
		"unistorage_disk_used_percent{path=\"/data\"} 80",
		"unistorage_s3_up{bucket=\"production-backups\",remote=\"aws-s3\"} 1",
		"unistorage_s3_latency_seconds{bucket=\"production-backups\",remote=\"aws-s3\"} 0.042",
		"unistorage_transfers_total{direction=\"upload\",status=\"success\"} 10",
		"unistorage_transfer_bytes_total{direction=\"upload\"} 5242880",
		"unistorage_backup_runs_total{job=\"daily-postgres\",status=\"success\"} 1",
		"unistorage_backup_skipped_overlap_total{job=\"daily-postgres\"} 1",
		"unistorage_retention_pruned_total{job=\"daily-postgres\"} 2",
		"unistorage_alerts_dispatched_total{severity=\"WARNING\",target=\"/data\"} 1",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(output, sub) {
			t.Errorf("missing expected metric line: %s\nFull output:\n%s", sub, output)
		}
	}

	// Verify HTTP Handler
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 from /metrics, got %d", rec.Code)
	}
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Fatalf("expected text/plain Content-Type, got %s", contentType)
	}
}

func TestWebhookDispatcher_DiskThresholdsAndHysteresis(t *testing.T) {
	dispatcher := telemetry.NewWebhookDispatcher("http://mock-url", "secret-key", nil)
	dispatcher.SetCooldown(1 * time.Second)

	// 1. 79% used: Below WARNING (80%), no alert
	p := dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: "/data", UsedPercent: 79.0})
	if p != nil {
		t.Fatalf("expected no alert at 79%%, got %v", p)
	}

	// 2. 82% used: Crosses WARNING (>80%)
	p = dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: "/data", UsedPercent: 82.0})
	if p == nil || p.Severity != telemetry.SeverityWarning {
		t.Fatalf("expected WARNING alert at 82%%, got %v", p)
	}

	// 3. 88% used: Above 80% but still in WARNING, no escalation yet
	p = dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: "/data", UsedPercent: 88.0})
	if p != nil {
		t.Fatalf("expected cooldown suppression for same severity WARNING, got %v", p)
	}

	// 4. 92% used: Crosses CRITICAL (>90%), escalation bypasses cooldown!
	p = dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: "/data", UsedPercent: 92.0})
	if p == nil || p.Severity != telemetry.SeverityCritical {
		t.Fatalf("expected CRITICAL escalation alert at 92%%, got %v", p)
	}

	// 5. Drops to 86%: Inside 5% hysteresis band of CRITICAL (90 - 5 = 85%), remains CRITICAL, no alert
	p = dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: "/data", UsedPercent: 86.0})
	if p != nil {
		t.Fatalf("expected no de-escalation inside hysteresis band (86%%), got %v", p)
	}

	// 6. Drops to 74%: Drops below 75% (80 - 5 = 75%), fires RESOLVED alert!
	p = dispatcher.EvaluateDisk(&telemetry.DiskUsage{Path: "/data", UsedPercent: 74.0})
	if p == nil || p.Severity != telemetry.SeverityResolved {
		t.Fatalf("expected RESOLVED alert when dropping below 75%%, got %v", p)
	}
}

func TestWebhookDispatcher_S3ProbeRules(t *testing.T) {
	dispatcher := telemetry.NewWebhookDispatcher("http://mock-url", "secret-key", nil)

	// 1st & 2nd failures: No alert
	if p := dispatcher.EvaluateS3(telemetry.ProbeResult{Remote: "s3", Bucket: "b", Up: false, ConsecutiveFailures: 1}); p != nil {
		t.Fatalf("expected no alert on 1st failure")
	}
	if p := dispatcher.EvaluateS3(telemetry.ProbeResult{Remote: "s3", Bucket: "b", Up: false, ConsecutiveFailures: 2}); p != nil {
		t.Fatalf("expected no alert on 2nd failure")
	}

	// 3rd failure: CRITICAL alert
	p := dispatcher.EvaluateS3(telemetry.ProbeResult{Remote: "s3", Bucket: "b", Up: false, ConsecutiveFailures: 3})
	if p == nil || p.Severity != telemetry.SeverityCritical {
		t.Fatalf("expected CRITICAL alert on 3rd failure, got %v", p)
	}

	// Recovery: RESOLVED alert
	p = dispatcher.EvaluateS3(telemetry.ProbeResult{Remote: "s3", Bucket: "b", Up: true, ConsecutiveFailures: 0, LatencySeconds: 0.05})
	if p == nil || p.Severity != telemetry.SeverityResolved {
		t.Fatalf("expected RESOLVED alert upon recovery, got %v", p)
	}
}

func TestWebhookDispatcher_DeliveryWithHMACAndRetry(t *testing.T) {
	secretKey := "my-shared-webhook-secret-12345"
	var attempts int32
	var receivedSig string
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		att := atomic.AddInt32(&attempts, 1)
		receivedSig = r.Header.Get("X-UniStorage-Signature")
		receivedBody, _ = io.ReadAll(r.Body)

		// First attempt fails with 500, second succeeds with 200
		if att == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"temporary glitch"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer server.Close()

	metrics := telemetry.NewMetricsRegistry()
	dispatcher := telemetry.NewWebhookDispatcher(server.URL, secretKey, metrics)

	payload := &telemetry.AlertPayload{
		Event:        "alert.threshold_breach",
		AlertID:      "alert-test-1",
		Severity:     telemetry.SeverityCritical,
		Rule:         "disk_critical",
		Threshold:    90.0,
		CurrentValue: 94.5,
		Target:       "/data",
		Message:      "Volume critical",
		Timestamp:    time.Now().UTC(),
	}

	ctx := context.Background()
	err := dispatcher.Dispatch(ctx, payload)
	if err != nil {
		t.Fatalf("expected Dispatch to succeed after retry, got error: %v", err)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("expected 2 attempts due to retry, got %d", attempts)
	}

	// Validate HMAC signature on received body
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(receivedBody)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if receivedSig != expectedSig {
		t.Fatalf("HMAC mismatch! Expected %s, got %s", expectedSig, receivedSig)
	}

	// Validate JSON body
	var parsed telemetry.AlertPayload
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("failed parsing received JSON: %v", err)
	}
	if parsed.AlertID != "alert-test-1" {
		t.Fatalf("expected AlertID alert-test-1, got %s", parsed.AlertID)
	}
}

func TestWebhookDispatcher_ClientErrorNoRetry(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest) // 400 Client Error
	}))
	defer server.Close()

	dispatcher := telemetry.NewWebhookDispatcher(server.URL, "secret", nil)
	payload := &telemetry.AlertPayload{
		AlertID:  "alert-400",
		Severity: telemetry.SeverityWarning,
	}

	err := dispatcher.Dispatch(context.Background(), payload)
	if err == nil {
		t.Fatalf("expected error on HTTP 400, got nil")
	}
	// Should not retry on 4xx
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected exactly 1 attempt on HTTP 400, got %d", attempts)
	}
}
