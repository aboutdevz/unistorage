package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/snapshot"
	"github.com/aboutdevz/unistorage/pkg/enterprise/telemetry"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
	"github.com/aboutdevz/unistorage/tests/e2e/harness"
)

// ==============================================================================
// Tier 4: Real-World Scenarios (End-to-End Operational Workflows)
// ==============================================================================

// Scenario A: Complete Disaster Recovery Backup and Full Cold Restore
// Tests: Primary local FS data loss, recovery from S3 snapshots, manifest hash validation.
func TestTier4_ScenarioA_DisasterRecovery_Backup_And_Restore(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("dr-cloud-bucket")

	h := harness.NewHarness(t)
	localProdDir := filepath.Join(h.RootDir, "prod_db")
	restoredDir := filepath.Join(h.RootDir, "restored_db")

	// 1. Generate multi-file dataset with various data types
	files := map[string][]byte{
		"users.dump":       []byte("TABLE users (id INT, name VARCHAR(255));\nINSERT INTO users VALUES (1, 'Alice');"),
		"orders.dump":      []byte("TABLE orders (id INT, total DECIMAL);\nINSERT INTO orders VALUES (101, 99.50);"),
		"config/app.json":  []byte(`{"app": "production", "version": "1.0"}`),
		"logs/empty.log":   {},
		"media/avatar.png": []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...image_binary_data..."),
	}

	expectedHashes := make(map[string]string)
	for relPath, content := range files {
		h.CreateFile(filepath.Join("prod_db", relPath), content)
		hSum := sha256.Sum256(content)
		expectedHashes[relPath] = hex.EncodeToString(hSum[:])
	}

	// Register s3-mock remote in encrypted vault before Step 1
	resRemote := h.RunCLI(context.Background(),
		"remote", "add", "s3-mock", "s3",
		"--endpoint", s3Mock.URL(),
		"--bucket", "dr-cloud-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
	)
	if resRemote.ExitCode != 0 {
		t.Fatalf("failed to register s3-mock remote: %s", resRemote.Stderr)
	}

	// 2. Perform Backup to S3
	t.Run("Step1_Perform_Full_Backup_To_S3", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", localProdDir, "s3-mock:dr-cloud-bucket/snapshots/latest", "--checksum")
		if res.ExitCode != 0 {
			t.Fatalf("backup sync failed (exit %d): %s", res.ExitCode, res.Stderr)
		}
	})

	// 3. Catastrophic Failure: Simulate complete disk failure
	t.Run("Step2_Simulate_Catastrophic_Local_Data_Loss", func(t *testing.T) {
		err := os.RemoveAll(localProdDir)
		if err != nil {
			t.Fatalf("failed to simulate disk wipe: %v", err)
		}
		if _, err := os.Stat(localProdDir); !os.IsNotExist(err) {
			t.Fatalf("expected production directory to be completely gone")
		}
	})

	// 4. Cold Restore from S3 Backup
	t.Run("Step3_Cold_Restore_From_S3", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", "s3-mock:dr-cloud-bucket/snapshots/latest", restoredDir, "--checksum")
		if res.ExitCode != 0 {
			t.Fatalf("restore sync failed (exit %d): %s", res.ExitCode, res.Stderr)
		}
	})

	// 5. Integrity Verification: Bit-for-bit SHA-256 hash checks
	t.Run("Step4_Verify_Restored_Data_Fidelity", func(t *testing.T) {
		for relPath, expectedHash := range expectedHashes {
			restoredFilePath := filepath.Join(restoredDir, relPath)
			fi, err := os.Stat(restoredFilePath)
			if err != nil {
				t.Fatalf("restored file missing: %s: %v", relPath, err)
			}
			if fi.IsDir() {
				t.Fatalf("expected restored item %s to be a file, got directory", relPath)
			}
			data, err := os.ReadFile(restoredFilePath)
			if err != nil {
				t.Fatalf("failed to read restored file %s: %v", relPath, err)
			}
			actualSum := sha256.Sum256(data)
			actualHash := hex.EncodeToString(actualSum[:])
			if actualHash != expectedHash {
				t.Errorf("CORRUPTION: Hash mismatch on restored %s: expected %s, got %s", relPath, expectedHash, actualHash)
			}
		}
	})
}

// Scenario B: Heterogeneous Multi-Remote Migration with Data Integrity
// Tests: Local FS -> S3 Cloud A -> S3 Cloud B, verifying checksums and conflict safety.
func TestTier4_ScenarioB_MultiRemote_Migration(t *testing.T) {
	s3CloudA := harness.NewS3MockServer()
	defer s3CloudA.Close()
	s3CloudA.CreateBucket("cloud-a-bucket")

	s3CloudB := harness.NewS3MockServer()
	defer s3CloudB.Close()
	s3CloudB.CreateBucket("cloud-b-bucket")

	h := harness.NewHarness(t)
	localSrc := filepath.Join(h.RootDir, "migration_src")

	h.CreateFile("migration_src/doc1.pdf", []byte("document 1 payload"))
	h.CreateFile("migration_src/large_archive.tar", make([]byte, 1024*1024)) // 1MB

	// Register cloud-a and cloud-b in encrypted vault
	resA := h.RunCLI(context.Background(),
		"remote", "add", "cloud-a", "s3",
		"--endpoint", s3CloudA.URL(),
		"--bucket", "cloud-a-bucket",
		"--access-key", "key-a",
		"--secret-key", "secret-a",
	)
	if resA.ExitCode != 0 {
		t.Fatalf("failed to register cloud-a: %s", resA.Stderr)
	}

	resB := h.RunCLI(context.Background(),
		"remote", "add", "cloud-b", "s3",
		"--endpoint", s3CloudB.URL(),
		"--bucket", "cloud-b-bucket",
		"--access-key", "key-b",
		"--secret-key", "secret-b",
	)
	if resB.ExitCode != 0 {
		t.Fatalf("failed to register cloud-b: %s", resB.Stderr)
	}

	// 1. Stage Local -> Cloud A
	t.Run("Step1_Transfer_Local_To_CloudA", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "cp", "-r", localSrc, "cloud-a:cloud-a-bucket/dataset")
		if res.ExitCode != 0 {
			t.Fatalf("cp to cloud-a failed (exit %d): %s", res.ExitCode, res.Stderr)
		}

		// Verify files exist on cloud-a
		resLs := h.RunCLI(context.Background(), "ls", "-r", "cloud-a:cloud-a-bucket/dataset")
		if resLs.ExitCode != 0 {
			t.Fatalf("ls failed on cloud-a: %s", resLs.Stderr)
		}
		if !strings.Contains(resLs.Stdout, "doc1.pdf") {
			t.Errorf("doc1.pdf missing on cloud-a: %s", resLs.Stdout)
		}
		if !strings.Contains(resLs.Stdout, "large_archive.tar") {
			t.Errorf("large_archive.tar missing on cloud-a: %s", resLs.Stdout)
		}
	})

	// 2. Migrate Cloud A -> Cloud B
	t.Run("Step2_Migrate_CloudA_To_CloudB", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", "cloud-a:cloud-a-bucket/dataset", "cloud-b:cloud-b-bucket/migrated", "--checksum")
		if res.ExitCode != 0 {
			t.Fatalf("sync cloud-a to cloud-b failed (exit %d): %s", res.ExitCode, res.Stderr)
		}

		// Verify files exist on cloud-b
		resLs := h.RunCLI(context.Background(), "ls", "-r", "cloud-b:cloud-b-bucket/migrated")
		if resLs.ExitCode != 0 {
			t.Fatalf("ls failed on cloud-b: %s", resLs.Stderr)
		}
		if !strings.Contains(resLs.Stdout, "doc1.pdf") {
			t.Errorf("doc1.pdf missing on cloud-b: %s", resLs.Stdout)
		}
		if !strings.Contains(resLs.Stdout, "large_archive.tar") {
			t.Errorf("large_archive.tar missing on cloud-b: %s", resLs.Stdout)
		}
	})

	// 3. Out-of-band conflict on Cloud B
	t.Run("Step3_Simulate_Out_Of_Band_Conflict_On_CloudB", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPut, s3CloudB.URL()+"/cloud-b-bucket/migrated/doc1.pdf", bytes.NewReader([]byte("conflict version on cloud b")))
		if err != nil {
			t.Fatalf("failed to create put request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to seed out-of-band conflict: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 from S3 put, got %d", resp.StatusCode)
		}
	})

	// 4. Re-sync with conflict backup verification
	t.Run("Step4_Resync_Preserves_CloudB_Conflict", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", "cloud-a:cloud-a-bucket/dataset", "cloud-b:cloud-b-bucket/migrated", "--checksum")
		if res.ExitCode != 0 {
			t.Fatalf("resync failed (exit %d): %s", res.ExitCode, res.Stderr)
		}

		// Verify .conflicts/ is preserved on cloud-b
		resLs := h.RunCLI(context.Background(), "ls", "-r", "cloud-b:cloud-b-bucket")
		if resLs.ExitCode != 0 {
			t.Fatalf("ls failed on cloud-b: %s", resLs.Stderr)
		}
		if !strings.Contains(resLs.Stdout, ".conflicts/migrated/doc1.pdf") {
			t.Errorf("expected .conflicts/migrated/doc1.pdf in cloud-b listing, got:\n%s", resLs.Stdout)
		}

		// Verify migrated/doc1.pdf now matches cloud-a content ("document 1 payload")
		resp, err := http.Get(s3CloudB.URL() + "/cloud-b-bucket/migrated/doc1.pdf")
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to fetch synced doc1.pdf from cloud-b: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		if string(body) != "document 1 payload" {
			t.Errorf("expected doc1.pdf to be updated to cloud-a version, got %q", string(body))
		}
	})
}

// Scenario C: Concurrent High-Throughput Sync with In-Flight Conflict Resolution
// Tests: 4 parallel workers, simultaneous modifications, anti-double-run mutex.
func TestTier4_ScenarioC_Concurrent_Sync_And_InFlight_Conflicts(t *testing.T) {
	h := harness.NewHarness(t)
	srcDir := filepath.Join(h.RootDir, "concurrent_src")
	dstDir := filepath.Join(h.RootDir, "concurrent_dst")

	// Seed 20 files
	for i := 0; i < 20; i++ {
		h.CreateFile(fmt.Sprintf("concurrent_src/chunk_%d.dat", i), []byte(fmt.Sprintf("data payload %d", i)))
	}

	t.Run("Step1_Concurrent_Workers_Sync", func(t *testing.T) {
		var wg sync.WaitGroup
		workers := 4
		results := make([]*harness.CLIResult, workers)

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				// Run sync with concurrency
				results[workerID] = h.RunCLI(context.Background(), "sync", "--workers", "4", srcDir, dstDir)
			}(w)
		}
		wg.Wait()

		for w := 0; w < workers; w++ {
			if results[w].ExitCode != 0 {
				t.Fatalf("worker %d sync failed (exit %d): %s", w, results[w].ExitCode, results[w].Stderr)
			}
		}

		// Verify all 20 chunk files exist in destination
		for i := 0; i < 20; i++ {
			rel := filepath.Join("concurrent_dst", fmt.Sprintf("chunk_%d.dat", i))
			if !h.FileExists(rel) {
				t.Fatalf("chunk file %s missing in destination", rel)
			}
			expectedContent := fmt.Sprintf("data payload %d", i)
			data := h.ReadFile(rel)
			if string(data) != expectedContent {
				t.Errorf("chunk %d content mismatch: expected %q, got %q", i, expectedContent, string(data))
			}
		}
	})

	t.Run("Step2_InFlight_Conflict_Resolution", func(t *testing.T) {
		// Overwrite chunk_0.dat in destination
		h.CreateFile("concurrent_dst/chunk_0.dat", []byte("overwritten while syncing!"))
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("sync with conflict failed (exit %d): %s", res.ExitCode, res.Stderr)
		}

		// Verify chunk_0.dat restored to source content
		chunk0Rel := filepath.Join("concurrent_dst", "chunk_0.dat")
		if string(h.ReadFile(chunk0Rel)) != "data payload 0" {
			t.Errorf("chunk_0.dat not restored to source content")
		}

		// Verify .conflicts directory contains conflict backup file
		conflictFiles, err := filepath.Glob(filepath.Join(dstDir, ".conflicts", "chunk_0.dat*"))
		if err != nil || len(conflictFiles) == 0 {
			t.Fatalf("expected conflict backup in .conflicts/chunk_0.dat*, got: %v", conflictFiles)
		}
		conflictData, err := os.ReadFile(conflictFiles[0])
		if err != nil || string(conflictData) != "overwritten while syncing!" {
			t.Errorf("conflict backup content mismatch: expected overwritten content, got %q", string(conflictData))
		}
	})

	t.Run("Step3_AntiDoubleRun_Mutex_Verification", func(t *testing.T) {
		drv, err := local.New(dstDir)
		if err != nil {
			t.Fatalf("failed to create local driver: %v", err)
		}
		ctx := context.Background()

		// Acquire first lock
		lock1, err := snapshot.AcquireStorageLock(ctx, drv, "", 60)
		if err != nil {
			t.Fatalf("failed to acquire primary lock: %v", err)
		}

		// Second concurrent attempt on the same storage location must fail with ErrJobAlreadyRunning
		_, err2 := snapshot.AcquireStorageLock(ctx, drv, "", 60)
		if err2 == nil || !errors.Is(err2, snapshot.ErrJobAlreadyRunning) {
			t.Errorf("expected ErrJobAlreadyRunning on second lock acquisition, got: %v", err2)
		}

		// Release first lock
		if err := lock1.Release(ctx); err != nil {
			t.Fatalf("failed to release lock: %v", err)
		}

		// Third acquisition should now succeed
		lock3, err3 := snapshot.AcquireStorageLock(ctx, drv, "", 60)
		if err3 != nil {
			t.Fatalf("expected lock acquisition after release to succeed, got: %v", err3)
		}
		_ = lock3.Release(ctx)
	})
}

// Scenario D: Health Probe Threshold Breach, Telemetry Scraping & Webhook Alert Lifecycle
// Tests: Disk usage crossing 80% (WARNING) and 90% (CRITICAL), hysteresis recovery, Prometheus scrape.
func TestTier4_ScenarioD_HealthProbe_And_Alert_Lifecycle(t *testing.T) {
	webhookMock := harness.NewWebhookMockServer("telemetry-secret")
	defer webhookMock.Close()

	metrics := telemetry.NewMetricsRegistry()
	dispatcher := telemetry.NewWebhookDispatcher(webhookMock.URL(), "telemetry-secret", metrics)
	dispatcher.SetCooldown(0)

	t.Run("Step1_Simulate_Warning_Threshold_85Pct", func(t *testing.T) {
		usage := &telemetry.DiskUsage{
			Path:        "C:\\data",
			TotalBytes:  1000,
			FreeBytes:   148,
			UsedBytes:   852,
			UsedPercent: 85.2,
		}
		metrics.SetDiskMetrics(usage)

		alert := dispatcher.EvaluateDisk(usage)
		if alert == nil {
			t.Fatalf("expected alert payload for 85.2%% usage")
		}
		if alert.Severity != telemetry.SeverityWarning {
			t.Errorf("expected WARNING severity, got %s", alert.Severity)
		}
		err := dispatcher.Dispatch(context.Background(), alert)
		if err != nil {
			t.Fatalf("failed to dispatch warning alert: %v", err)
		}
		captured := webhookMock.GetCaptured()
		if len(captured) != 1 {
			t.Fatalf("expected 1 captured alert, got %d", len(captured))
		}
		if !webhookMock.VerifyHMAC(captured[0]) {
			t.Errorf("HMAC signature verification failed on warning alert")
		}
		if captured[0].Payload.Severity != "WARNING" {
			t.Errorf("expected WARNING severity in captured payload, got %s", captured[0].Payload.Severity)
		}
	})

	t.Run("Step2_Escalate_To_Critical_92Pct", func(t *testing.T) {
		usage := &telemetry.DiskUsage{
			Path:        "C:\\data",
			TotalBytes:  1000,
			FreeBytes:   72,
			UsedBytes:   928,
			UsedPercent: 92.8,
		}
		metrics.SetDiskMetrics(usage)

		alert := dispatcher.EvaluateDisk(usage)
		if alert == nil {
			t.Fatalf("expected alert payload for 92.8%% usage")
		}
		if alert.Severity != telemetry.SeverityCritical {
			t.Errorf("expected CRITICAL severity, got %s", alert.Severity)
		}
		err := dispatcher.Dispatch(context.Background(), alert)
		if err != nil {
			t.Fatalf("failed to dispatch critical alert: %v", err)
		}
		captured := webhookMock.GetCaptured()
		if len(captured) != 2 {
			t.Fatalf("expected 2 captured alerts, got %d", len(captured))
		}
		if !webhookMock.VerifyHMAC(captured[1]) {
			t.Errorf("HMAC signature verification failed on critical alert")
		}
		if captured[1].Payload.Severity != "CRITICAL" {
			t.Errorf("expected CRITICAL severity in captured payload, got %s", captured[1].Payload.Severity)
		}
	})

	t.Run("Step3_Test_Hysteresis_Reset_At_70Pct", func(t *testing.T) {
		// Hysteresis: Dropping to 78% does NOT reset (must drop <= 75% for 5% band below 80%)
		usage78 := &telemetry.DiskUsage{
			Path:        "C:\\data",
			TotalBytes:  1000,
			FreeBytes:   220,
			UsedBytes:   780,
			UsedPercent: 78.0,
		}
		alert78 := dispatcher.EvaluateDisk(usage78)
		if alert78 != nil && alert78.Severity == telemetry.SeverityResolved {
			t.Errorf("expected 78.0%% NOT to trigger RESOLVED due to 5%% hysteresis band")
		}

		// Dropping to 70% fires RESOLVED
		usage70 := &telemetry.DiskUsage{
			Path:        "C:\\data",
			TotalBytes:  1000,
			FreeBytes:   300,
			UsedBytes:   700,
			UsedPercent: 70.0,
		}
		metrics.SetDiskMetrics(usage70)

		alert70 := dispatcher.EvaluateDisk(usage70)
		if alert70 == nil {
			t.Fatalf("expected alert payload for 70.0%% usage recovery")
		}
		if alert70.Severity != telemetry.SeverityResolved {
			t.Errorf("expected RESOLVED severity, got %s", alert70.Severity)
		}
		err := dispatcher.Dispatch(context.Background(), alert70)
		if err != nil {
			t.Fatalf("failed to dispatch resolved alert: %v", err)
		}

		captured := webhookMock.GetCaptured()
		if len(captured) != 3 {
			t.Fatalf("expected 3 captured alerts in lifecycle, got %d", len(captured))
		}
		if !webhookMock.VerifyHMAC(captured[2]) {
			t.Errorf("HMAC signature verification failed on resolved alert")
		}
		if captured[2].Payload.Severity != "RESOLVED" {
			t.Errorf("expected RESOLVED severity in captured payload, got %s", captured[2].Payload.Severity)
		}
	})

	t.Run("Step4_Scrape_Prometheus_Metrics", func(t *testing.T) {
		server := httptest.NewServer(metrics.Handler())
		defer server.Close()

		req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
		if err != nil {
			t.Fatalf("failed to create scrape request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("failed to scrape /metrics: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200 from /metrics, got %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read /metrics response: %v", err)
		}
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "unistorage_disk_used_percent") {
			t.Errorf("expected unistorage_disk_used_percent in metrics exposition, got:\n%s", bodyStr)
		}
		if !strings.Contains(bodyStr, "unistorage_alerts_dispatched_total") {
			t.Errorf("expected unistorage_alerts_dispatched_total in metrics exposition, got:\n%s", bodyStr)
		}
	})
}

// Scenario E: Hardened Daemon Remote Control & Zero-Trust Session Management
// Tests: Daemon bootstrap, token generation, 0600 permission check, anti-DNS rebinding, graceful stop.
func TestTier4_ScenarioE_Daemon_ZeroTrust_Lifecycle(t *testing.T) {
	h := harness.NewHarness(t)

	var token string

	// 1. Daemon Start and Token Creation
	t.Run("Step1_Start_Daemon_And_Verify_Token", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "start", "--port", "8082", "--addr", "127.0.0.1")
		if res.ExitCode != 0 {
			t.Fatalf("daemon start failed (exit %d): %s", res.ExitCode, res.Stderr)
		}

		h.DaemonAddr = "127.0.0.1:8082"

		// Token check: poll for up to 3s
		deadline := time.Now().Add(3 * time.Second)
		var err error
		for time.Now().Before(deadline) {
			token, err = h.GetToken()
			if err == nil && len(token) >= 32 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if len(token) < 32 {
			t.Fatalf("daemon token file was not created or too short: %q (err: %v)", token, err)
		}
		if !h.VerifyTokenPermissions() {
			t.Errorf("expected daemon.token to have 0600 permissions")
		}
	})

	defer func() {
		_ = h.RunCLI(context.Background(), "daemon", "stop")
	}()

	// 2. Unauthenticated Access Rejection
	t.Run("Step2_Unauthenticated_Request_Rejected_401", func(t *testing.T) {
		client := h.NewDaemonClient("")
		req, err := http.NewRequest(http.MethodGet, client.BaseURL+"/api/v1/remotes", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("unauthenticated request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected HTTP 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	// 3. DNS-Rebinding Attack Rejection
	t.Run("Step3_DNS_Rebinding_Attack_Blocked_403", func(t *testing.T) {
		client := h.NewDaemonClient(token)
		resp, err := client.TestHostHeader("/api/v1/remotes", "attacker.dnsrebind.com")
		if err != nil {
			// Denial at transport layer is also safe
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected HTTP 403 Forbidden for DNS-rebinding host, got %d", resp.StatusCode)
		}
	})

	// 4. Cross-Origin Drive-By Attack Rejection
	t.Run("Step4_CORS_Attack_Blocked_403", func(t *testing.T) {
		client := h.NewDaemonClient(token)
		resp, err := client.TestCORSOrigin("/api/v1/remotes", "http://evil.org")
		if err != nil {
			t.Fatalf("CORS request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected HTTP 403 Forbidden for unauthorized Origin, got %d", resp.StatusCode)
		}
	})

	// 5. Authenticated Remote Registration
	t.Run("Step5_Authenticated_Remote_Registration", func(t *testing.T) {
		client := h.NewDaemonClient(token)
		resp, err := client.PostJSON("/api/v1/remotes", map[string]any{
			"name": "encrypted-remote",
			"type": "local",
			"path": h.DataDir,
		})
		if err != nil {
			t.Fatalf("remote registration failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 201/200 from remote registration, got %d", resp.StatusCode)
		}

		// Verify vault file is created on disk and does not contain plaintext
		vaultPath := filepath.Join(h.ConfigDir, "vault.enc")
		vaultData, err := os.ReadFile(vaultPath)
		if err != nil {
			t.Fatalf("vault file %s was not created or unreadable: %v", vaultPath, err)
		}
		if bytes.Contains(vaultData, []byte(h.DataDir)) {
			t.Errorf("SECURITY ALERT: plaintext path leaked in vault file: %s", h.DataDir)
		}
	})

	// 6. Graceful Daemon Shutdown
	t.Run("Step6_Graceful_Daemon_Shutdown", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "stop")
		if res.ExitCode != 0 {
			t.Fatalf("daemon stop failed (exit %d): %s", res.ExitCode, res.Stderr)
		}
	})
}
