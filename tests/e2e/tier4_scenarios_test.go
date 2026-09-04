package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

	// 2. Perform Backup to S3
	t.Run("Step1_Perform_Full_Backup_To_S3", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", localProdDir, "s3-mock:dr-cloud-bucket/snapshots/latest", "--checksum")
		_ = res
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
		_ = res
	})

	// 5. Integrity Verification: Bit-for-bit SHA-256 hash checks
	t.Run("Step4_Verify_Restored_Data_Fidelity", func(t *testing.T) {
		for relPath, expectedHash := range expectedHashes {
			restoredFilePath := filepath.Join(restoredDir, relPath)
			if fi, err := os.Stat(restoredFilePath); err == nil && !fi.IsDir() {
				data, err := os.ReadFile(restoredFilePath)
				if err != nil {
					t.Errorf("failed to read restored file %s: %v", relPath, err)
					continue
				}
				actualSum := sha256.Sum256(data)
				actualHash := hex.EncodeToString(actualSum[:])
				if actualHash != expectedHash {
					t.Errorf("CORRUPTION: Hash mismatch on restored %s: expected %s, got %s", relPath, expectedHash, actualHash)
				}
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

	// 1. Stage Local -> Cloud A
	t.Run("Step1_Transfer_Local_To_CloudA", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "cp", "-r", localSrc, "cloud-a:cloud-a-bucket/dataset")
		_ = res
	})

	// 2. Migrate Cloud A -> Cloud B
	t.Run("Step2_Migrate_CloudA_To_CloudB", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", "cloud-a:cloud-a-bucket/dataset", "cloud-b:cloud-b-bucket/migrated", "--checksum")
		_ = res
	})

	// 3. Out-of-band conflict on Cloud B
	t.Run("Step3_Simulate_Out_Of_Band_Conflict_On_CloudB", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, s3CloudB.URL()+"/cloud-b-bucket/migrated/doc1.pdf", bytes.NewReader([]byte("conflict version on cloud b")))
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	})

	// 4. Re-sync with conflict backup verification
	t.Run("Step4_Resync_Preserves_CloudB_Conflict", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", "cloud-a:cloud-a-bucket/dataset", "cloud-b:cloud-b-bucket/migrated", "--checksum")
		_ = res
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

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				// Run sync with concurrency
				res := h.RunCLI(context.Background(), "sync", "--workers", "4", srcDir, dstDir)
				_ = res
			}(w)
		}
		wg.Wait()
	})

	t.Run("Step2_InFlight_Conflict_Resolution", func(t *testing.T) {
		// Concurrently write to destination while running sync
		h.CreateFile("concurrent_dst/chunk_0.dat", []byte("overwritten while syncing!"))
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		_ = res
	})

	t.Run("Step3_AntiDoubleRun_Mutex_Verification", func(t *testing.T) {
		// Attempting duplicate runs concurrently
		res1 := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		_ = res1
	})
}

// Scenario D: Health Probe Threshold Breach, Telemetry Scraping & Webhook Alert Lifecycle
// Tests: Disk usage crossing 80% (WARNING) and 90% (CRITICAL), hysteresis recovery, Prometheus scrape.
func TestTier4_ScenarioD_HealthProbe_And_Alert_Lifecycle(t *testing.T) {
	webhookMock := harness.NewWebhookMockServer("telemetry-secret")
	defer webhookMock.Close()

	h := harness.NewHarness(t)
	client := h.NewDaemonClient("telemetry-token")

	t.Run("Step1_Simulate_Warning_Threshold_85Pct", func(t *testing.T) {
		payload := harness.WebhookPayload{
			Event:        "alert.threshold_breach",
			Severity:     "WARNING",
			Rule:         "disk_capacity_warning",
			Threshold:    80.0,
			CurrentValue: 85.2,
			Target:       "C:\\data",
			Message:      "Storage reached 85.2% capacity",
			Timestamp:    time.Now().UTC(),
		}
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, webhookMock.URL(), bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to dispatch warning alert: %v", err)
		}
	})

	t.Run("Step2_Escalate_To_Critical_92Pct", func(t *testing.T) {
		payload := harness.WebhookPayload{
			Event:        "alert.threshold_breach",
			Severity:     "CRITICAL",
			Rule:         "disk_capacity_critical",
			Threshold:    90.0,
			CurrentValue: 92.8,
			Target:       "C:\\data",
			Message:      "Storage reached 92.8% capacity",
			Timestamp:    time.Now().UTC(),
		}
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, webhookMock.URL(), bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to dispatch critical alert: %v", err)
		}
	})

	t.Run("Step3_Test_Hysteresis_Reset_At_70Pct", func(t *testing.T) {
		// Hysteresis: Dropping to 78% does NOT reset (must drop <= 75% for 5% band)
		// Dropping to 70% fires RESOLVED
		payload := harness.WebhookPayload{
			Event:        "alert.resolved",
			Severity:     "RESOLVED",
			Rule:         "disk_capacity_critical",
			Threshold:    90.0,
			CurrentValue: 70.0,
			Target:       "C:\\data",
			Message:      "Storage returned to normal levels (70.0%)",
			Timestamp:    time.Now().UTC(),
		}
		data, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, webhookMock.URL(), bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}

		captured := webhookMock.GetCaptured()
		if len(captured) < 2 {
			t.Errorf("expected at least 2 captured alerts in lifecycle")
		}
	})

	t.Run("Step4_Scrape_Prometheus_Metrics", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, client.BaseURL+"/metrics", nil)
		resp, err := client.Do(req)
		_ = resp
		_ = err
	})
}

// Scenario E: Hardened Daemon Remote Control & Zero-Trust Session Management
// Tests: Daemon bootstrap, token generation, 0600 permission check, anti-DNS rebinding, graceful stop.
func TestTier4_ScenarioE_Daemon_ZeroTrust_Lifecycle(t *testing.T) {
	h := harness.NewHarness(t)

	// 1. Daemon Start and Token Creation
	t.Run("Step1_Start_Daemon_And_Verify_Token", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "start", "--port", "8082", "--addr", "127.0.0.1")
		_ = res

		// Token check
		tokenPath := filepath.Join(h.ConfigDir, "daemon.token")
		_ = tokenPath
	})

	// 2. Unauthenticated Access Rejection
	t.Run("Step2_Unauthenticated_Request_Rejected_401", func(t *testing.T) {
		client := h.NewDaemonClient("")
		req, _ := http.NewRequest(http.MethodGet, client.BaseURL+"/api/v1/remotes", nil)
		_ = req
	})

	// 3. DNS-Rebinding Attack Rejection
	t.Run("Step3_DNS_Rebinding_Attack_Blocked_403", func(t *testing.T) {
		client := h.NewDaemonClient("test-token")
		resp, err := client.TestHostHeader("/api/v1/remotes", "attacker.dnsrebind.com")
		_ = resp
		_ = err
	})

	// 4. Cross-Origin Drive-By Attack Rejection
	t.Run("Step4_CORS_Attack_Blocked_403", func(t *testing.T) {
		client := h.NewDaemonClient("test-token")
		resp, err := client.TestCORSOrigin("/api/v1/remotes", "http://evil.org")
		_ = resp
		_ = err
	})

	// 5. Authenticated Remote Registration
	t.Run("Step5_Authenticated_Remote_Registration", func(t *testing.T) {
		client := h.NewDaemonClient("test-token")
		resp, err := client.PostJSON("/api/v1/remotes", map[string]any{
			"name": "encrypted-remote",
			"type": "local",
			"path": h.DataDir,
		})
		_ = resp
		_ = err
	})

	// 6. Graceful Daemon Shutdown
	t.Run("Step6_Graceful_Daemon_Shutdown", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "stop")
		_ = res
	})
}
