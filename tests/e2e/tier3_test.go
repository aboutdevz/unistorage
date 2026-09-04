package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aboutdevz/unistorage/internal/daemon"
	"github.com/aboutdevz/unistorage/pkg/enterprise/snapshot"
	"github.com/aboutdevz/unistorage/pkg/enterprise/telemetry"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
	"github.com/aboutdevz/unistorage/pkg/storage/s3"
	"github.com/aboutdevz/unistorage/tests/e2e/harness"
)

// ==============================================================================
// Tier 3: Cross-Feature Combinations (Pairwise Integration Tests)
// ==============================================================================

// TestTier3_LocalToS3Sync_WithConflicts tests pairwise interaction between
// Local FS Driver, S3 Driver, Sync Engine, and Conflict Backups.
func TestTier3_LocalToS3Sync_WithConflicts(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("sync-conflict-bucket")

	h := harness.NewHarness(t)
	localSrc := filepath.Join(h.RootDir, "local_src")

	h.CreateFile("local_src/contract.pdf", []byte("local contract version 1"))
	h.CreateFile("local_src/readme.md", []byte("local readme"))

	// Pre-populate S3 destination with conflicting file
	req, _ := http.NewRequest(http.MethodPut, s3Mock.URL()+"/sync-conflict-bucket/contract.pdf", bytes.NewReader([]byte("remote conflict version 2")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to seed S3 conflict file: %v", err)
	}
	resp.Body.Close()

	// 1. Register s3-mock remote in encrypted vault
	resRemote := h.RunCLI(context.Background(),
		"remote", "add", "s3-mock", "s3",
		"--endpoint", s3Mock.URL(),
		"--bucket", "sync-conflict-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
	)
	if resRemote.ExitCode != 0 {
		t.Fatalf("failed to register s3-mock remote: %s", resRemote.Stderr)
	}

	t.Run("Pairwise_Sync_Detects_Remote_Conflict", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", localSrc, "s3-mock:sync-conflict-bucket")
		if res.ExitCode != 0 {
			t.Fatalf("sync failed (exit %d): %s", res.ExitCode, res.Stderr)
		}
		if !strings.Contains(res.Stdout, "Conflicts:    1 files moved") {
			t.Errorf("expected 1 conflict reported in sync output, got:\n%s", res.Stdout)
		}
	})

	t.Run("Pairwise_Conflict_Moved_To_Conflicts_Dir", func(t *testing.T) {
		// Verify .conflicts/ preservation on S3 remote
		resLs := h.RunCLI(context.Background(), "ls", "-r", "s3-mock:sync-conflict-bucket")
		if resLs.ExitCode != 0 {
			t.Fatalf("ls failed on s3 remote: %s", resLs.Stderr)
		}
		if !strings.Contains(resLs.Stdout, ".conflicts/contract.pdf") {
			t.Errorf("expected .conflicts/contract.pdf in remote listing, got:\n%s", resLs.Stdout)
		}

		// Verify remote contract.pdf was updated with local version
		getResp, err := http.Get(s3Mock.URL() + "/sync-conflict-bucket/contract.pdf")
		if err != nil || getResp.StatusCode != http.StatusOK {
			t.Fatalf("failed to read updated file from S3: %v", err)
		}
		body, _ := io.ReadAll(getResp.Body)
		getResp.Body.Close()
		if string(body) != "local contract version 1" {
			t.Errorf("expected S3 contract.pdf to be updated to local version, got: %s", string(body))
		}
	})
}

// TestTier3_DaemonProxying_To_S3 tests pairwise interaction between
// Loopback HTTP Daemon, Bearer Auth, and S3 Storage Driver.
func TestTier3_DaemonProxying_To_S3(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("daemon-s3-bucket")

	h := harness.NewHarness(t)

	// Bind ephemeral loopback port and start real in-process daemon
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind loopback listener: %v", err)
	}
	defer ln.Close()

	d, err := daemon.New(daemon.Config{
		Addr:      ln.Addr().String(),
		TokenFile: filepath.Join(h.ConfigDir, "daemon.token"),
	})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	// Register S3 driver pointing to s3Mock
	s3Drv, err := s3.New(context.Background(), s3.Config{
		Endpoint:     s3Mock.URL(),
		Bucket:       "daemon-s3-bucket",
		AccessKey:    "test-key",
		SecretKey:    "test-secret",
		UsePathStyle: true,
	})
	if err != nil {
		t.Fatalf("failed to initialize s3 driver: %v", err)
	}
	d.RegisterDriver("s3-mock", s3Drv)

	srv := &http.Server{Handler: d.Handler()}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	h.DaemonAddr = ln.Addr().String()
	client := h.NewDaemonClient(d.Token())

	payload := []byte("binary stream sent via daemon proxy to s3")

	t.Run("Pairwise_Daemon_Upload_Proxies_To_S3", func(t *testing.T) {
		resp, err := client.PutStream("/api/v1/storage/s3-mock/objects/stream.bin", bytes.NewReader(payload), int64(len(payload)))
		if err != nil {
			t.Fatalf("PutStream failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200 from daemon PutStream, got %d", resp.StatusCode)
		}
	})

	t.Run("Pairwise_Daemon_Download_Proxies_From_S3", func(t *testing.T) {
		resp, err := client.Get("/api/v1/storage/s3-mock/objects/stream.bin")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 from daemon Get, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !bytes.Equal(body, payload) {
			t.Errorf("data mismatch: expected %q, got %q", string(payload), string(body))
		}
	})

	t.Run("Pairwise_Daemon_Stat_Proxies_To_S3", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodHead, client.BaseURL+"/api/v1/storage/s3-mock/objects/stream.bin", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Head request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200 from daemon Head, got %d", resp.StatusCode)
		}
		expectedLen := fmt.Sprintf("%d", len(payload))
		if resp.Header.Get("Content-Length") != expectedLen {
			t.Errorf("expected Content-Length %s, got %s", expectedLen, resp.Header.Get("Content-Length"))
		}
	})
}

// TestTier3_VaultCredentials_UsedBySync tests pairwise interaction between
// Encrypted Secret Vault (Argon2id + AES-GCM), CLI Remote management, and Sync Engine.
func TestTier3_VaultCredentials_UsedBySync(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("production-backups")

	h := harness.NewHarness(t)
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	t.Run("Pairwise_Vault_Stores_Remote_Profile", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "remote", "add", "prod-s3", "s3",
			"--endpoint", s3Mock.URL(),
			"--bucket", "production-backups",
			"--access-key", "AKIAIOSFODNN7EXAMPLE",
			"--secret-key", secretKey,
		)
		if res.ExitCode != 0 {
			t.Fatalf("remote add failed (exit %d): %s", res.ExitCode, res.Stderr)
		}

		// Verify remote is listed
		resList := h.RunCLI(context.Background(), "remote", "list", "--json")
		if resList.ExitCode != 0 || !strings.Contains(resList.Stdout, "prod-s3") {
			t.Errorf("prod-s3 missing from remote list: %s", resList.Stdout)
		}
	})

	t.Run("Pairwise_Sync_Loads_Credentials_From_Vault", func(t *testing.T) {
		srcDir := filepath.Join(h.RootDir, "data_to_sync")
		h.CreateFile("data_to_sync/file.txt", []byte("payload"))

		res := h.RunCLI(context.Background(), "sync", srcDir, "prod-s3:daily")
		if res.ExitCode != 0 {
			t.Fatalf("sync with vault remote failed (exit %d): %s", res.ExitCode, res.Stderr)
		}

		// Verify file reached S3 mock
		resp, err := http.Get(s3Mock.URL() + "/production-backups/daily/file.txt")
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to fetch synced file from S3: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "payload" {
			t.Errorf("expected 'payload', got %s", string(body))
		}
	})

	t.Run("Pairwise_Vault_ZeroPlaintext_On_Disk", func(t *testing.T) {
		vaultPath := filepath.Join(h.ConfigDir, "vault.enc")
		if !h.FileExists(".unistorage/vault.enc") {
			t.Fatalf("vault file missing on disk: %s", vaultPath)
		}
		raw := h.ReadFile(".unistorage/vault.enc")
		if bytes.Contains(raw, []byte(secretKey)) {
			t.Errorf("SECURITY ALERT: Plaintext secret key found in vault file on disk!")
		}
	})
}

// TestTier3_SnapshotRetentionPruning_AcrossMultipleSyncs tests pairwise interaction between
// Sync Engine, Snapshot Manifests, and Retention Pruner.
func TestTier3_SnapshotRetentionPruning_AcrossMultipleSyncs(t *testing.T) {
	h := harness.NewHarness(t)
	destRoot := filepath.Join(h.RootDir, "snapshots_dest")
	retentionLimit := 3

	// Create 5 synthetic snapshot directory trees with manifests
	for i := 1; i <= 5; i++ {
		snapDir := fmt.Sprintf("snapshots_dest/snapshots/2026-09-04T0%d-00-00Z", i)
		h.CreateFile(filepath.Join(snapDir, "data.bin"), []byte(fmt.Sprintf("snapshot %d", i)))

		manifest := map[string]any{
			"manifest_version": "1.0",
			"snapshot_id":      fmt.Sprintf("snap-%d", i),
			"timestamp":        fmt.Sprintf("2026-09-04T0%d:00:00Z", i),
			"stats": map[string]any{
				"total_files": 1,
				"status":      "SUCCESS",
			},
		}
		data, _ := json.Marshal(manifest)
		h.CreateFile(filepath.Join(snapDir, "manifest.json"), data)
	}

	drv, err := local.New(destRoot)
	if err != nil {
		t.Fatalf("failed to instantiate local driver: %v", err)
	}
	pruner := snapshot.NewPruner(drv)

	var pruneRes *snapshot.PruneResult
	t.Run("Pairwise_Pruner_Identifies_Excess_Snapshots", func(t *testing.T) {
		res, err := pruner.Prune(context.Background(), "", retentionLimit)
		if err != nil {
			t.Fatalf("pruner failed: %v", err)
		}
		pruneRes = res

		if pruneRes.TotalSnapshots != 5 {
			t.Errorf("expected 5 total snapshots, got %d", pruneRes.TotalSnapshots)
		}
		if pruneRes.ValidSnapshots != 5 {
			t.Errorf("expected 5 valid snapshots, got %d", pruneRes.ValidSnapshots)
		}
		if pruneRes.PrunedSnapshots != 2 {
			t.Errorf("expected 2 pruned snapshots, got %d", pruneRes.PrunedSnapshots)
		}
	})

	t.Run("Pairwise_Pruner_Preserves_Newest_N", func(t *testing.T) {
		// Snapshots 1 and 2 must be purged
		for i := 1; i <= 2; i++ {
			snapDir := fmt.Sprintf("snapshots_dest/snapshots/2026-09-04T0%d-00-00Z", i)
			if h.FileExists(filepath.Join(snapDir, "data.bin")) {
				t.Errorf("snapshot %d should have been deleted by pruner", i)
			}
		}
		// Snapshots 3, 4, 5 must remain intact
		for i := 3; i <= 5; i++ {
			snapDir := fmt.Sprintf("snapshots_dest/snapshots/2026-09-04T0%d-00-00Z", i)
			if !h.FileExists(filepath.Join(snapDir, "data.bin")) {
				t.Errorf("snapshot %d should be preserved by pruner", i)
			}
		}
	})
}

// TestTier3_JobMutex_Prevents_Overlapping_Syncs tests pairwise interaction between
// Anti-Double-Run Mutex, Snapshot Scheduler, and File Transfers.
func TestTier3_JobMutex_Prevents_Overlapping_Syncs(t *testing.T) {
	h := harness.NewHarness(t)
	jobID := "daily-db-backup"
	ctx := context.Background()

	drv, err := local.New(h.RootDir)
	if err != nil {
		t.Fatalf("failed to create driver: %v", err)
	}

	t.Run("Pairwise_Mutex_Lock_File_Created", func(t *testing.T) {
		lock, err := snapshot.AcquireStorageLock(ctx, drv, "", 60)
		if err != nil {
			t.Fatalf("failed to acquire initial storage lock: %v", err)
		}
		defer lock.Release(ctx)

		lockFilePath := filepath.Join(h.RootDir, ".job.lock")
		if !h.FileExists(".job.lock") {
			t.Fatalf(".job.lock file missing on disk at %s", lockFilePath)
		}
	})

	t.Run("Pairwise_Second_Execution_Skipped", func(t *testing.T) {
		// Acquire first lock
		lock1, err := snapshot.AcquireStorageLock(ctx, drv, "", 60)
		if err != nil {
			t.Fatalf("failed to acquire primary lock: %v", err)
		}

		// Second concurrent attempt must fail with ErrJobAlreadyRunning
		_, err2 := snapshot.AcquireStorageLock(ctx, drv, "", 60)
		if err2 == nil || !errors.Is(err2, snapshot.ErrJobAlreadyRunning) {
			t.Errorf("expected ErrJobAlreadyRunning, got %v", err2)
		}

		// Release first lock
		if err := lock1.Release(ctx); err != nil {
			t.Fatalf("failed to release lock: %v", err)
		}

		// Third acquisition should now succeed
		lock3, err3 := snapshot.AcquireStorageLock(ctx, drv, "", 60)
		if err3 != nil {
			t.Fatalf("expected lock acquisition after release, got: %v", err3)
		}
		_ = lock3.Release(ctx)

		// Verify in-memory registry mutex as well
		reg := snapshot.NewJobMutexRegistry()
		if !reg.TryLock(jobID) {
			t.Errorf("initial TryLock failed")
		}
		if reg.TryLock(jobID) {
			t.Errorf("secondary TryLock should have been blocked")
		}
		reg.Unlock(jobID)
		if !reg.TryLock(jobID) {
			t.Errorf("TryLock after Unlock failed")
		}
	})
}

// TestTier3_DiskHealthProbe_And_WebhookAlert tests pairwise interaction between
// OS Syscall Disk Inspection, Telemetry Probe, and Webhook Alert Dispatcher.
func TestTier3_DiskHealthProbe_And_WebhookAlert(t *testing.T) {
	webhookMock := harness.NewWebhookMockServer("webhook-secret-key")
	defer webhookMock.Close()

	metrics := telemetry.NewMetricsRegistry()
	dispatcher := telemetry.NewWebhookDispatcher(webhookMock.URL(), "webhook-secret-key", metrics)
	dispatcher.SetCooldown(0)

	t.Run("Pairwise_Probe_Breach_Fires_Webhook", func(t *testing.T) {
		// Simulate disk probe exceeding 80% WARNING
		usage := &telemetry.DiskUsage{
			Path:        "C:\\data",
			TotalBytes:  1000,
			FreeBytes:   155,
			UsedBytes:   845,
			UsedPercent: 84.5,
		}

		payload := dispatcher.EvaluateDisk(usage)
		if payload == nil {
			t.Fatalf("expected alert payload from disk usage 84.5%%")
		}
		if payload.Severity != telemetry.SeverityWarning {
			t.Errorf("expected WARNING severity, got %s", payload.Severity)
		}

		err := dispatcher.Dispatch(context.Background(), payload)
		if err != nil {
			t.Fatalf("failed to dispatch webhook: %v", err)
		}

		captured := webhookMock.GetCaptured()
		if len(captured) != 1 {
			t.Fatalf("expected 1 captured webhook, got %d", len(captured))
		}
		if !webhookMock.VerifyHMAC(captured[0]) {
			t.Errorf("HMAC signature verification failed")
		}
		if captured[0].Payload.Severity != "WARNING" {
			t.Errorf("expected WARNING severity in captured payload, got %s", captured[0].Payload.Severity)
		}
		if captured[0].Payload.Rule != "disk_capacity_warning" {
			t.Errorf("expected rule disk_capacity_warning, got %s", captured[0].Payload.Rule)
		}
	})
}
