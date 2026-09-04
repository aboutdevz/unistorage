package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aboutdevz/unistorage/internal/daemon"
	"github.com/aboutdevz/unistorage/pkg/entitlement"
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

// TestTier3_Entitlement_And_Sync_Boundary tests pairwise interaction between
// Sync Engine and Entitlement Checker.
func TestTier3_Entitlement_And_Sync_Boundary(t *testing.T) {
	h := harness.NewHarness(t)
	ctx := context.Background()

	checker := entitlement.NewDefaultChecker()

	t.Run("Pairwise_Community_Edition_Allows_Core_Sync", func(t *testing.T) {
		h.CreateFile("source/sample.txt", []byte("sample core sync content"))
		res := h.RunCLI(ctx, "sync", filepath.Join(h.RootDir, "source"), filepath.Join(h.RootDir, "dest"))
		if res.ExitCode != 0 {
			t.Fatalf("core sync failed under community edition: %s", res.Stderr)
		}
		if !h.FileExists("dest/sample.txt") {
			t.Errorf("synced file dest/sample.txt missing on disk")
		}
	})

	t.Run("Pairwise_Community_Edition_Denies_Commercial_Capabilities", func(t *testing.T) {
		for _, feat := range []entitlement.Feature{
			entitlement.FeatureSnapshotBackup,
			entitlement.FeatureRetentionPrune,
			entitlement.FeatureTelemetryProbe,
			entitlement.FeatureWebhookAlerts,
		} {
			if checker.IsFeatureEnabled(ctx, feat) {
				t.Errorf("expected commercial feature %s to be denied", feat)
			}
		}
	})
}

// TestTier3_LocalDriver_And_Storage_Isolation tests pairwise interaction between
// Local FS Driver and Sandboxed Storage Root Boundaries.
func TestTier3_LocalDriver_And_Storage_Isolation(t *testing.T) {
	h := harness.NewHarness(t)
	ctx := context.Background()

	drv, err := local.New(h.RootDir)
	if err != nil {
		t.Fatalf("failed to create driver: %v", err)
	}

	t.Run("Pairwise_Driver_Writes_And_Reads_Within_Root", func(t *testing.T) {
		data := []byte("isolated payload")
		if err := drv.Write(ctx, "sub/test.bin", bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		rc, err := drv.Read(ctx, "sub/test.bin")
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}
		defer rc.Close()

		readBytes, _ := io.ReadAll(rc)
		if string(readBytes) != string(data) {
			t.Errorf("data mismatch: expected %q, got %q", string(data), string(readBytes))
		}
	})
}
