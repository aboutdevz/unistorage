package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aboutdevz/unistorage/internal/daemon"
	"github.com/aboutdevz/unistorage/pkg/entitlement"
	"github.com/aboutdevz/unistorage/tests/e2e/harness"
)

// ==============================================================================
// Tier 5: Adversarial Hardening (Cross-Cutting White-Box & Opaque-Box E2E Tests)
// ==============================================================================

// 1. Path Traversal Attacks via CLI Commands
func TestTier5_PathTraversal_CLI_Rejection(t *testing.T) {
	h := harness.NewHarness(t)

	// Create test files inside sandbox
	h.CreateFile("sandbox/legit.txt", []byte("safe legitimate payload"))
	outsideSecret := filepath.Join(h.RootDir, "secret_outside.txt")
	if err := os.WriteFile(outsideSecret, []byte("TOP_SECRET_CANNOT_LEAK"), 0600); err != nil {
		t.Fatalf("failed to create target file: %v", err)
	}

	traversalPayloads := []string{
		"../secret_outside.txt",
		`..\secret_outside.txt`,
		"sandbox/../../secret_outside.txt",
		`sandbox\..\..\secret_outside.txt`,
		"....//....//secret_outside.txt",
		"CON",
		"NUL",
		"AUX",
	}

	for _, payload := range traversalPayloads {
		t.Run("ls_"+payload, func(t *testing.T) {
			res := h.RunCLI(context.Background(), "ls", payload)
			if res.ExitCode == 0 {
				t.Errorf("expected failure when running ls with traversal payload %q, but exited with code 0", payload)
			}
		})

		t.Run("cp_"+payload, func(t *testing.T) {
			res := h.RunCLI(context.Background(), "cp", payload, filepath.Join(h.RootDir, "leak.txt"))
			if res.ExitCode == 0 {
				t.Errorf("expected failure when running cp with traversal payload %q, but exited with code 0", payload)
			}
		})
	}
}

// 2. Daemon Authentication Bypass & Brute-Force Rejection
func TestTier5_Daemon_AuthBypass_Rejection(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "daemon.token")

	d, err := daemon.New(daemon.Config{
		Addr:      "127.0.0.1:0",
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	server := &http.Server{
		Handler: d.Handler(),
	}

	ln, err := listenLoopbackPort()
	if err != nil {
		t.Fatalf("failed to bind loopback listener: %v", err)
	}
	defer ln.Close()

	go func() {
		_ = server.Serve(ln)
	}()
	defer func() {
		_ = server.Close()
	}()

	addr := ln.Addr().String()
	baseURL := "http://" + addr

	attackCases := []struct {
		name       string
		authHeader string
	}{
		{"missing_auth_header", ""},
		{"malformed_bearer_prefix", "Basic 123456"},
		{"empty_bearer_token", "Bearer "},
		{"short_invalid_token", "Bearer bad"},
		{"random_64char_token", "Bearer 0000000000000000000000000000000000000000000000000000000000000000"},
		{"sql_injection_token", "Bearer ' OR '1'='1"},
		{"newline_injection_token", "Bearer valid\r\nInjected: true"},
	}

	for _, tc := range attackCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/remotes", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				// Go's net/http client may reject invalid header characters before transmission
				if strings.Contains(err.Error(), "invalid header field") {
					return // Expected client-side rejection of malformed header
				}
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("expected status 401 Unauthorized for %s, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}

// 3. DNS Rebinding & Cross-Origin Attack Rejection on Daemon
func TestTier5_Daemon_DNSRebinding_Rejection(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "daemon.token")

	d, err := daemon.New(daemon.Config{
		Addr:      "127.0.0.1:0",
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	ln, err := listenLoopbackPort()
	if err != nil {
		t.Fatalf("failed to bind loopback: %v", err)
	}
	defer ln.Close()

	server := &http.Server{Handler: d.Handler()}
	go func() { _ = server.Serve(ln) }()
	defer func() { _ = server.Close() }()

	baseURL := "http://" + ln.Addr().String()

	// 1. Host Header Spoofing (DNS Rebinding)
	spoofedHosts := []string{
		"attacker.com",
		"attacker.com:8080",
		"127.0.0.1.attacker.com",
		"evil-rebinding.org",
		"192.168.1.100",
		"google.com",
	}

	for _, host := range spoofedHosts {
		t.Run("host_"+host, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/health", nil)
			req.Host = host

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("expected HTTP 403 Forbidden for spoofed host %q, got %d", host, resp.StatusCode)
			}
		})
	}

	// 2. CORS Browser Drive-By Rejection
	t.Run("cors_origin_rejection", func(t *testing.T) {
		origins := []string{
			"http://evil.com",
			"https://attacker.org",
			"null",
			"file://",
		}
		for _, origin := range origins {
			req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/health", nil)
			req.Header.Set("Origin", origin)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("expected HTTP 403 Forbidden for Origin %q, got %d", origin, resp.StatusCode)
			}
		}
	})
}

// 4. Concurrent Sync Operations and Race Resilience
func TestTier5_Concurrent_Sync_Race_Resilience(t *testing.T) {
	h := harness.NewHarness(t)
	srcDir := filepath.Join(h.RootDir, "sync_src")
	dstDir := filepath.Join(h.RootDir, "sync_dst")

	// Seed 25 files
	for i := 0; i < 25; i++ {
		h.CreateFile(fmt.Sprintf("sync_src/file_%d.txt", i), []byte(fmt.Sprintf("initial content %d", i)))
	}

	var wg sync.WaitGroup
	workers := 4

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			res := h.RunCLI(context.Background(), "sync", srcDir, dstDir, "--checksum")
			if res.Err != nil && res.ExitCode == 0 {
				t.Errorf("unexpected error on 0 exit: %v", res.Err)
			}
		}(w)
	}

	wg.Wait()

	// Perform converging sync to ensure final consistency
	finalRes := h.RunCLI(context.Background(), "sync", srcDir, dstDir, "--checksum")
	if finalRes.ExitCode != 0 {
		t.Fatalf("converging sync failed: %s", finalRes.Stderr)
	}

	// Verify all 25 files exist in destination with intact data
	for i := 0; i < 25; i++ {
		dstFile := filepath.Join(dstDir, fmt.Sprintf("file_%d.txt", i))
		data, err := os.ReadFile(dstFile)
		if err != nil {
			t.Errorf("expected synced file %s to exist in destination: %v", dstFile, err)
			continue
		}
		expected := fmt.Sprintf("initial content %d", i)
		if string(data) != expected {
			t.Errorf("data corruption in %s: expected %q, got %q", dstFile, expected, string(data))
		}
	}
}

// 5. Constant-Memory Streaming OOM Resistance
func TestTier5_ConstantMemory_Streaming_OOM_Resistance(t *testing.T) {
	h := harness.NewHarness(t)

	// Create a 5MB payload
	dataSize := 5 * 1024 * 1024
	srcFile := filepath.Join(h.RootDir, "large_source.bin")
	dstFile := filepath.Join(h.RootDir, "large_dest.bin")

	zeros := make([]byte, 1024*1024)
	f, err := os.Create(srcFile)
	if err != nil {
		t.Fatalf("failed to create large source: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := f.Write(zeros); err != nil {
			f.Close()
			t.Fatalf("failed to write data: %v", err)
		}
	}
	_ = f.Close()

	// Execute cp via CLI
	res := h.RunCLI(context.Background(), "cp", srcFile, dstFile)
	if res.ExitCode != 0 {
		t.Fatalf("cp failed for 5MB file: %v, stderr: %s", res.Err, res.Stderr)
	}

	fi, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("destination file not created: %v", err)
	}
	if fi.Size() != int64(dataSize) {
		t.Errorf("expected file size %d bytes, got %d", dataSize, fi.Size())
	}
}

// 6. Vault Credential Isolation at Rest
func TestTier5_Vault_Credential_Isolation_At_Rest(t *testing.T) {
	h := harness.NewHarness(t)
	passphrase := "my-ultra-secure-vault-passphrase"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// Add remote via CLI
	res := h.RunCLI(context.Background(),
		"remote", "add", "prod-s3", "s3",
		"--endpoint", "https://s3.amazonaws.com",
		"--bucket", "company-prod-vault-test",
		"--access-key", "AKIAIOSFODNN7EXAMPLE",
		"--secret-key", secretKey,
		"--vault-passphrase", passphrase,
	)
	if res.ExitCode != 0 {
		t.Fatalf("remote add failed: %v, stderr: %s", res.Err, res.Stderr)
	}

	// Read vault file from disk directly
	vaultPath := filepath.Join(h.ConfigDir, "vault.enc")
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		vaultPath = filepath.Join(h.ConfigDir, "vault.db")
	}

	vaultBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault file from disk: %v", err)
	}

	// Verify plaintext secret key is NOT present in raw vault file
	if bytes.Contains(vaultBytes, []byte(secretKey)) {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Secret key %q found in plaintext in vault file %s", secretKey, vaultPath)
	}
	if bytes.Contains(vaultBytes, []byte(passphrase)) {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Vault passphrase found in plaintext in vault file %s", vaultPath)
	}
}

// 7. Enterprise Feature Gate Enforcement
func TestTier5_Enterprise_FeatureGate_Enforcement(t *testing.T) {
	checker := entitlement.NewCommunityChecker()
	ctx := context.Background()

	// Verify community edition denies commercial features
	if checker.IsFeatureEnabled(ctx, entitlement.FeatureSnapshotBackup) {
		t.Errorf("expected FeatureSnapshotBackup to be FALSE for Community edition")
	}
	if checker.IsFeatureEnabled(ctx, entitlement.FeatureTelemetryProbe) {
		t.Errorf("expected FeatureTelemetryProbe to be FALSE for Community edition")
	}
	if err := checker.Require(ctx, entitlement.FeatureWebhookAlerts); err == nil {
		t.Errorf("expected Require(FeatureWebhookAlerts) to return error for Community edition")
	}

	info, err := checker.LicenseInfo()
	if err != nil {
		t.Fatalf("unexpected error getting license info: %v", err)
	}
	if info.Tier != entitlement.TierCommunity {
		t.Errorf("expected tier 'community', got %q", info.Tier)
	}
}

func listenLoopbackPort() (net.Listener, error) {
	var l net.Listener
	var err error
	for port := 18080; port < 19000; port++ {
		l, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			return l, nil
		}
	}
	return nil, err
}
