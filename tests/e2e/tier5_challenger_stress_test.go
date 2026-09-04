package e2e

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/internal/daemon"
	"github.com/aboutdevz/unistorage/tests/e2e/harness"
)

// TestChallenger_PathTraversal_DeepAdversarial probes extensive traversal attacks across CLI commands
// and local remote sandbox confinement.
func TestChallenger_PathTraversal_DeepAdversarial(t *testing.T) {
	h := harness.NewHarness(t)

	// Create canary file strictly outside sandbox
	outsideDir := t.TempDir()
	outsideCanary := filepath.Join(outsideDir, "canary_leak.txt")
	canaryContent := "CRITICAL_SYSTEM_CANARY_DO_NOT_DISCLOSE"
	if err := os.WriteFile(outsideCanary, []byte(canaryContent), 0600); err != nil {
		t.Fatalf("failed to create canary file: %v", err)
	}

	sandboxDir := filepath.Join(h.RootDir, "sandbox")
	if err := os.MkdirAll(sandboxDir, 0755); err != nil {
		t.Fatalf("failed to create sandbox dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sandboxDir, "safe.txt"), []byte("safe content"), 0644); err != nil {
		t.Fatalf("failed to create safe file: %v", err)
	}

	// Register a local remote confined to sandboxDir
	passphrase := "testpass"
	addRes := h.RunCLI(context.Background(),
		"remote", "add", "sandboxed", "local",
		"--path", sandboxDir,
		"--vault-passphrase", passphrase,
	)
	if addRes.ExitCode != 0 {
		t.Fatalf("failed to add sandboxed remote: %s", addRes.Stderr)
	}

	// 1. Test attacks against sandboxed remote
	remoteAttackVectors := []struct {
		name    string
		payload string
	}{
		{"dotdot_unix", "../canary_leak.txt"},
		{"dotdot_windows", `..\canary_leak.txt`},
		{"mixed_slashes_1", `../..\canary_leak.txt`},
		{"mixed_slashes_2", `..\../canary_leak.txt`},
		{"double_slash_traversal", `....//....//canary_leak.txt`},
		{"triple_dot", `.../canary_leak.txt`},
		{"quad_dot", `..../canary_leak.txt`},
		{"url_encoded_dotdot_slash", `%2e%2e%2fcanary_leak.txt`},
		{"url_encoded_dotdot_backslash", `%2e%2e%5ccanary_leak.txt`},
		{"alternate_data_stream_basic", `safe.txt::$DATA`},
		{"alternate_data_stream_custom", `safe.txt:stream`},
		{"device_nul_ext", `NUL.txt`},
		{"device_com1_ext", `COM1.txt`},
		{"device_lpt1_ext", `LPT1.txt`},
		{"device_con_ext", `CON.txt`},
		{"device_prn_ext", `PRN.txt`},
		{"device_aux_ext", `AUX.txt`},
		{"colon_drive_traversal", `C:canary_leak.txt`},
		{"absolute_drive_path", outsideCanary},
	}

	for _, tc := range remoteAttackVectors {
		target := "sandboxed:" + tc.payload

		t.Run("Remote_ls_confinement_"+tc.name, func(t *testing.T) {
			res := h.RunCLI(context.Background(), "ls", target, "--vault-passphrase", passphrase)
			// Strict confinement invariant: ls must NEVER disclose outside canary content or files
			if strings.Contains(res.Stdout, canaryContent) || strings.Contains(res.Stderr, canaryContent) {
				t.Fatalf("CRITICAL SECURITY VIOLATION: canary content disclosed in output for %s", tc.name)
			}
			if strings.Contains(res.Stdout, "canary_leak.txt") {
				t.Fatalf("CRITICAL SECURITY VIOLATION: canary file disclosed in ls listing for %s", tc.name)
			}
		})

		t.Run("Remote_cp_rejection_"+tc.name, func(t *testing.T) {
			destFile := filepath.Join(h.RootDir, "leak_target_"+tc.name+".txt")
			res := h.RunCLI(context.Background(), "cp", target, destFile, "--vault-passphrase", passphrase)
			// cp must be completely rejected by path sanitizer
			if res.ExitCode == 0 {
				t.Fatalf("VULNERABILITY: 'cp %s' succeeded with exit code 0!", target)
			}
			if data, err := os.ReadFile(destFile); err == nil {
				if strings.Contains(string(data), canaryContent) {
					t.Fatalf("CRITICAL LEAK: canary data copied to destination via %s", tc.name)
				}
			}
		})

		t.Run("Remote_rm_rejection_"+tc.name, func(t *testing.T) {
			res := h.RunCLI(context.Background(), "rm", target, "--vault-passphrase", passphrase)
			// rm must fail to delete or access outside target
			if res.ExitCode == 0 {
				t.Fatalf("VULNERABILITY: 'rm %s' succeeded with exit code 0!", target)
			}
			// Verify canary file remains intact
			if _, err := os.Stat(outsideCanary); err != nil {
				t.Fatalf("CRITICAL DAMAGE: canary file was modified or deleted via rm %s: %v", tc.name, err)
			}
		})
	}

	// 2. Direct CLI path traversal rejection for relative escape payloads
	cliTraversalPayloads := []string{
		"../secret.txt",
		`..\secret.txt`,
		"....//....//secret.txt",
		"CON",
		"NUL",
		"AUX",
	}

	for _, payload := range cliTraversalPayloads {
		t.Run("Direct_ls_"+payload, func(t *testing.T) {
			res := h.RunCLI(context.Background(), "ls", payload)
			if res.ExitCode == 0 {
				t.Fatalf("expected failure for direct traversal payload %q, got 0", payload)
			}
		})
		t.Run("Direct_cp_"+payload, func(t *testing.T) {
			res := h.RunCLI(context.Background(), "cp", payload, filepath.Join(h.RootDir, "dest.txt"))
			if res.ExitCode == 0 {
				t.Fatalf("expected failure for direct cp traversal payload %q, got 0", payload)
			}
		})
	}
}

// TestChallenger_Daemon_AuthBypass_Stress tests HTTP method tampering, case variants, and malicious tokens.
func TestChallenger_Daemon_AuthBypass_Stress(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "daemon.token")

	d, err := daemon.New(daemon.Config{
		Addr:      "127.0.0.1:0",
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	handler := d.Handler()
	realToken := d.Token()

	attackCases := []struct {
		name       string
		method     string
		path       string
		authHeader string
	}{
		{"lowercase_bearer", http.MethodGet, "/api/v1/remotes", "bearer " + realToken},
		{"uppercase_bearer", http.MethodGet, "/api/v1/remotes", "BEARER " + realToken},
		{"double_space_bearer", http.MethodGet, "/api/v1/remotes", "Bearer  " + realToken},
		{"tab_separated_bearer", http.MethodGet, "/api/v1/remotes", "Bearer\t" + realToken},
		{"trailing_space_token", http.MethodGet, "/api/v1/remotes", "Bearer " + realToken + " "},
		{"prefix_only_token", http.MethodGet, "/api/v1/remotes", "Bearer " + realToken[:16]},
		{"null_byte_in_token", http.MethodGet, "/api/v1/remotes", "Bearer " + realToken[:10] + "\x00" + realToken[11:]},
		{"method_options_unauth", http.MethodOptions, "/api/v1/remotes", ""},
		{"method_post_unauth", http.MethodPost, "/api/v1/remotes", ""},
		{"method_delete_unauth", http.MethodDelete, "/api/v1/remotes/nonexistent", ""},
		{"method_patch_unauth", http.MethodPatch, "/api/v1/remotes", ""},
		{"storage_get_unauth", http.MethodGet, "/api/v1/storage/default/secret.txt", ""},
		{"storage_put_unauth", http.MethodPut, "/api/v1/storage/default/secret.txt", ""},
		{"storage_delete_unauth", http.MethodDelete, "/api/v1/storage/default/secret.txt", ""},
		{"storage_head_unauth", http.MethodHead, "/api/v1/storage/default/secret.txt", ""},
	}

	for _, tc := range attackCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Host = "127.0.0.1:8080"
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
				t.Fatalf("SECURITY VIOLATION for %s %s (%s): expected 401/403, got %d (body: %s)",
					tc.method, tc.path, tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestChallenger_Daemon_HostSpoofing_Exhaustive tests octal, hex, dword IP formats, and external origins.
func TestChallenger_Daemon_HostSpoofing_Exhaustive(t *testing.T) {
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "daemon.token")

	d, err := daemon.New(daemon.Config{
		Addr:      "127.0.0.1:0",
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	handler := d.Handler()

	spoofedHosts := []struct {
		name string
		host string
	}{
		{"octal_ip", "0177.0000.0000.0001"},
		{"hex_ip", "0x7f000001"},
		{"dword_ip", "2130706433"},
		{"alternative_loopback_2", "127.0.0.2"},
		{"alternative_loopback_254", "127.0.0.254"},
		{"ipv6_unspecified", "[::]"},
		{"ipv6_non_loopback", "[::2]"},
		{"trailing_dot_localhost", "localhost."},
		{"empty_host", ""},
		{"port_only", ":8080"},
		{"external_subdomain", "localhost.evil.com"},
		{"prefix_spoof", "127.0.0.1.attacker.com"},
	}

	for _, tc := range spoofedHosts {
		t.Run("Host_"+tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Host = tc.host
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("DNS REBINDING VULNERABILITY: host %q returned %d, expected 403 Forbidden", tc.host, w.Code)
			}
		})
	}

	// Test CORS origin spoofing against public endpoints as well
	origins := []string{
		"http://127.0.0.1:3000",
		"http://localhost:3000",
		"http://127.0.0.1:8080",
		"null",
		"file://",
		"https://google.com",
	}

	for _, origin := range origins {
		t.Run("Origin_"+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("CORS VULNERABILITY: origin %q was not denied! Got %d", origin, w.Code)
			}
		})
	}
}

// TestChallenger_ConcurrentSync_HighConcurrencyRace stresses sync with 8 concurrent workers and random file mutations.
func TestChallenger_ConcurrentSync_HighConcurrencyRace(t *testing.T) {
	h := harness.NewHarness(t)
	srcDir := filepath.Join(h.RootDir, "stress_src")
	dstDir := filepath.Join(h.RootDir, "stress_dst")

	const totalFiles = 40
	payloads := make(map[string][]byte)

	for i := 0; i < totalFiles; i++ {
		key := fmt.Sprintf("stress_src/file_%02d.bin", i)
		data := make([]byte, 1024*(i+1))
		_, _ = rand.Read(data)
		payloads[fmt.Sprintf("file_%02d.bin", i)] = data
		h.CreateFile(key, data)
	}

	const workers = 8
	var wg sync.WaitGroup
	var panicCount int32

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt32(&panicCount, 1)
				}
			}()

			res := h.RunCLI(ctx, "sync", srcDir, dstDir, "--checksum")
			if res.Err != nil && res.ExitCode == 0 {
				t.Errorf("unexpected error on 0 exit: %v", res.Err)
			}
		}(w)
	}

	wg.Wait()

	if atomic.LoadInt32(&panicCount) > 0 {
		t.Fatalf("CRITICAL: %d panics occurred during concurrent sync execution", panicCount)
	}

	// Converging final sync
	finalRes := h.RunCLI(context.Background(), "sync", srcDir, dstDir, "--checksum")
	if finalRes.ExitCode != 0 {
		t.Fatalf("converging sync failed: %s (stderr: %s)", finalRes.Err, finalRes.Stderr)
	}

	// Bit-for-bit validation
	for filename, wantBytes := range payloads {
		gotPath := filepath.Join(dstDir, filename)
		gotBytes, err := os.ReadFile(gotPath)
		if err != nil {
			t.Fatalf("missing synced file %s: %v", filename, err)
		}
		if len(gotBytes) != len(wantBytes) {
			t.Fatalf("file %s size mismatch: got %d, want %d", filename, len(gotBytes), len(wantBytes))
		}
		for b := range wantBytes {
			if gotBytes[b] != wantBytes[b] {
				t.Fatalf("file %s byte mismatch at offset %d", filename, b)
			}
		}
	}
}
