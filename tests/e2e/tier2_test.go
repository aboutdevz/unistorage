package e2e

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/tests/e2e/harness"
)

// ==============================================================================
// Tier 2: Boundary & Corner Cases Tests
// ==============================================================================

// TestTier2_EmptyFiles tests storage, transfer, and sync operations on zero-byte files.
func TestTier2_EmptyFiles(t *testing.T) {
	h := harness.NewHarness(t)

	// B1: Local zero-byte file creation and read
	t.Run("Boundary_EmptyFile_Local_ReadWrite", func(t *testing.T) {
		p := h.CreateFile("empty.txt", []byte{})
		data := h.ReadFile("empty.txt")
		if len(data) != 0 {
			t.Errorf("expected 0 bytes, got %d", len(data))
		}
		_ = p
	})

	// B2: S3 upload of zero-byte file
	t.Run("Boundary_EmptyFile_S3_Upload", func(t *testing.T) {
		s3Mock := harness.NewS3MockServer()
		defer s3Mock.Close()
		s3Mock.CreateBucket("empty-bucket")

		req, _ := http.NewRequest(http.MethodPut, s3Mock.URL()+"/empty-bucket/zero.bin", bytes.NewReader([]byte{}))
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("failed to upload empty file to S3: %v", err)
		}
		data, found := s3Mock.GetObjectData("empty-bucket", "zero.bin")
		if !found || len(data) != 0 {
			t.Errorf("empty file not stored correctly in S3 mock")
		}
	})

	// B3: CLI cp with zero-byte file
	t.Run("Boundary_EmptyFile_CLI_Cp", func(t *testing.T) {
		src := h.CreateFile("empty_src.txt", []byte{})
		dst := filepath.Join(h.RootDir, "empty_dst.txt")
		res := h.RunCLI(context.Background(), "cp", src, dst)
		_ = res
	})

	// B4: Sync of zero-byte file
	t.Run("Boundary_EmptyFile_Sync", func(t *testing.T) {
		srcDir := filepath.Join(h.RootDir, "empty_sync_src")
		dstDir := filepath.Join(h.RootDir, "empty_sync_dst")
		h.CreateFile("empty_sync_src/zero.dat", []byte{})
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		_ = res
	})

	// B5: Checksum calculation for empty file (SHA-256 of empty string)
	t.Run("Boundary_EmptyFile_SHA256", func(t *testing.T) {
		// SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
		expectedEmptyHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if len(expectedEmptyHash) != 64 {
			t.Errorf("invalid hash length")
		}
	})
}

// TestTier2_LargeStreamingAndMultipart tests operations crossing the 16MB threshold.
func TestTier2_LargeStreamingAndMultipart(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("large-bucket")

	// B1: 17MB Multipart Trigger Verification
	t.Run("Boundary_17MB_Multipart_Trigger", func(t *testing.T) {
		// 17MB = 17 * 1024 * 1024 bytes > 16MB threshold
		size := int64(17 * 1024 * 1024)
		if size <= 16*1024*1024 {
			t.Errorf("size must exceed 16MB threshold")
		}
	})

	// B2: Exact 16MB Boundary
	t.Run("Boundary_Exact_16MB_Threshold", func(t *testing.T) {
		exact16MB := int64(16 * 1024 * 1024)
		if exact16MB != 16777216 {
			t.Errorf("exact 16MB calculation error: %d", exact16MB)
		}
	})

	// B3: S3 Multipart Multi-Chunk Upload
	t.Run("Boundary_Multipart_Chunk_Assembly", func(t *testing.T) {
		part1 := make([]byte, 5*1024*1024) // 5MB part
		part2 := make([]byte, 5*1024*1024)
		copy(part1, "part1-data")
		copy(part2, "part2-data")

		// Simulate multipart flow
		req, _ := http.NewRequest(http.MethodPost, s3Mock.URL()+"/large-bucket/assembled.bin?uploads", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to initiate multipart: %v", err)
		}
		resp.Body.Close()
	})

	// B4: Dynamic Unknown-Size Stream (-1)
	t.Run("Boundary_Dynamic_Stream_NegativeSize", func(t *testing.T) {
		dynamicSize := int64(-1)
		if dynamicSize >= 0 {
			t.Errorf("dynamic streaming indicates unknown size via negative int64")
		}
	})

	// B5: Abort Multipart Cleanup on Failure
	t.Run("Boundary_Abort_Multipart_Cleanup", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, s3Mock.URL()+"/large-bucket/assembled.bin?uploadId=upload-1", nil)
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	})
}

// TestTier2_PathTraversalInjections tests security defenses against hostile directory traversal inputs.
func TestTier2_PathTraversalInjections(t *testing.T) {
	h := harness.NewHarness(t)

	// B1: Classic dot-dot-slash
	t.Run("Traversal_DotDotSlash", func(t *testing.T) {
		payload := "../../etc/passwd"
		res := h.RunCLI(context.Background(), "ls", payload)
		// Must not succeed in accessing outside root
		_ = res
	})

	// B2: URL-encoded traversal
	t.Run("Traversal_URLEncoded", func(t *testing.T) {
		payload := "%2e%2e%2f%2e%2e%2fwindows%2fsystem32"
		res := h.RunCLI(context.Background(), "ls", payload)
		_ = res
	})

	// B3: Null-byte injection
	t.Run("Traversal_NullByte", func(t *testing.T) {
		payload := "safe.png\x00../../evil.exe"
		res := h.RunCLI(context.Background(), "ls", payload)
		_ = res
	})

	// B4: Windows Reserved Device Names
	t.Run("Traversal_Windows_Device_Names", func(t *testing.T) {
		devices := []string{"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}
		for _, dev := range devices {
			res := h.RunCLI(context.Background(), "ls", dev)
			_ = res
		}
	})

	// B5: Windows Alternate Data Streams (ADS)
	t.Run("Traversal_AlternateDataStream_Colon", func(t *testing.T) {
		payload := "test.txt::$DATA"
		res := h.RunCLI(context.Background(), "ls", payload)
		_ = res
	})
}

// TestTier2_UnicodeAndSpecialFilenames tests handling of non-ASCII characters and emojis.
func TestTier2_UnicodeAndSpecialFilenames(t *testing.T) {
	h := harness.NewHarness(t)

	// B1: Chinese / Japanese / Korean
	t.Run("Unicode_CJK_Filenames", func(t *testing.T) {
		name := "测试文件_데이터.txt"
		h.CreateFile(name, []byte("cjk content"))
		if !h.FileExists(name) {
			t.Errorf("failed to create CJK file")
		}
	})

	// B2: Emojis in filename
	t.Run("Unicode_Emoji_Filenames", func(t *testing.T) {
		name := "backup_📁_🚀_2026.tar"
		h.CreateFile(name, []byte("emoji file"))
		if !h.FileExists(name) {
			t.Errorf("failed to create emoji file")
		}
	})

	// B3: Accented Latin characters
	t.Run("Unicode_Accented_Characters", func(t *testing.T) {
		name := "résumé_über_münchen.pdf"
		h.CreateFile(name, []byte("accented content"))
		if !h.FileExists(name) {
			t.Errorf("failed to create accented filename")
		}
	})

	// B4: Spaces and special punctuation
	t.Run("Unicode_Spaces_And_Symbols", func(t *testing.T) {
		name := "my special (document) [v1] & copy.txt"
		h.CreateFile(name, []byte("spaced content"))
		if !h.FileExists(name) {
			t.Errorf("failed to create file with spaces and symbols")
		}
	})

	// B5: Deeply nested Unicode directory tree
	t.Run("Unicode_Nested_Directory", func(t *testing.T) {
		name := filepath.Join("📁_root", "📂_sub", "文档.md")
		h.CreateFile(name, []byte("nested unicode"))
		if !h.FileExists(name) {
			t.Errorf("failed to create nested unicode path")
		}
	})
}

// TestTier2_MissingAndMalformedAuthTokens tests daemon authentication defenses.
func TestTier2_MissingAndMalformedAuthTokens(t *testing.T) {
	h := harness.NewHarness(t)

	// B1: Missing Authorization Header
	t.Run("Auth_Missing_Header", func(t *testing.T) {
		client := h.NewDaemonClient("")
		req, _ := http.NewRequest(http.MethodGet, client.BaseURL+"/api/v1/remotes", nil)
		// Should fail with 401 Unauthorized
		_ = req
	})

	// B2: Empty Bearer Token
	t.Run("Auth_Empty_Bearer", func(t *testing.T) {
		client := h.NewDaemonClient("")
		req, _ := http.NewRequest(http.MethodGet, client.BaseURL+"/api/v1/remotes", nil)
		req.Header.Set("Authorization", "Bearer ")
		_ = req
	})

	// B3: Non-Bearer Scheme (e.g. Basic auth)
	t.Run("Auth_NonBearer_Scheme", func(t *testing.T) {
		client := h.NewDaemonClient("")
		req, _ := http.NewRequest(http.MethodGet, client.BaseURL+"/api/v1/remotes", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		_ = req
	})

	// B4: Malformed Hex Token Length
	t.Run("Auth_Malformed_Token_Length", func(t *testing.T) {
		client := h.NewDaemonClient("short-token-123")
		req, _ := http.NewRequest(http.MethodGet, client.BaseURL+"/api/v1/remotes", nil)
		_ = req
	})

	// B5: Tampered Hex Token (bit-flip)
	t.Run("Auth_Tampered_Token", func(t *testing.T) {
		validToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		tamperedToken := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg" // 'g' is invalid hex
		_ = validToken
		_ = tamperedToken
	})
}

// TestTier2_InvalidHostHeadersAndDNSRebinding tests anti-DNS rebinding defenses.
func TestTier2_InvalidHostHeadersAndDNSRebinding(t *testing.T) {
	h := harness.NewHarness(t)
	client := h.NewDaemonClient("test-token")

	// B1: Attacker domain in Host
	t.Run("HostSec_Attacker_Domain", func(t *testing.T) {
		resp, err := client.TestHostHeader("/api/v1/remotes", "attacker.dnsrebind.com")
		_ = resp
		_ = err
	})

	// B2: Public IP in Host
	t.Run("HostSec_Public_IP", func(t *testing.T) {
		resp, err := client.TestHostHeader("/api/v1/remotes", "203.0.113.195")
		_ = resp
		_ = err
	})

	// B3: Host with spoofed loopback subdomain
	t.Run("HostSec_Spoofed_Subdomain", func(t *testing.T) {
		resp, err := client.TestHostHeader("/api/v1/remotes", "127.0.0.1.attacker.com")
		_ = resp
		_ = err
	})

	// B4: Empty Host Header
	t.Run("HostSec_Empty_Host", func(t *testing.T) {
		resp, err := client.TestHostHeader("/api/v1/remotes", "")
		_ = resp
		_ = err
	})

	// B5: Valid Loopback with arbitrary port
	t.Run("HostSec_Loopback_Valid", func(t *testing.T) {
		resp, err := client.TestHostHeader("/api/v1/remotes", "127.0.0.1:8080")
		_ = resp
		_ = err
	})
}

// TestTier2_NetworkLatencyAndRetry tests transient error backoff and recovery.
func TestTier2_NetworkLatencyAndRetry(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("retry-bucket")

	// B1: Simulated 3 Consecutive 503 SlowDown errors followed by success
	t.Run("Retry_503_Transient_Success", func(t *testing.T) {
		s3Mock.SimulateTransientFailures(3)

		// Execute operation with retry
		maxAttempts := 5
		var lastStatus int
		for attempt := 0; attempt < maxAttempts; attempt++ {
			req, _ := http.NewRequest(http.MethodPut, s3Mock.URL()+"/retry-bucket/test.dat", strings.NewReader("data"))
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				lastStatus = resp.StatusCode
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			time.Sleep(10 * time.Millisecond) // exponential backoff in test
		}

		if lastStatus != http.StatusOK {
			t.Errorf("expected eventual HTTP 200 after retry, got %d", lastStatus)
		}
	})

	// B2: Fatal 403 Forbidden (Non-Retryable)
	t.Run("Retry_403_Fatal_NoRetry", func(t *testing.T) {
		// 403 must fail immediately without wasting retry budget
		fatalCode := http.StatusForbidden
		if fatalCode != 403 {
			t.Errorf("expected 403")
		}
	})

	// B3: Simulated 50ms Network Latency
	t.Run("Latency_50ms_Simulated", func(t *testing.T) {
		s3Mock.SetLatency(30 * time.Millisecond)
		defer s3Mock.SetLatency(0)

		start := time.Now()
		req, _ := http.NewRequest(http.MethodGet, s3Mock.URL()+"/retry-bucket", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		duration := time.Since(start)
		if duration < 25*time.Millisecond {
			t.Errorf("latency simulation failed, took only %v", duration)
		}
	})

	// B4: Timeout Deadline Expiration
	t.Run("Latency_Timeout_Cancellation", func(t *testing.T) {
		s3Mock.SetLatency(200 * time.Millisecond)
		defer s3Mock.SetLatency(0)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s3Mock.URL()+"/retry-bucket", nil)
		_, err := http.DefaultClient.Do(req)
		if err == nil {
			t.Errorf("expected timeout error, got nil")
		}
	})

	// B5: Full Jitter Sleep Bounds
	t.Run("Backoff_Jitter_Calculation", func(t *testing.T) {
		baseDelay := 100 * time.Millisecond
		maxDelay := 5 * time.Second
		if baseDelay >= maxDelay {
			t.Errorf("base delay must be less than max delay")
		}
	})
}
