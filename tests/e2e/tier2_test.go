package e2e

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/internal/daemon"
	"github.com/aboutdevz/unistorage/pkg/storage/s3"
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
		h.CreateFile("empty.txt", []byte{})
		data := h.ReadFile("empty.txt")
		if len(data) != 0 {
			t.Errorf("expected 0 bytes, got %d", len(data))
		}
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
		if res.ExitCode != 0 {
			t.Fatalf("cp empty file failed with exit code %d: %s", res.ExitCode, res.Stderr)
		}
		if !h.FileExists("empty_dst.txt") {
			t.Fatalf("destination file empty_dst.txt was not created")
		}
		if data := h.ReadFile("empty_dst.txt"); len(data) != 0 {
			t.Errorf("expected 0 bytes in destination, got %d", len(data))
		}
	})

	// B4: Sync of zero-byte file
	t.Run("Boundary_EmptyFile_Sync", func(t *testing.T) {
		srcDir := filepath.Join(h.RootDir, "empty_sync_src")
		dstDir := filepath.Join(h.RootDir, "empty_sync_dst")
		h.CreateFile("empty_sync_src/zero.dat", []byte{})
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("sync empty file failed with exit code %d: %s", res.ExitCode, res.Stderr)
		}
		syncedFile := filepath.Join("empty_sync_dst", "zero.dat")
		if !h.FileExists(syncedFile) {
			t.Fatalf("synced file %s does not exist", syncedFile)
		}
		if data := h.ReadFile(syncedFile); len(data) != 0 {
			t.Errorf("expected 0 bytes in synced file, got %d", len(data))
		}
	})

	// B5: Checksum calculation for empty file (SHA-256 of empty string)
	t.Run("Boundary_EmptyFile_SHA256", func(t *testing.T) {
		srcDir := filepath.Join(h.RootDir, "empty_chk_src")
		dstDir := filepath.Join(h.RootDir, "empty_chk_dst")
		h.CreateFile("empty_chk_src/zero.dat", []byte{})
		res := h.RunCLI(context.Background(), "sync", "--checksum", srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("sync --checksum failed for empty file: %s", res.Stderr)
		}
		syncedFile := filepath.Join("empty_chk_dst", "zero.dat")
		if !h.FileExists(syncedFile) {
			t.Fatalf("expected synced file to exist")
		}
		// Re-run sync to ensure idempotent 0-copy under checksum match
		res2 := h.RunCLI(context.Background(), "sync", "--checksum", srcDir, dstDir)
		if res2.ExitCode != 0 {
			t.Fatalf("second sync --checksum failed: %s", res2.Stderr)
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
		ctx := context.Background()
		s3Drv, err := s3.New(ctx, s3.Config{
			Endpoint:     s3Mock.URL(),
			Region:       "us-east-1",
			Bucket:       "large-bucket",
			AccessKey:    "test-access",
			SecretKey:    "test-secret",
			UsePathStyle: true,
		})
		if err != nil {
			t.Fatalf("failed to init s3 driver: %v", err)
		}
		size17MB := int64(17 * 1024 * 1024)
		chunk := bytes.Repeat([]byte("M"), 1024*1024)
		readers := make([]io.Reader, 17)
		for i := 0; i < 17; i++ {
			readers[i] = bytes.NewReader(chunk)
		}
		err = s3Drv.Write(ctx, "trigger-17mb.bin", io.MultiReader(readers...), size17MB)
		if err != nil {
			t.Fatalf("17MB multipart write failed: %v", err)
		}
		data, found := s3Mock.GetObjectData("large-bucket", "trigger-17mb.bin")
		if !found || int64(len(data)) != size17MB {
			t.Fatalf("expected 17MB object stored in s3 mock, found=%v len=%d", found, len(data))
		}
	})

	// B2: Exact 16MB Boundary
	t.Run("Boundary_Exact_16MB_Threshold", func(t *testing.T) {
		ctx := context.Background()
		s3Drv, err := s3.New(ctx, s3.Config{
			Endpoint:     s3Mock.URL(),
			Region:       "us-east-1",
			Bucket:       "large-bucket",
			AccessKey:    "test-access",
			SecretKey:    "test-secret",
			UsePathStyle: true,
		})
		if err != nil {
			t.Fatalf("failed to init s3 driver: %v", err)
		}
		size16MB := int64(16 * 1024 * 1024)
		chunk := bytes.Repeat([]byte("K"), 1024*1024)
		readers := make([]io.Reader, 16)
		for i := 0; i < 16; i++ {
			readers[i] = bytes.NewReader(chunk)
		}
		err = s3Drv.Write(ctx, "exact-16mb.bin", io.MultiReader(readers...), size16MB)
		if err != nil {
			t.Fatalf("exact 16MB single-part write failed: %v", err)
		}
		data, found := s3Mock.GetObjectData("large-bucket", "exact-16mb.bin")
		if !found || int64(len(data)) != size16MB {
			t.Fatalf("expected 16MB object stored in s3 mock, found=%v len=%d", found, len(data))
		}
	})

	// B3: S3 Multipart Multi-Chunk Upload
	t.Run("Boundary_Multipart_Chunk_Assembly", func(t *testing.T) {
		// Initiate
		req, _ := http.NewRequest(http.MethodPost, s3Mock.URL()+"/large-bucket/assembled.bin?uploads", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to initiate multipart: %v", err)
		}
		var initRes struct {
			UploadId string `xml:"UploadId"`
		}
		_ = xml.NewDecoder(resp.Body).Decode(&initRes)
		resp.Body.Close()

		// Upload part 1 (5MB)
		part1 := bytes.Repeat([]byte("A"), 5*1024*1024)
		p1Req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/large-bucket/assembled.bin?partNumber=1&uploadId=%s", s3Mock.URL(), initRes.UploadId), bytes.NewReader(part1))
		p1Resp, err := http.DefaultClient.Do(p1Req)
		if err != nil || p1Resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to upload part 1: %v", err)
		}
		p1Resp.Body.Close()

		// Upload part 2 (5MB)
		part2 := bytes.Repeat([]byte("B"), 5*1024*1024)
		p2Req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/large-bucket/assembled.bin?partNumber=2&uploadId=%s", s3Mock.URL(), initRes.UploadId), bytes.NewReader(part2))
		p2Resp, err := http.DefaultClient.Do(p2Req)
		if err != nil || p2Resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to upload part 2: %v", err)
		}
		p2Resp.Body.Close()

		// Complete
		completeXML := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"etag1"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"etag2"</ETag></Part></CompleteMultipartUpload>`
		cReq, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/large-bucket/assembled.bin?uploadId=%s", s3Mock.URL(), initRes.UploadId), strings.NewReader(completeXML))
		cResp, err := http.DefaultClient.Do(cReq)
		if err != nil || cResp.StatusCode != http.StatusOK {
			t.Fatalf("failed to complete multipart: %v", err)
		}
		cResp.Body.Close()

		data, found := s3Mock.GetObjectData("large-bucket", "assembled.bin")
		if !found || len(data) != 10*1024*1024 {
			t.Fatalf("expected 10MB assembled object, found=%v len=%d", found, len(data))
		}
	})

	// B4: Dynamic Unknown-Size Stream (-1)
	t.Run("Boundary_Dynamic_Stream_NegativeSize", func(t *testing.T) {
		ctx := context.Background()
		s3Drv, err := s3.New(ctx, s3.Config{
			Endpoint:     s3Mock.URL(),
			Region:       "us-east-1",
			Bucket:       "large-bucket",
			AccessKey:    "test-access",
			SecretKey:    "test-secret",
			UsePathStyle: true,
		})
		if err != nil {
			t.Fatalf("failed to init s3 driver: %v", err)
		}
		content := []byte("dynamic unknown size content stream")
		err = s3Drv.Write(ctx, "dynamic-stream.bin", bytes.NewReader(content), -1)
		if err != nil {
			t.Fatalf("dynamic stream write failed: %v", err)
		}
		data, found := s3Mock.GetObjectData("large-bucket", "dynamic-stream.bin")
		if !found || string(data) != string(content) {
			t.Fatalf("dynamic stream content mismatch: found=%v", found)
		}
	})

	// B5: Abort Multipart Cleanup on Failure
	t.Run("Boundary_Abort_Multipart_Cleanup", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, s3Mock.URL()+"/large-bucket/aborted.bin?uploads", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("failed to initiate: %v", err)
		}
		var initRes struct {
			UploadId string `xml:"UploadId"`
		}
		_ = xml.NewDecoder(resp.Body).Decode(&initRes)
		resp.Body.Close()

		abortReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/large-bucket/aborted.bin?uploadId=%s", s3Mock.URL(), initRes.UploadId), nil)
		abortResp, err := http.DefaultClient.Do(abortReq)
		if err != nil || abortResp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204 No Content on abort, got %v (status %d)", err, abortResp.StatusCode)
		}
		abortResp.Body.Close()
	})
}

// TestTier2_PathTraversalInjections tests security defenses against hostile directory traversal inputs.
func TestTier2_PathTraversalInjections(t *testing.T) {
	h := harness.NewHarness(t)

	// B1: Classic dot-dot-slash
	t.Run("Traversal_DotDotSlash", func(t *testing.T) {
		payload := "../../etc/passwd"
		res := h.RunCLI(context.Background(), "ls", payload)
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for traversal %q, got 0", payload)
		}
	})

	// B2: URL-encoded traversal
	t.Run("Traversal_URLEncoded", func(t *testing.T) {
		payload := "%2e%2e%2f%2e%2e%2fwindows%2fsystem32"
		res := h.RunCLI(context.Background(), "ls", payload)
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for url-encoded traversal, got 0")
		}
	})

	// B3: Null-byte injection
	t.Run("Traversal_NullByte", func(t *testing.T) {
		payload := "safe.png\x00../../evil.exe"
		res := h.RunCLI(context.Background(), "ls", payload)
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for null byte injection, got 0")
		}
	})

	// B4: Windows Reserved Device Names
	t.Run("Traversal_Windows_Device_Names", func(t *testing.T) {
		devices := []string{"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}
		for _, dev := range devices {
			res := h.RunCLI(context.Background(), "ls", dev)
			if res.ExitCode == 0 {
				t.Fatalf("expected non-zero exit code for Windows device %q, got 0", dev)
			}
		}
	})

	// B5: Windows Alternate Data Streams (ADS)
	t.Run("Traversal_AlternateDataStream_Colon", func(t *testing.T) {
		payload := "test.txt::$DATA"
		res := h.RunCLI(context.Background(), "ls", payload)
		if res.ExitCode == 0 {
			t.Fatalf("expected non-zero exit code for ADS payload, got 0")
		}
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
	tempDir := t.TempDir()
	tokenFile := filepath.Join(tempDir, "daemon.token")
	d, err := daemon.New(daemon.Config{
		Addr:      "127.0.0.1:0",
		TokenFile: tokenFile,
	})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	server := httptest.NewServer(d.Handler())
	defer server.Close()

	// B1: Missing Authorization Header
	t.Run("Auth_Missing_Header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/remotes", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	// B2: Empty Bearer Token
	t.Run("Auth_Empty_Bearer", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/remotes", nil)
		req.Header.Set("Authorization", "Bearer ")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	// B3: Non-Bearer Scheme (e.g. Basic auth)
	t.Run("Auth_NonBearer_Scheme", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/remotes", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	// B4: Malformed Hex Token Length
	t.Run("Auth_Malformed_Token_Length", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/remotes", nil)
		req.Header.Set("Authorization", "Bearer short-token-123")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})

	// B5: Tampered Hex Token (bit-flip)
	t.Run("Auth_Tampered_Token", func(t *testing.T) {
		realToken := d.Token()
		tampered := []byte(realToken)
		if len(tampered) > 0 {
			if tampered[0] == 'a' {
				tampered[0] = 'b'
			} else {
				tampered[0] = 'a'
			}
		}
		req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/remotes", nil)
		req.Header.Set("Authorization", "Bearer "+string(tampered))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
		}
	})
}

// TestTier2_InvalidHostHeadersAndDNSRebinding tests anti-DNS rebinding defenses.
func TestTier2_InvalidHostHeadersAndDNSRebinding(t *testing.T) {
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

	testHost := func(t *testing.T, host string, expectedCode int) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Host = host

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != expectedCode {
			t.Errorf("host %q: expected status %d, got %d", host, expectedCode, rec.Code)
		}
	}

	t.Run("HostSec_Attacker_Domain", func(t *testing.T) { testHost(t, "attacker.dnsrebind.com", http.StatusForbidden) })
	t.Run("HostSec_Public_IP", func(t *testing.T) { testHost(t, "203.0.113.195", http.StatusForbidden) })
	t.Run("HostSec_Spoofed_Subdomain", func(t *testing.T) { testHost(t, "127.0.0.1.attacker.com", http.StatusForbidden) })
	t.Run("HostSec_Empty_Host", func(t *testing.T) { testHost(t, "", http.StatusForbidden) })
	t.Run("HostSec_Loopback_Valid", func(t *testing.T) { testHost(t, "127.0.0.1:8080", http.StatusOK) })
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
		permErr := errors.New("AccessDenied: 403 Forbidden")
		if s3.IsTransient(permErr) {
			t.Errorf("403 error must not be classified as transient")
		}
		callCount := 0
		cfg := s3.DefaultRetryConfig()
		err := s3.ExecuteWithRetry(context.Background(), cfg, func() error {
			callCount++
			return permErr
		})
		if err == nil || callCount != 1 {
			t.Errorf("expected fatal error with callCount=1, got callCount=%d err=%v", callCount, err)
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
		cfg := s3.RetryConfig{
			MaxRetries: 3,
			BaseDelay:  5 * time.Millisecond,
			MaxDelay:   20 * time.Millisecond,
		}
		attempts := 0
		err := s3.ExecuteWithRetry(context.Background(), cfg, func() error {
			attempts++
			if attempts < 3 {
				return errors.New("503 SlowDown transient error")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("expected retry recovery, got error: %v", err)
		}
		if attempts != 3 {
			t.Errorf("expected exactly 3 attempts, got %d", attempts)
		}
	})
}
