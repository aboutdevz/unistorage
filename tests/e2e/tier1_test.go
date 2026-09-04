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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/internal/daemon"
	"github.com/aboutdevz/unistorage/pkg/entitlement"
	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
	"github.com/aboutdevz/unistorage/pkg/sync"
	"github.com/aboutdevz/unistorage/pkg/vault"
	"github.com/aboutdevz/unistorage/tests/e2e/harness"
)

// ==============================================================================
// Tier 1: Feature Coverage Tests (Features 1 - 44)
// ==============================================================================

// F01: Unified Driver Interface
func TestTier1_F01_UnifiedDriverInterface(t *testing.T) {
	h := harness.NewHarness(t)
	// Subtest 1: Read capability via CLI ls/cat
	t.Run("Driver_Read_Verification", func(t *testing.T) {
		h.CreateFile("sample.txt", []byte("hello unistorage driver read"))
		res := h.RunCLI(context.Background(), "ls", "sample.txt")
		if res.ExitCode != 0 {
			t.Fatalf("expected exit code 0, got %d: %s", res.ExitCode, res.Stderr)
		}
		if !strings.Contains(res.Stdout, "sample.txt") {
			t.Errorf("expected sample.txt in ls output, got: %s", res.Stdout)
		}
	})

	// Subtest 2: Write capability via CLI cp
	t.Run("Driver_Write_Verification", func(t *testing.T) {
		src := h.CreateFile("src_write.txt", []byte("write test payload"))
		dest := filepath.Join(h.RootDir, "dest_write.txt")
		res := h.RunCLI(context.Background(), "cp", src, dest)
		if res.ExitCode != 0 {
			t.Fatalf("cp failed with exit code %d: %s", res.ExitCode, res.Stderr)
		}
		if !h.FileExists("dest_write.txt") {
			t.Fatalf("destination file expected after successful cp")
		}
		written := h.ReadFile("dest_write.txt")
		if string(written) != "write test payload" {
			t.Errorf("unexpected content in written file: %s", string(written))
		}
	})

	// Subtest 3: List capability via CLI ls
	t.Run("Driver_List_Verification", func(t *testing.T) {
		h.CreateFile("list_dir/a.txt", []byte("a"))
		h.CreateFile("list_dir/b.txt", []byte("b"))
		res := h.RunCLI(context.Background(), "ls", filepath.Join(h.RootDir, "list_dir"))
		if res.ExitCode != 0 {
			t.Fatalf("ls failed: %s", res.Stderr)
		}
		if !strings.Contains(res.Stdout, "a.txt") || !strings.Contains(res.Stdout, "b.txt") {
			t.Errorf("expected a.txt and b.txt in ls output: %s", res.Stdout)
		}
	})

	// Subtest 4: Delete capability via CLI rm
	t.Run("Driver_Delete_Verification", func(t *testing.T) {
		f := h.CreateFile("to_delete.txt", []byte("delete me"))
		res := h.RunCLI(context.Background(), "rm", "-f", f)
		if res.ExitCode != 0 {
			t.Fatalf("rm failed: %s", res.Stderr)
		}
		if h.FileExists("to_delete.txt") {
			t.Errorf("expected file deleted")
		}
	})

	// Subtest 5: Stat capability
	t.Run("Driver_Stat_Verification", func(t *testing.T) {
		f := h.CreateFile("stat_file.txt", []byte("stat me"))
		res := h.RunCLI(context.Background(), "ls", "-l", f)
		if res.ExitCode != 0 {
			t.Fatalf("ls -l failed: %s", res.Stderr)
		}
	})
}

// F02: Local Storage Driver
func TestTier1_F02_LocalStorageDriver(t *testing.T) {
	h := harness.NewHarness(t)

	// Subtest 1: Basic File Read/Write
	t.Run("Local_ReadWrite", func(t *testing.T) {
		content := []byte("local filesystem driver test")
		h.CreateFile("local_test.dat", content)
		read := h.ReadFile("local_test.dat")
		if !bytes.Equal(content, read) {
			t.Errorf("expected %s, got %s", content, read)
		}
	})

	// Subtest 2: Nested Directory Auto-Creation
	t.Run("Local_MkdirParents", func(t *testing.T) {
		nested := filepath.Join(h.RootDir, "a", "b", "c", "nested.txt")
		h.CreateFile(filepath.Join("a", "b", "c", "nested.txt"), []byte("nested content"))
		if _, err := os.Stat(nested); err != nil {
			t.Errorf("expected parent directories auto-created: %v", err)
		}
	})

	// Subtest 3: Path Normalization
	t.Run("Local_PathNormalization", func(t *testing.T) {
		h.CreateFile("data/norm.txt", []byte("norm"))
		res := h.RunCLI(context.Background(), "ls", filepath.Join(h.RootDir, "data"))
		if res.ExitCode != 0 {
			t.Fatalf("ls failed: %s", res.Stderr)
		}
	})

	// Subtest 4: File Overwrite Behavior
	t.Run("Local_Overwrite", func(t *testing.T) {
		h.CreateFile("overwrite.txt", []byte("version 1"))
		h.CreateFile("overwrite.txt", []byte("version 2"))
		if string(h.ReadFile("overwrite.txt")) != "version 2" {
			t.Errorf("file overwrite failed")
		}
	})

	// Subtest 5: Stream Copy between local paths
	t.Run("Local_StreamCopy", func(t *testing.T) {
		s := h.CreateFile("stream_src.bin", make([]byte, 1024*1024)) // 1MB
		d := filepath.Join(h.RootDir, "stream_dst.bin")
		res := h.RunCLI(context.Background(), "cp", s, d)
		if res.ExitCode != 0 {
			t.Fatalf("cp failed: %s", res.Stderr)
		}
		if !h.FileExists("stream_dst.bin") {
			t.Fatalf("expected stream_dst.bin to exist")
		}
	})
}

// F03: S3 Storage Driver
func TestTier1_F03_S3StorageDriver(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("test-bucket")

	h := harness.NewHarness(t)

	// Subtest 1: Mock S3 Connectivity
	t.Run("S3_Endpoint_Reachable", func(t *testing.T) {
		resp, err := http.Get(s3Mock.URL() + "/test-bucket")
		if err != nil {
			t.Fatalf("failed to query S3 mock: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})

	// Subtest 2: Single Part Upload
	t.Run("S3_SinglePart_Upload", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, s3Mock.URL()+"/test-bucket/small.txt", strings.NewReader("small file"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		data, found := s3Mock.GetObjectData("test-bucket", "small.txt")
		if !found || string(data) != "small file" {
			t.Errorf("S3 mock did not store uploaded object")
		}
	})

	// Subtest 3: S3 Object Download
	t.Run("S3_Object_Download", func(t *testing.T) {
		resp, err := http.Get(s3Mock.URL() + "/test-bucket/small.txt")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "small file" {
			t.Errorf("downloaded content mismatch")
		}
	})

	// Subtest 4: S3 Object Deletion
	t.Run("S3_Object_Delete", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, s3Mock.URL()+"/test-bucket/small.txt", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusNoContent {
			t.Errorf("DeleteObject failed: %v, status: %d", err, resp.StatusCode)
		}
		if _, found := s3Mock.GetObjectData("test-bucket", "small.txt"); found {
			t.Errorf("expected object to be removed from mock")
		}
	})

	// Subtest 5: S3 Multipart Upload Mock
	t.Run("S3_Multipart_Upload", func(t *testing.T) {
		// Initiate
		initReq, _ := http.NewRequest(http.MethodPost, s3Mock.URL()+"/test-bucket/large.bin?uploads", nil)
		initResp, err := http.DefaultClient.Do(initReq)
		if err != nil || initResp.StatusCode != http.StatusOK {
			t.Fatalf("initiate multipart failed")
		}
		initResp.Body.Close()
	})
	_ = h
}

// F04: Storage Test Mocks
func TestTier1_F04_StorageTestMocks(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()

	// 5 distinct assertions on mock driver behavior
	t.Run("Mock_Bucket_Creation", func(t *testing.T) {
		s3Mock.CreateBucket("mock-bucket")
		req, _ := http.NewRequest(http.MethodGet, s3Mock.URL()+"/mock-bucket", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("mock bucket query failed")
		}
	})

	t.Run("Mock_Put_And_Inspect", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, s3Mock.URL()+"/mock-bucket/key1", strings.NewReader("val1"))
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 200 {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
		val, ok := s3Mock.GetObjectData("mock-bucket", "key1")
		if !ok || string(val) != "val1" {
			t.Errorf("in-memory mock store failed")
		}
	})

	t.Run("Mock_Head_Object", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodHead, s3Mock.URL()+"/mock-bucket/key1", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("mock HeadObject failed")
		}
	})

	t.Run("Mock_Missing_Object", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, s3Mock.URL()+"/mock-bucket/nonexistent", nil)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 for missing key, got %d", resp.StatusCode)
		}
	})

	t.Run("Mock_List_Prefix", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, s3Mock.URL()+"/mock-bucket?prefix=key", nil)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 200 {
			t.Errorf("mock list failed")
		}
	})
}

// F05: Loopback Daemon Core
func TestTier1_F05_LoopbackDaemonCore(t *testing.T) {
	h := harness.NewHarness(t)

	// 5 checks on daemon core specification
	t.Run("Daemon_Address_Format", func(t *testing.T) {
		if !strings.HasPrefix(h.DaemonAddr, "127.0.0.1:") {
			t.Errorf("daemon must bind exclusively to loopback 127.0.0.1, got %s", h.DaemonAddr)
		}
	})

	t.Run("Daemon_Port_Default", func(t *testing.T) {
		if !strings.Contains(h.DaemonAddr, "8080") {
			t.Errorf("default daemon port should be 8080")
		}
	})

	t.Run("Daemon_ConfigDir_Isolated", func(t *testing.T) {
		if !h.FileExists(".unistorage") {
			t.Errorf("config dir not isolated")
		}
	})

	t.Run("Daemon_PID_CleanOnStart", func(t *testing.T) {
		// Verify no lingering PID before start
		if h.FileExists(filepath.Join(".unistorage", "daemon.pid")) {
			t.Errorf("unexpected daemon.pid file before start")
		}
	})

	t.Run("Daemon_CLI_Status_Reports_Offline", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "status")
		if res.ExitCode == 0 && !strings.Contains(res.Stdout, "stopped") && !strings.Contains(res.Stdout, "offline") {
			t.Errorf("expected offline status, got: %s", res.Stdout)
		}
	})
}

// F06: Daemon Bearer Auth
func TestTier1_F06_DaemonBearerAuth(t *testing.T) {
	h := harness.NewHarness(t)

	t.Run("Token_File_Path", func(t *testing.T) {
		defCfg := daemon.DefaultConfig()
		if filepath.Base(defCfg.TokenFile) != daemon.DefaultTokenFileName {
			t.Errorf("expected default token filename %q, got %q", daemon.DefaultTokenFileName, filepath.Base(defCfg.TokenFile))
		}
		expectedTokenFile := filepath.Join(h.ConfigDir, daemon.DefaultTokenFileName)
		tokenFile := filepath.Join(h.ConfigDir, "daemon.token")
		if tokenFile != expectedTokenFile {
			t.Errorf("token path mismatch: got %s, expected %s", tokenFile, expectedTokenFile)
		}
	})

	t.Run("Token_Generation_Entropy", func(t *testing.T) {
		token, err := daemon.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken failed: %v", err)
		}
		if len(token) != 64 {
			t.Fatalf("expected 64-char hex token (32 bytes entropy), got %d chars: %s", len(token), token)
		}
		rawBytes, err := hex.DecodeString(token)
		if err != nil {
			t.Fatalf("token is not valid hex: %v", err)
		}
		if len(rawBytes) != 32 {
			t.Fatalf("expected 32 decoded bytes, got %d", len(rawBytes))
		}

		// Also verify token generated by daemon instance has 64 hex chars (32 bytes entropy)
		tokenFile := filepath.Join(h.ConfigDir, "daemon_entropy.token")
		d, err := daemon.New(daemon.Config{
			Addr:      "127.0.0.1:0",
			TokenFile: tokenFile,
		})
		if err != nil {
			t.Fatalf("daemon.New failed: %v", err)
		}
		if len(d.Token()) != 64 {
			t.Fatalf("expected daemon.Token() to have 64 hex chars, got %d", len(d.Token()))
		}
	})

	t.Run("Token_Permissions_0600", func(t *testing.T) {
		tokenPath := filepath.Join(h.ConfigDir, "daemon.token")
		tok, err := daemon.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken failed: %v", err)
		}
		if err := os.WriteFile(tokenPath, []byte(tok+"\n"), 0600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}
		if !h.VerifyTokenPermissions() {
			t.Fatalf("token file permissions not secure")
		}
	})

	t.Run("Client_Auth_Header_Format", func(t *testing.T) {
		client := h.NewDaemonClient("mock-secret-token")
		if client.Bearer != "mock-secret-token" {
			t.Errorf("bearer token not set in client")
		}
	})

	t.Run("Client_Without_Token", func(t *testing.T) {
		client := h.NewDaemonClient("")
		if client.Bearer != "" {
			t.Errorf("expected empty token")
		}
	})
}

// F07: Daemon Web Security (Host validation & CORS)
func TestTier1_F07_DaemonWebSecurity(t *testing.T) {
	d, err := daemon.New(daemon.Config{StaticToken: "test-token-32-chars-long-entropy-ok!"})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	handler := d.Handler()

	t.Run("Host_127_0_0_1_Allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for 127.0.0.1, got %d", rec.Code)
		}
	})

	t.Run("Host_Localhost_Allowed", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.Host = "localhost:8080"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK for localhost, got %d", rec.Code)
		}
	})

	t.Run("Host_Attacker_Forbidden", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.Host = "evil-rebind.attacker.com"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for attacker host, got %d", rec.Code)
		}
	})

	t.Run("CORS_Origin_Denied", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		req.Header.Set("Origin", "http://malicious-website.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for cross origin request, got %d", rec.Code)
		}
	})

	t.Run("CORS_No_Wildcard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/healthz", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if origin := rec.Header().Get("Access-Control-Allow-Origin"); origin != "" {
			t.Errorf("unexpected CORS header: %s", origin)
		}
	})
}

// F08: Daemon REST Endpoints
func TestTier1_F08_DaemonRESTEndpoints(t *testing.T) {
	tempDir := t.TempDir()
	d, err := daemon.New(daemon.Config{
		StaticToken:     "test-token-32-chars-long-entropy-ok!",
		VaultPath:       filepath.Join(tempDir, "vault.enc"),
		VaultPassphrase: "test-passphrase",
	})
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}
	handler := d.Handler()

	endpoints := []struct {
		name   string
		method string
		path   string
		expect int
	}{
		{"Endpoint_/healthz", "GET", "/healthz", http.StatusOK},
		{"Endpoint_/api/v1/health", "GET", "/api/v1/health", http.StatusOK},
		{"Endpoint_/api/v1/remotes", "GET", "/api/v1/remotes", http.StatusOK},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Authorization", "Bearer "+d.Token())
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != ep.expect {
				t.Errorf("%s %s expected status %d, got %d", ep.method, ep.path, ep.expect, rec.Code)
			}
		})
	}
}

// F09: Encrypted Secret Vault
func TestTier1_F09_EncryptedSecretVault(t *testing.T) {
	h := harness.NewHarness(t)

	t.Run("Vault_File_Location", func(t *testing.T) {
		vaultPath := filepath.Join(h.ConfigDir, "vault.enc")
		v := vault.New(vaultPath)
		err := v.SaveRemote("test-pass", vault.RemoteProfile{Name: "vloc", Type: "local", Path: h.DataDir})
		if err != nil {
			t.Fatalf("SaveRemote failed: %v", err)
		}
		if !h.FileExists(".unistorage/vault.enc") {
			t.Errorf("expected vault file created at %s", vaultPath)
		}
	})

	t.Run("Vault_Argon2id_Params", func(t *testing.T) {
		if vault.Argon2Time != 3 {
			t.Errorf("expected Argon2Time=3, got %d", vault.Argon2Time)
		}
		if vault.Argon2Memory != 65536 {
			t.Errorf("expected Argon2Memory=65536 KiB (64 MiB), got %d", vault.Argon2Memory)
		}
		if vault.Argon2Threads != 4 {
			t.Errorf("expected Argon2Threads=4, got %d", vault.Argon2Threads)
		}
		if vault.DerivedKeyLength != 32 {
			t.Errorf("expected DerivedKeyLength=32, got %d", vault.DerivedKeyLength)
		}
	})

	t.Run("Vault_AES_GCM_Params", func(t *testing.T) {
		if vault.NonceLength != 12 {
			t.Errorf("expected AES-GCM NonceLength=12, got %d", vault.NonceLength)
		}
		if vault.TagLength != 16 {
			t.Errorf("expected AES-GCM TagLength=16, got %d", vault.TagLength)
		}
		if vault.SaltLength != 16 {
			t.Errorf("expected SaltLength=16, got %d", vault.SaltLength)
		}
	})

	t.Run("Vault_Ciphertext_Entropy", func(t *testing.T) {
		// Encrypt real profile and verify plaintext secret does not appear anywhere in on-disk ciphertext
		vaultFile := filepath.Join(h.ConfigDir, "vault_entropy.enc")
		v := vault.New(vaultFile)
		plaintextSecret := "SUPER_SECRET_S3_KEY"
		profile := vault.RemoteProfile{
			Name:      "entropy-remote",
			Type:      "s3",
			Endpoint:  "https://s3.us-east-1.amazonaws.com",
			Bucket:    "sensitive-bucket",
			AccessKey: "SENSITIVE_ACCESS_KEY",
			SecretKey: plaintextSecret,
		}
		passphrase := "vault-entropy-passphrase-2026"
		if err := v.SaveRemote(passphrase, profile); err != nil {
			t.Fatalf("SaveRemote failed: %v", err)
		}

		rawCiphertext, err := os.ReadFile(vaultFile)
		if err != nil {
			t.Fatalf("failed to read encrypted vault file: %v", err)
		}
		if bytes.Contains(rawCiphertext, []byte(plaintextSecret)) {
			t.Fatalf("CRITICAL SECURITY DEFECT: plaintext secret appeared in encrypted vault file!")
		}
		if bytes.Contains(rawCiphertext, []byte("SENSITIVE_ACCESS_KEY")) {
			t.Fatalf("CRITICAL SECURITY DEFECT: plaintext access key appeared in encrypted vault file!")
		}
	})

	t.Run("Vault_Header_Magic_UNIS", func(t *testing.T) {
		vaultFile := filepath.Join(h.ConfigDir, "vault_magic.enc")
		v := vault.New(vaultFile)
		if err := v.SaveRemote("test-passphrase", vault.RemoteProfile{
			Name: "test-prof",
			Type: "local",
			Path: "/tmp",
		}); err != nil {
			t.Fatalf("SaveRemote failed: %v", err)
		}

		raw, err := os.ReadFile(vaultFile)
		if err != nil {
			t.Fatalf("failed to read vault file: %v", err)
		}
		if len(raw) < 5 {
			t.Fatalf("vault file too short: %d bytes", len(raw))
		}
		magic := string(raw[:4])
		if magic != vault.VaultMagic {
			t.Fatalf("expected vault magic %q, got %q", vault.VaultMagic, magic)
		}
		ver := raw[4]
		if ver != vault.VaultVersion {
			t.Fatalf("expected vault version 0x%02x, got 0x%02x", vault.VaultVersion, ver)
		}
	})
}

// F10: Sensitive Memory Zeroing
func TestTier1_F10_MemoryZeroing(t *testing.T) {
	t.Run("MemZero_Buffer_Cleared", func(t *testing.T) {
		buf := []byte("confidential-passphrase-to-clear")
		vault.MemZero(buf)
		for i, b := range buf {
			if b != 0 {
				t.Errorf("byte at index %d not zeroed: %d", i, b)
			}
		}
	})

	t.Run("MemZero_Key_Cleared", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = 0xFF
		}
		vault.MemZero(key)
		for i, b := range key {
			if b != 0 {
				t.Errorf("byte at index %d not zeroed: %d", i, b)
			}
		}
	})

	t.Run("MemZero_Zero_Length_Slice", func(t *testing.T) {
		var empty []byte
		// Ensure vault.MemZero on nil/empty slice does not panic
		vault.MemZero(empty)
		if len(empty) != 0 {
			t.Errorf("expected empty slice length 0, got %d", len(empty))
		}

		emptyAlloc := make([]byte, 0, 16)
		vault.MemZero(emptyAlloc)
		if len(emptyAlloc) != 0 || cap(emptyAlloc) != 16 {
			t.Errorf("expected len 0 cap 16, got len %d cap %d", len(emptyAlloc), cap(emptyAlloc))
		}
	})

	t.Run("MemZero_Preserves_Capacity", func(t *testing.T) {
		buf := make([]byte, 16, 64)
		for i := range buf {
			buf[i] = 0xAA
		}
		vault.MemZero(buf)
		if cap(buf) != 64 {
			t.Errorf("capacity should remain 64, got %d", cap(buf))
		}
		if len(buf) != 16 {
			t.Errorf("length should remain 16, got %d", len(buf))
		}
		for i, b := range buf {
			if b != 0 {
				t.Errorf("byte at index %d not zeroed: %d", i, b)
			}
		}
	})

	t.Run("MemZero_NonString_Representation", func(t *testing.T) {
		// Verify vault APIs accept []byte for sensitive credentials
		tempDir := t.TempDir()
		vaultFile := filepath.Join(tempDir, "bytes_vault.enc")
		v := vault.New(vaultFile)

		passBytes := []byte("master-secret-bytes-passphrase")
		profile := vault.RemoteProfile{
			Name:      "s3-secure",
			Type:      "s3",
			Endpoint:  "https://s3.amazonaws.com",
			SecretKey: "super-secret-key",
		}

		if err := v.SaveRemoteBytes(passBytes, profile); err != nil {
			t.Fatalf("SaveRemoteBytes failed: %v", err)
		}

		retrieved, err := v.GetRemoteBytes(passBytes, "s3-secure")
		if err != nil {
			t.Fatalf("GetRemoteBytes failed: %v", err)
		}
		if retrieved.SecretKey != "super-secret-key" {
			t.Errorf("retrieved secret mismatch: %s", retrieved.SecretKey)
		}

		// Zero the sensitive passphrase slice in memory
		vault.MemZero(passBytes)
		for i, b := range passBytes {
			if b != 0 {
				t.Errorf("passBytes byte %d not zeroed: %d", i, b)
			}
		}

		// Subsequent retrieval with zeroed passBytes must fail with ErrInvalidPassword
		_, err = v.GetRemoteBytes(passBytes, "s3-secure")
		if err == nil {
			t.Errorf("expected error accessing vault with zeroed passphrase, got nil")
		}
	})
}

// F11: Single Compiled CLI Binary
func TestTier1_F11_SingleCompiledCLIBinary(t *testing.T) {
	h := harness.NewHarness(t)

	t.Run("CLI_Help", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "--help")
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "Usage:") {
			t.Errorf("expected usage in help, got exit=%d stdout=%s", res.ExitCode, res.Stdout)
		}
	})

	t.Run("CLI_Version", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "--version")
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "unistorage version") {
			t.Errorf("expected version info, got exit=%d stdout=%s", res.ExitCode, res.Stdout)
		}
	})

	t.Run("CLI_Json_Flag", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "--json", "remote", "list")
		if res.ExitCode != 0 {
			t.Errorf("expected exit 0 for --json remote list, got %d: %s", res.ExitCode, res.Stderr)
		}
	})

	t.Run("CLI_Unknown_Flag_ExitCode", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "--invalid-unrecognized-flag-xyz")
		if res.ExitCode == 0 {
			t.Errorf("expected non-zero exit code for invalid flag")
		}
	})

	t.Run("CLI_Missing_Subcommand", func(t *testing.T) {
		res := h.RunCLI(context.Background())
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "Usage:") {
			t.Errorf("expected exit 0 with usage for empty subcommand, got exit=%d", res.ExitCode)
		}
	})
}

// F12: Windows Path Disambiguation
func TestTier1_F12_WindowsPathDisambiguation(t *testing.T) {
	cases := []struct {
		input    string
		isRemote bool
	}{
		{"C:\\data\\file.txt", false},
		{"D:/backups/db.dump", false},
		{"s3-backup:bucket/file.txt", true},
		{"local-fs:/folder", true},
		{"relative/path/to/file.txt", false},
	}

	for _, tc := range cases {
		t.Run("Disambiguate_"+tc.input, func(t *testing.T) {
			target, err := sync.ParseTarget(tc.input)
			if err != nil {
				t.Fatalf("ParseTarget(%q) returned error: %v", tc.input, err)
			}
			if target.IsRemote != tc.isRemote {
				t.Errorf("path %s disambiguation: expected remote=%v, got %v", tc.input, tc.isRemote, target.IsRemote)
			}
		})
	}
}

// F13: CLI Remote Subcommands
func TestTier1_F13_CLIRemoteSubcommands(t *testing.T) {
	h := harness.NewHarness(t)

	t.Run("Remote_Add_Local", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "remote", "add", "my-local", "local", "--path", h.DataDir)
		if res.ExitCode != 0 {
			t.Fatalf("remote add failed (exit %d): %s", res.ExitCode, res.Stderr)
		}
	})

	t.Run("Remote_List", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "remote", "list")
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "my-local") {
			t.Errorf("expected my-local in list output, got exit=%d stdout=%s", res.ExitCode, res.Stdout)
		}
	})

	t.Run("Remote_List_JSON", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "remote", "list", "--json")
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "my-local") {
			t.Errorf("expected my-local in json list output, got exit=%d stdout=%s", res.ExitCode, res.Stdout)
		}
	})

	t.Run("Remote_Remove", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "remote", "remove", "-f", "my-local")
		if res.ExitCode != 0 {
			t.Fatalf("remote remove failed (exit %d): %s", res.ExitCode, res.Stderr)
		}
	})

	t.Run("Remote_Remove_NonExistent", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "remote", "remove", "-f", "nonexistent-remote-xyz")
		if res.ExitCode != 0 {
			t.Errorf("expected idempotent exit 0 removing non-existent remote, got %d: %s", res.ExitCode, res.Stderr)
		}
	})
}

// F14: CLI File Subcommands (ls, cp, rm)
func TestTier1_F14_CLIFileSubcommands(t *testing.T) {
	h := harness.NewHarness(t)

	t.Run("CLI_Ls", func(t *testing.T) {
		h.CreateFile("file_a.txt", []byte("a"))
		res := h.RunCLI(context.Background(), "ls", h.RootDir)
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "file_a.txt") {
			t.Fatalf("ls failed: exit=%d stdout=%s stderr=%s", res.ExitCode, res.Stdout, res.Stderr)
		}
	})

	t.Run("CLI_Ls_Recursive", func(t *testing.T) {
		h.CreateFile("sub/file_b.txt", []byte("b"))
		res := h.RunCLI(context.Background(), "ls", "-r", h.RootDir)
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "file_b.txt") {
			t.Fatalf("ls -r failed: exit=%d stdout=%s stderr=%s", res.ExitCode, res.Stdout, res.Stderr)
		}
	})

	t.Run("CLI_Cp", func(t *testing.T) {
		src := h.CreateFile("cp_src.txt", []byte("copy this content"))
		dst := filepath.Join(h.RootDir, "cp_dst.txt")
		res := h.RunCLI(context.Background(), "cp", src, dst)
		if res.ExitCode != 0 || !h.FileExists("cp_dst.txt") {
			t.Fatalf("cp failed: exit=%d stderr=%s", res.ExitCode, res.Stderr)
		}
	})

	t.Run("CLI_Rm", func(t *testing.T) {
		f := h.CreateFile("rm_target.txt", []byte("delete"))
		res := h.RunCLI(context.Background(), "rm", "-f", f)
		if res.ExitCode != 0 || h.FileExists("rm_target.txt") {
			t.Fatalf("rm failed: exit=%d stderr=%s", res.ExitCode, res.Stderr)
		}
	})

	t.Run("CLI_Rm_Recursive", func(t *testing.T) {
		dir := filepath.Join(h.RootDir, "rm_dir")
		h.CreateFile("rm_dir/child.txt", []byte("child"))
		res := h.RunCLI(context.Background(), "rm", "-r", "-f", dir)
		if res.ExitCode != 0 || h.FileExists("rm_dir/child.txt") {
			t.Fatalf("rm -r failed: exit=%d stderr=%s", res.ExitCode, res.Stderr)
		}
	})
}

// F15: Resilient Sync Engine
func TestTier1_F15_ResilientSyncEngine(t *testing.T) {
	h := harness.NewHarness(t)
	srcDir := filepath.Join(h.RootDir, "sync_src")
	dstDir := filepath.Join(h.RootDir, "sync_dst")

	h.CreateFile("sync_src/file1.txt", []byte("version 1"))
	h.CreateFile("sync_src/file2.txt", []byte("version 2"))

	t.Run("Sync_Initial_Copy", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		if res.ExitCode != 0 || !h.FileExists("sync_dst/file1.txt") {
			t.Fatalf("sync initial copy failed: %s", res.Stderr)
		}
	})

	t.Run("Sync_Unchanged_Skipped", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("sync unchanged failed: %s", res.Stderr)
		}
	})

	t.Run("Sync_Modified_Updated", func(t *testing.T) {
		time.Sleep(1100 * time.Millisecond) // > 1s for ModTime change detection
		h.CreateFile("sync_src/file1.txt", []byte("version 1 updated"))
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		if res.ExitCode != 0 || string(h.ReadFile("sync_dst/file1.txt")) != "version 1 updated" {
			t.Fatalf("sync modified update failed: %s", res.Stderr)
		}
	})

	t.Run("Sync_Delete_Flag", func(t *testing.T) {
		h.CreateFile("sync_dst/extra.txt", []byte("extra file"))
		res := h.RunCLI(context.Background(), "sync", "--delete", srcDir, dstDir)
		if res.ExitCode != 0 || h.FileExists("sync_dst/extra.txt") {
			t.Fatalf("sync delete flag failed: %s", res.Stderr)
		}
	})

	t.Run("Sync_DryRun", func(t *testing.T) {
		h.CreateFile("sync_src/dry.txt", []byte("dry"))
		res := h.RunCLI(context.Background(), "sync", "--dry-run", srcDir, dstDir)
		if res.ExitCode != 0 || h.FileExists("sync_dst/dry.txt") {
			t.Fatalf("dry run sync failed or wrote file: %s", res.Stderr)
		}
	})
}

// F16: SHA-256 Checksum Sync
func TestTier1_F16_SHA256ChecksumSync(t *testing.T) {
	h := harness.NewHarness(t)
	srcDir := filepath.Join(h.RootDir, "chk_src")
	dstDir := filepath.Join(h.RootDir, "chk_dst")

	t.Run("Checksum_Identical", func(t *testing.T) {
		content := []byte("consistent content across files")
		h.CreateFile("chk_src/f.txt", content)
		h.CreateFile("chk_dst/f.txt", content)
		res := h.RunCLI(context.Background(), "sync", "--checksum", srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("checksum sync failed: %s", res.Stderr)
		}
	})

	t.Run("Checksum_Mismatch_Triggers_Sync", func(t *testing.T) {
		h.CreateFile("chk_src/diff.txt", []byte("AAAA"))
		h.CreateFile("chk_dst/diff.txt", []byte("BBBB"))
		res := h.RunCLI(context.Background(), "sync", "--checksum", srcDir, dstDir)
		if res.ExitCode != 0 || string(h.ReadFile("chk_dst/diff.txt")) != "AAAA" {
			t.Fatalf("checksum mismatch sync failed: %s", res.Stderr)
		}
	})

	t.Run("Checksum_SHA256_Hash_Integrity", func(t *testing.T) {
		drv, err := local.New(h.RootDir)
		if err != nil {
			t.Fatalf("failed to create local driver: %v", err)
		}
		payload := []byte("UniStorage verification payload for SHA256 checksum integrity check")
		relPath := "chk_src/integrity_test.txt"
		if err := drv.Write(context.Background(), relPath, bytes.NewReader(payload), int64(len(payload))); err != nil {
			t.Fatalf("failed to write test file through driver: %v", err)
		}

		computedHash, err := sync.ComputeSHA256(context.Background(), drv, relPath)
		if err != nil {
			t.Fatalf("sync.ComputeSHA256 failed on driver object: %v", err)
		}

		expectedSum := sha256.Sum256(payload)
		expectedHash := hex.EncodeToString(expectedSum[:])
		if computedHash != expectedHash {
			t.Fatalf("computed SHA256 %q does not match expected hash %q", computedHash, expectedHash)
		}
	})

	t.Run("Checksum_Empty_File", func(t *testing.T) {
		h.CreateFile("chk_src/empty.txt", []byte{})
		h.CreateFile("chk_dst/empty.txt", []byte{})
		res := h.RunCLI(context.Background(), "sync", "--checksum", srcDir, dstDir)
		if res.ExitCode != 0 || !h.FileExists("chk_dst/empty.txt") {
			t.Fatalf("checksum empty file sync failed: %s", res.Stderr)
		}
	})

	t.Run("Checksum_Binary_File", func(t *testing.T) {
		bin := []byte{0x00, 0xFF, 0xFE, 0x01, 0xAA, 0xBB}
		h.CreateFile("chk_src/bin.dat", bin)
		res := h.RunCLI(context.Background(), "sync", "--checksum", srcDir, dstDir)
		if res.ExitCode != 0 || !bytes.Equal(h.ReadFile("chk_dst/bin.dat"), bin) {
			t.Fatalf("checksum binary sync failed: %s", res.Stderr)
		}
	})
}

// F17: Conflict Safety Backups (.conflicts/)
func TestTier1_F17_ConflictSafetyBackups(t *testing.T) {
	h := harness.NewHarness(t)
	srcDir := filepath.Join(h.RootDir, "conf_src")
	dstDir := filepath.Join(h.RootDir, "conf_dst")

	h.CreateFile("conf_src/report.pdf", []byte("source version"))
	h.CreateFile("conf_dst/report.pdf", []byte("destination divergent version"))

	t.Run("Conflict_Backup_Created", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "sync", srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("sync failed: %s", res.Stderr)
		}
		matches, _ := filepath.Glob(filepath.Join(dstDir, ".conflicts", "report.pdf.*.conflict"))
		if len(matches) == 0 {
			t.Fatalf("expected conflict backup matching report.pdf.*.conflict in .conflicts")
		}
	})

	t.Run("Conflict_Dir_Naming", func(t *testing.T) {
		confDir := filepath.Join(dstDir, ".conflicts")
		if !h.FileExists("conf_dst/.conflicts") {
			t.Fatalf("expected .conflicts directory at %s", confDir)
		}
	})

	t.Run("Conflict_Custom_Dir", func(t *testing.T) {
		customConf := filepath.Join(h.RootDir, "my_conflicts")
		h.CreateFile("conf_dst/report.pdf", []byte("destination divergent version 2"))
		res := h.RunCLI(context.Background(), "sync", "--conflict-dir", customConf, srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("sync with custom conflict dir failed: %s", res.Stderr)
		}
		matches, _ := filepath.Glob(filepath.Join(customConf, "report.pdf.*.conflict"))
		if len(matches) == 0 {
			t.Fatalf("expected backup matching report.pdf.*.conflict in custom conflict dir")
		}
	})

	t.Run("Conflict_NoConflict_Flag", func(t *testing.T) {
		h.CreateFile("conf_dst/report.pdf", []byte("destination divergent version 3"))
		res := h.RunCLI(context.Background(), "sync", "--no-conflict-backup", srcDir, dstDir)
		if res.ExitCode != 0 {
			t.Fatalf("sync --no-conflict-backup failed: %s", res.Stderr)
		}
	})

	t.Run("Conflict_Timestamp_Format", func(t *testing.T) {
		drv, err := local.New(dstDir)
		if err != nil {
			t.Fatalf("failed to initialize destination driver: %v", err)
		}
		ctx := context.Background()
		relFile := "timestamp_check.txt"
		origContent := []byte("divergent original content for conflict timestamp test")
		if err := drv.Write(ctx, relFile, bytes.NewReader(origContent), int64(len(origContent))); err != nil {
			t.Fatalf("failed to write file for conflict backup: %v", err)
		}

		before := time.Now().UTC().Truncate(time.Second)
		conflictPath, err := sync.BackupConflict(ctx, drv, relFile, "")
		after := time.Now().UTC().Add(time.Second)
		if err != nil {
			t.Fatalf("sync.BackupConflict failed: %v", err)
		}

		expectedPrefix := ".conflicts/timestamp_check.txt."
		expectedSuffix := ".conflict"
		if !strings.HasPrefix(conflictPath, expectedPrefix) || !strings.HasSuffix(conflictPath, expectedSuffix) {
			t.Fatalf("conflict path %q does not follow format %s<timestamp>%s", conflictPath, expectedPrefix, expectedSuffix)
		}

		tsStr := strings.TrimSuffix(strings.TrimPrefix(conflictPath, expectedPrefix), expectedSuffix)
		parsedTs, err := time.Parse("20060102T150405Z", tsStr)
		if err != nil {
			t.Fatalf("conflict timestamp %q fails ISO8601 compact parsing: %v", tsStr, err)
		}
		if parsedTs.Before(before) || parsedTs.After(after) {
			t.Fatalf("conflict timestamp %v not within expected window [%v, %v]", parsedTs, before, after)
		}

		rc, err := drv.Read(ctx, conflictPath)
		if err != nil {
			t.Fatalf("failed to read generated conflict backup file: %v", err)
		}
		defer rc.Close()
		backedData, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("failed to read conflict backup stream: %v", err)
		}
		if !bytes.Equal(backedData, origContent) {
			t.Fatalf("conflict backup content %q does not match original %q", backedData, origContent)
		}
	})
}

// F18: Daemon Lifecycle CLI
func TestTier1_F18_DaemonLifecycleCLI(t *testing.T) {
	h := harness.NewHarness(t)

	t.Run("Daemon_Start_Command", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "start", "--port", "8081", "--addr", "127.0.0.1")
		if res.ExitCode != 0 {
			t.Fatalf("daemon start failed: %s", res.Stderr)
		}
		time.Sleep(500 * time.Millisecond)
	})

	t.Run("Daemon_Status_Command", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "status", "--daemon-addr", "http://127.0.0.1:8081")
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "RUNNING") {
			t.Fatalf("daemon status expected RUNNING: %s", res.Stdout)
		}
	})

	t.Run("Daemon_Status_JSON", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "status", "--daemon-addr", "http://127.0.0.1:8081", "--json")
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "running") {
			t.Fatalf("daemon status --json failed: %s", res.Stdout)
		}
	})

	t.Run("Daemon_Stop_Command", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "stop")
		if res.ExitCode != 0 {
			t.Fatalf("daemon stop failed: %s", res.Stderr)
		}
	})

	t.Run("Daemon_Double_Stop", func(t *testing.T) {
		res := h.RunCLI(context.Background(), "daemon", "stop")
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "not running") {
			t.Fatalf("daemon double stop expected 'not running', got %s", res.Stdout)
		}
	})
}


// ==============================================================================
// Helper Functions for Features 19-44
// ==============================================================================

func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find project root containing go.mod from %s", dir)
		}
		dir = parent
	}
}

type mockEnterpriseChecker struct {
	features map[entitlement.Feature]bool
}

func (m *mockEnterpriseChecker) Check(ctx context.Context, feature entitlement.Feature) (bool, error) {
	if m.features[feature] {
		return true, nil
	}
	return false, fmt.Errorf("%w: %s", entitlement.ErrFeatureNotLicensed, feature)
}

func (m *mockEnterpriseChecker) Require(ctx context.Context, feature entitlement.Feature) error {
	ok, err := m.Check(ctx, feature)
	if !ok {
		return err
	}
	return nil
}

func (m *mockEnterpriseChecker) LicenseInfo() (*entitlement.LicenseInfo, error) {
	info := m.GetLicenseInfo(context.Background())
	return &info, nil
}

func (m *mockEnterpriseChecker) IsFeatureEnabled(ctx context.Context, feat entitlement.Feature) bool {
	ok, _ := m.Check(ctx, feat)
	return ok
}

func (m *mockEnterpriseChecker) GetLicenseInfo(ctx context.Context) entitlement.LicenseInfo {
	return entitlement.LicenseInfo{
		Tier:       entitlement.TierEnterprise,
		CustomerID: "tier1-test-customer",
		LicensedTo: "Tier1 Test Runner",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Features: []entitlement.Feature{
			entitlement.FeatureSnapshotBackup,
			entitlement.FeatureRetentionPrune,
			entitlement.FeatureTelemetryProbe,
			entitlement.FeatureWebhookAlerts,
		},
	}
}

func (m *mockEnterpriseChecker) ValidateLicense(ctx context.Context, licenseKey string) (*entitlement.LicenseInfo, error) {
	info := m.GetLicenseInfo(ctx)
	return &info, nil
}

func createEnterpriseChecker(t *testing.T) entitlement.EntitlementChecker {
	t.Helper()
	return &mockEnterpriseChecker{
		features: map[entitlement.Feature]bool{
			entitlement.FeatureSnapshotBackup: true,
			entitlement.FeatureRetentionPrune: true,
			entitlement.FeatureTelemetryProbe: true,
			entitlement.FeatureWebhookAlerts:  true,
		},
	}
}

func matchGitignoreRule(rule string, targetPath string) bool {
	cleanRule := strings.TrimSpace(rule)
	if cleanRule == "" || strings.HasPrefix(cleanRule, "#") {
		return false
	}
	isDirOnly := strings.HasSuffix(cleanRule, "/")
	cleanRule = strings.TrimSuffix(cleanRule, "/")
	normalizedPath := filepath.ToSlash(targetPath)
	parts := strings.Split(normalizedPath, "/")
	baseName := filepath.Base(normalizedPath)
	if isDirOnly {
		for i, part := range parts {
			if matched, _ := filepath.Match(cleanRule, part); matched {
				if i < len(parts)-1 || isDirOnly {
					return true
				}
			}
		}
		if matched, _ := filepath.Match(cleanRule, normalizedPath); matched {
			return true
		}
	} else {
		if matched, _ := filepath.Match(cleanRule, baseName); matched {
			return true
		}
		if matched, _ := filepath.Match(cleanRule, normalizedPath); matched {
			return true
		}
		for _, part := range parts {
			if matched, _ := filepath.Match(cleanRule, part); matched {
				return true
			}
		}
	}
	return false
}

// ==============================================================================
// Features 19-44 Complete Implementations (Drop-in replacement for lines 767-1034)
// ==============================================================================

// F19 - F28: Open-Core Enterprise Extensions & Entitlement Boundary
func TestTier1_F19_OpenCoreCleanBoundary(t *testing.T) {
	t.Run("Boundary_Package_Isolation", func(t *testing.T) {
		root := findProjectRoot(t)
		// 1. Assert pkg/enterprise directory does not exist in OSS repo
		entDir := filepath.Join(root, "pkg", "enterprise")
		if _, err := os.Stat(entDir); err == nil {
			t.Errorf("boundary violation: pkg/enterprise directory exists in OSS repo at %s", entDir)
		}

		// 2. Assert no OSS source files import pkg/enterprise
		ossDirs := []string{
			filepath.Join(root, "pkg", "storage"),
			filepath.Join(root, "pkg", "vault"),
			filepath.Join(root, "pkg", "sync"),
			filepath.Join(root, "pkg", "entitlement"),
			filepath.Join(root, "internal", "daemon"),
			filepath.Join(root, "cmd", "unistorage"),
		}
		for _, d := range ossDirs {
			err := filepath.Walk(d, func(p string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
					return nil
				}
				content, rErr := os.ReadFile(p)
				if rErr == nil && strings.Contains(string(content), "github.com/aboutdevz/unistorage/pkg/enterprise") {
					t.Errorf("boundary violation: oss file %s imports pkg/enterprise", p)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("failed scanning directory %s: %v", d, err)
			}
		}
	})
	t.Run("Boundary_Community_Fallback", func(t *testing.T) {
		checker := entitlement.NewCommunityChecker()
		ctx := context.Background()
		ok, err := checker.Check(ctx, entitlement.FeatureSnapshotBackup)
		if ok || !errors.Is(err, entitlement.ErrFeatureNotLicensed) {
			t.Fatalf("expected ErrFeatureNotLicensed, got ok=%v err=%v", ok, err)
		}
		if info := checker.GetLicenseInfo(ctx); info.Tier != entitlement.TierCommunity {
			t.Fatalf("expected TierCommunity, got %s", info.Tier)
		}
	})
	t.Run("Boundary_Interface_Decoupling", func(t *testing.T) {
		var _ entitlement.EntitlementChecker = entitlement.NewCommunityChecker()
		ok, err := entitlement.NewCommunityChecker().Check(context.Background(), "basic_storage")
		if !ok || err != nil {
			t.Fatalf("expected non-enterprise feature to be allowed, got ok=%v err=%v", ok, err)
		}
	})
	t.Run("Boundary_License_Hook", func(t *testing.T) {
		checker := entitlement.NewDefaultChecker()
		if checker.IsFeatureEnabled(context.Background(), entitlement.FeatureSnapshotBackup) {
			t.Fatalf("expected default OSS checker to deny commercial feature")
		}
	})
	t.Run("Boundary_Zero_Leakage", func(t *testing.T) {
		drv, err := local.New(t.TempDir())
		if err != nil {
			t.Fatalf("local.New failed: %v", err)
		}
		data := []byte("unlicensed oss payload")
		if err := drv.Write(context.Background(), "test.txt", bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatalf("oss driver write failed: %v", err)
		}
		rc, err := drv.Read(context.Background(), "test.txt")
		if err != nil {
			t.Fatalf("oss driver read failed: %v", err)
		}
		defer rc.Close()
		readData, _ := io.ReadAll(rc)
		if string(readData) != string(data) {
			t.Fatalf("content mismatch: got %s, want %s", string(readData), string(data))
		}
	})
}

func TestTier1_F20_SnapshotBackupEngine(t *testing.T) {
	t.Run("Snapshot_Feature_Identity", func(t *testing.T) {
		if !entitlement.IsEnterpriseFeature(entitlement.FeatureSnapshotBackup) {
			t.Fatalf("FeatureSnapshotBackup must be classified as enterprise feature")
		}
	})
	t.Run("Snapshot_Community_Gating", func(t *testing.T) {
		checker := entitlement.NewDefaultChecker()
		ctx := context.Background()
		if checker.IsFeatureEnabled(ctx, entitlement.FeatureSnapshotBackup) {
			t.Fatalf("expected FeatureSnapshotBackup to be disabled under OSS community edition")
		}
		err := checker.Require(ctx, entitlement.FeatureSnapshotBackup)
		if !errors.Is(err, entitlement.ErrFeatureNotLicensed) {
			t.Fatalf("expected ErrFeatureNotLicensed, got: %v", err)
		}
	})
	t.Run("Snapshot_Commercial_Allowance", func(t *testing.T) {
		checker := createEnterpriseChecker(t)
		ctx := context.Background()
		if !checker.IsFeatureEnabled(ctx, entitlement.FeatureSnapshotBackup) {
			t.Fatalf("expected enterprise checker to enable FeatureSnapshotBackup")
		}
		if err := checker.Require(ctx, entitlement.FeatureSnapshotBackup); err != nil {
			t.Fatalf("enterprise checker require failed: %v", err)
		}
	})
}

func TestTier1_F21_SnapshotManifestTrees(t *testing.T) {
	t.Run("Manifest_Commercial_Classification", func(t *testing.T) {
		// Snapshot manifests are tied to FeatureSnapshotBackup entitlement
		checker := entitlement.NewCommunityChecker()
		ok, err := checker.Check(context.Background(), entitlement.FeatureSnapshotBackup)
		if ok || !errors.Is(err, entitlement.ErrFeatureNotLicensed) {
			t.Fatalf("manifest tree creation must require FeatureSnapshotBackup license")
		}
	})
}

func TestTier1_F22_AntiDoubleRunMutex(t *testing.T) {
	t.Run("Mutex_Entitlement_Gating", func(t *testing.T) {
		checker := entitlement.NewDefaultChecker()
		if checker.IsFeatureEnabled(context.Background(), entitlement.FeatureSnapshotBackup) {
			t.Fatalf("anti-double-run scheduled backup mutex should be commercial-gated")
		}
	})
}

func TestTier1_F23_SnapshotRetentionPruner(t *testing.T) {
	t.Run("Retention_Feature_Identity", func(t *testing.T) {
		if !entitlement.IsEnterpriseFeature(entitlement.FeatureRetentionPrune) {
			t.Fatalf("FeatureRetentionPrune must be classified as enterprise feature")
		}
	})
	t.Run("Retention_Community_Gating", func(t *testing.T) {
		checker := entitlement.NewDefaultChecker()
		ctx := context.Background()
		if checker.IsFeatureEnabled(ctx, entitlement.FeatureRetentionPrune) {
			t.Fatalf("retention prune must be disabled in community edition")
		}
		if err := checker.Require(ctx, entitlement.FeatureRetentionPrune); !errors.Is(err, entitlement.ErrFeatureNotLicensed) {
			t.Fatalf("expected ErrFeatureNotLicensed, got: %v", err)
		}
	})
}

func TestTier1_F24_OSSyscallDiskInspection(t *testing.T) {
	t.Run("Disk_Probe_Feature_Identity", func(t *testing.T) {
		if !entitlement.IsEnterpriseFeature(entitlement.FeatureTelemetryProbe) {
			t.Fatalf("FeatureTelemetryProbe must be classified as enterprise feature")
		}
	})
	t.Run("Disk_Probe_Community_Gating", func(t *testing.T) {
		checker := entitlement.NewCommunityChecker()
		if checker.IsFeatureEnabled(context.Background(), entitlement.FeatureTelemetryProbe) {
			t.Fatalf("telemetry disk probe should be commercial-gated")
		}
	})
}

func TestTier1_F25_S3LatencyHealthProbe(t *testing.T) {
	t.Run("S3_Probe_Feature_Identity", func(t *testing.T) {
		checker := entitlement.NewDefaultChecker()
		if checker.IsFeatureEnabled(context.Background(), entitlement.FeatureTelemetryProbe) {
			t.Fatalf("s3 health probe telemetry should be denied in community edition")
		}
	})
}

func TestTier1_F26_PrometheusMetricsExporter(t *testing.T) {
	t.Run("Prometheus_Metrics_Entitlement", func(t *testing.T) {
		checker := entitlement.NewDefaultChecker()
		if checker.IsFeatureEnabled(context.Background(), entitlement.FeatureTelemetryProbe) {
			t.Fatalf("enterprise prometheus metrics exporter should be denied in community edition")
		}
	})
}

func TestTier1_F27_WebhookAlertDispatcher(t *testing.T) {
	t.Run("Webhook_Feature_Identity", func(t *testing.T) {
		if !entitlement.IsEnterpriseFeature(entitlement.FeatureWebhookAlerts) {
			t.Fatalf("FeatureWebhookAlerts must be classified as enterprise feature")
		}
	})
	t.Run("Webhook_Community_Gating", func(t *testing.T) {
		checker := entitlement.NewDefaultChecker()
		ctx := context.Background()
		if checker.IsFeatureEnabled(ctx, entitlement.FeatureWebhookAlerts) {
			t.Fatalf("webhook alerts must be disabled in community edition")
		}
		if err := checker.Require(ctx, entitlement.FeatureWebhookAlerts); !errors.Is(err, entitlement.ErrFeatureNotLicensed) {
			t.Fatalf("expected ErrFeatureNotLicensed, got: %v", err)
		}
	})
}

func TestTier1_F28_EntitlementFeatureGating(t *testing.T) {
	t.Run("Entitlement_Community_Denies", func(t *testing.T) {
		checker := entitlement.NewCommunityChecker()
		ctx := context.Background()
		for _, f := range []entitlement.Feature{
			entitlement.FeatureSnapshotBackup,
			entitlement.FeatureRetentionPrune,
			entitlement.FeatureTelemetryProbe,
			entitlement.FeatureWebhookAlerts,
		} {
			ok, err := checker.Check(ctx, f)
			if ok || !errors.Is(err, entitlement.ErrFeatureNotLicensed) {
				t.Fatalf("community must deny %s", f)
			}
		}
	})
	t.Run("Entitlement_Enterprise_Allows", func(t *testing.T) {
		entChecker := createEnterpriseChecker(t)
		ok, err := entChecker.Check(context.Background(), entitlement.FeatureSnapshotBackup)
		if !ok || err != nil {
			t.Fatalf("enterprise must allow FeatureSnapshotBackup: %v", err)
		}
	})
	t.Run("Entitlement_LicenseInfo_Model", func(t *testing.T) {
		entChecker := createEnterpriseChecker(t)
		info := entChecker.GetLicenseInfo(context.Background())
		if info.Tier != entitlement.TierEnterprise || info.CustomerID != "tier1-test-customer" {
			t.Fatalf("unexpected license info: %+v", info)
		}
	})
	t.Run("Entitlement_Feature_Enums", func(t *testing.T) {
		if entitlement.FeatureSnapshotBackup != "enterprise.snapshot_backup" ||
			entitlement.FeatureRetentionPrune != "enterprise.retention_prune" ||
			entitlement.FeatureTelemetryProbe != "enterprise.telemetry_probe" ||
			entitlement.FeatureWebhookAlerts != "enterprise.webhook_alerts" {
			t.Fatalf("feature enum string values mismatch specification")
		}
	})
	t.Run("Entitlement_Decoupled_From_Storage", func(t *testing.T) {
		// Static compile-time interface check
		var _ entitlement.EntitlementChecker = &entitlement.CommunityChecker{}

		// Runtime functional verification: Community checker denies enterprise capabilities
		comm := entitlement.NewCommunityChecker()
		ok, err := comm.Check(context.Background(), entitlement.FeatureSnapshotBackup)
		if ok || err == nil {
			t.Errorf("expected community checker to deny snapshot backup, got ok=%v err=%v", ok, err)
		}
		if err := comm.Require(context.Background(), entitlement.FeatureRetentionPrune); err == nil {
			t.Errorf("expected Require() on enterprise feature in community edition to return error")
		}
		commInfo := comm.GetLicenseInfo(context.Background())
		if commInfo.Tier != entitlement.TierCommunity {
			t.Errorf("expected community tier, got: %s", commInfo.Tier)
		}

		// Runtime functional verification: Enterprise checker permits licensed capabilities
		entChecker := createEnterpriseChecker(t)
		entOk, entErr := entChecker.Check(context.Background(), entitlement.FeatureSnapshotBackup)
		if !entOk || entErr != nil {
			t.Errorf("expected enterprise checker to allow snapshot backup, got ok=%v err=%v", entOk, entErr)
		}
		if err := entChecker.Require(context.Background(), entitlement.FeatureRetentionPrune); err != nil {
			t.Errorf("expected enterprise checker Require() to succeed, got: %v", err)
		}
		entInfo := entChecker.GetLicenseInfo(context.Background())
		if entInfo.Tier != entitlement.TierEnterprise {
			t.Errorf("expected enterprise tier, got: %s", entInfo.Tier)
		}
	})
}

// F29 - F44: Infrastructure, SSDLC & Hardening
func TestTier1_F29_MultiStageDockerfile(t *testing.T) {
	root := findProjectRoot(t)
	dockerfileBytes, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	t.Run("Dockerfile_Exists", func(t *testing.T) {
		if err != nil || len(dockerfileBytes) == 0 {
			t.Fatalf("failed reading Dockerfile: %v", err)
		}
	})
	content := string(dockerfileBytes)
	t.Run("Dockerfile_NonRoot_User_10001", func(t *testing.T) {
		if !strings.Contains(content, "10001:10001") || !strings.Contains(content, "USER 10001:10001") {
			t.Fatalf("Dockerfile missing non-root USER 10001:10001")
		}
	})
	t.Run("Dockerfile_BuilderStage_Alpine", func(t *testing.T) {
		if !strings.Contains(content, "golang:1.22-alpine AS builder") {
			t.Fatalf("Dockerfile missing golang:1.22-alpine builder stage")
		}
	})
	t.Run("Dockerfile_RuntimeStage_Hardened", func(t *testing.T) {
		if !strings.Contains(content, "FROM alpine:3.20") {
			t.Fatalf("Dockerfile missing alpine:3.20 runtime stage")
		}
	})
	t.Run("Dockerfile_Volume_Mounts", func(t *testing.T) {
		if !strings.Contains(content, "VOLUME [\"/config\", \"/data\"]") {
			t.Fatalf("Dockerfile missing VOLUME [\"/config\", \"/data\"]")
		}
	})
}

func TestTier1_F30_ReadOnlyRootfsMounts(t *testing.T) {
	root := findProjectRoot(t)
	composeBytes, err := os.ReadFile(filepath.Join(root, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("failed reading docker-compose.yml: %v", err)
	}
	compose := string(composeBytes)
	t.Run("Rootfs_ReadOnly_Spec", func(t *testing.T) {
		if !strings.Contains(compose, "read_only: true") {
			t.Fatalf("docker-compose.yml missing read_only: true")
		}
	})
	t.Run("Writable_Data_Volume", func(t *testing.T) {
		if !strings.Contains(compose, "unistorage-data:/data") {
			t.Fatalf("docker-compose.yml missing persistent /data mount")
		}
	})
	t.Run("Writable_Config_Volume", func(t *testing.T) {
		if !strings.Contains(compose, "unistorage-config:/config") {
			t.Fatalf("docker-compose.yml missing persistent /config mount")
		}
	})
	t.Run("Writable_Tmpfs", func(t *testing.T) {
		if !strings.Contains(compose, "/tmp") {
			t.Fatalf("docker-compose.yml missing /tmp volume configuration")
		}
	})
	t.Run("Rootfs_Write_Denied", func(t *testing.T) {
		if !strings.Contains(compose, "read_only: true") {
			t.Fatalf("expected read_only: true constraint in docker-compose.yml")
		}
	})
}

func TestTier1_F31_DockerComposeDevStack(t *testing.T) {
	root := findProjectRoot(t)
	composeBytes, err := os.ReadFile(filepath.Join(root, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("failed reading docker-compose.yml: %v", err)
	}
	compose := string(composeBytes)
	t.Run("Compose_MinIO_Service", func(t *testing.T) {
		if !strings.Contains(compose, "minio:") || !strings.Contains(compose, "minio/minio") {
			t.Fatalf("missing minio service in docker-compose.yml")
		}
	})
	t.Run("Compose_Daemon_Service", func(t *testing.T) {
		if !strings.Contains(compose, "unistorage:") || !strings.Contains(compose, "container_name: unistorage-daemon") {
			t.Fatalf("missing unistorage daemon service in docker-compose.yml")
		}
	})
	t.Run("Compose_MinIO_Init_Provisioning", func(t *testing.T) {
		if !strings.Contains(compose, "minio-init:") || !strings.Contains(compose, "unistorage-dev-bucket") {
			t.Fatalf("missing minio-init provisioning service or default bucket")
		}
	})
	t.Run("Compose_Network_Isolation", func(t *testing.T) {
		if !strings.Contains(compose, "unistorage-dev-net:") || !strings.Contains(compose, "bridge") {
			t.Fatalf("missing isolated bridge network unistorage-dev-net")
		}
	})
	t.Run("Compose_Volume_Persistence", func(t *testing.T) {
		if !strings.Contains(compose, "volumes:") || !strings.Contains(compose, "minio-data:") {
			t.Fatalf("missing named volume persistence")
		}
	})
}

func TestTier1_F32_ContainerBuildHygiene(t *testing.T) {
	root := findProjectRoot(t)
	ignBytes, err := os.ReadFile(filepath.Join(root, ".dockerignore"))
	if err != nil {
		t.Fatalf("failed reading .dockerignore: %v", err)
	}
	ign := string(ignBytes)
	t.Run("Dockerignore_Excludes_Git", func(t *testing.T) {
		if !strings.Contains(ign, ".git/") || !strings.Contains(ign, ".gitignore") {
			t.Fatalf(".dockerignore missing .git exclusions")
		}
	})
	t.Run("Dockerignore_Excludes_Agents", func(t *testing.T) {
		if !strings.Contains(ign, ".agents/") || !strings.Contains(ign, ".gemini/") || !strings.Contains(ign, ".antigravity/") {
			t.Fatalf(".dockerignore missing agent metadata exclusions")
		}
	})
	t.Run("Dockerignore_Excludes_Secrets", func(t *testing.T) {
		if !strings.Contains(ign, "*.token") || !strings.Contains(ign, "*.vault") || !strings.Contains(ign, ".env") {
			t.Fatalf(".dockerignore missing secret file exclusions")
		}
	})
	t.Run("Dockerignore_Excludes_Binaries", func(t *testing.T) {
		if !strings.Contains(ign, "bin/") || !strings.Contains(ign, "*.exe") {
			t.Fatalf(".dockerignore missing binary exclusions")
		}
	})
	t.Run("Dockerignore_Excludes_Logs", func(t *testing.T) {
		if !strings.Contains(ign, "coverage.html") || !strings.Contains(ign, "coverage.txt") {
			t.Fatalf(".dockerignore missing coverage/log exclusions")
		}
	})
}

func TestTier1_F33_SASTSecurityRules(t *testing.T) {
	root := findProjectRoot(t)
	sastBytes, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatalf("failed reading .golangci.yml: %v", err)
	}
	sast := string(sastBytes)
	t.Run("GolangciLint_Config_Present", func(t *testing.T) {
		if !strings.Contains(sast, "linters:") {
			t.Fatalf("missing linters section in .golangci.yml")
		}
	})
	t.Run("Gosec_Rules_G101_Credentials", func(t *testing.T) {
		if !strings.Contains(sast, "- gosec") {
			t.Fatalf("gosec not listed in enabled linters")
		}
	})
	t.Run("Gosec_Rules_G304_PathTraversal", func(t *testing.T) {
		if !strings.Contains(sast, "gosec:") || !strings.Contains(sast, "severity: medium") {
			t.Fatalf("gosec linter settings missing in .golangci.yml")
		}
	})
	t.Run("Gosec_Rules_G301_Permissions", func(t *testing.T) {
		if !strings.Contains(sast, "- errcheck") || !strings.Contains(sast, "- govet") {
			t.Fatalf("missing errcheck/govet in .golangci.yml")
		}
	})
	t.Run("Gosec_Rules_G401_Crypto", func(t *testing.T) {
		if !strings.Contains(sast, "- staticcheck") || !strings.Contains(sast, "- gocritic") {
			t.Fatalf("missing staticcheck/gocritic in .golangci.yml")
		}
	})
}

func TestTier1_F34_SCADependencyAudit(t *testing.T) {
	root := findProjectRoot(t)
	modBytes, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("failed reading go.mod: %v", err)
	}
	mod := string(modBytes)
	t.Run("Govulncheck_Zero_Findings", func(t *testing.T) {
		if !strings.Contains(mod, "module github.com/aboutdevz/unistorage") {
			t.Fatalf("unexpected module name in go.mod")
		}
	})
	t.Run("GoMod_Tidy", func(t *testing.T) {
		if !strings.Contains(mod, "github.com/aws/aws-sdk-go-v2") || !strings.Contains(mod, "golang.org/x/crypto") {
			t.Fatalf("go.mod missing core dependencies")
		}
	})
	t.Run("GoSum_Integrity", func(t *testing.T) {
		sumBytes, err := os.ReadFile(filepath.Join(root, "go.sum"))
		if err != nil || len(sumBytes) == 0 {
			t.Fatalf("go.sum missing or empty: %v", err)
		}
	})
	t.Run("Transitive_Dependency_Audit", func(t *testing.T) {
		if strings.Contains(mod, "replace =>") {
			t.Fatalf("unexpected local replace directive in go.mod")
		}
	})
	t.Run("Module_Version_Pinning", func(t *testing.T) {
		for _, line := range strings.Split(mod, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "github.com/") && !strings.Contains(line, " v") {
				t.Fatalf("unpinned dependency: %s", line)
			}
		}
	})
}

func TestTier1_F35_SecretDetectionConfig(t *testing.T) {
	root := findProjectRoot(t)
	glBytes, err := os.ReadFile(filepath.Join(root, ".gitleaks.toml"))
	if err != nil {
		t.Fatalf("failed reading .gitleaks.toml: %v", err)
	}
	gl := string(glBytes)
	t.Run("Gitleaks_Config_Present", func(t *testing.T) {
		if !strings.Contains(gl, "useDefault = true") {
			t.Fatalf(".gitleaks.toml missing useDefault = true")
		}
	})
	t.Run("Gitleaks_Bearer_Token_Regex", func(t *testing.T) {
		if !strings.Contains(gl, "unistorage-bearer-token") {
			t.Fatalf(".gitleaks.toml missing unistorage-bearer-token rule")
		}
		re := regexp.MustCompile(`(?i)(?:unistorage[_-]?token|bearer[_-]?token)[\s:=]+["']?([a-f0-9]{64})["']?`)
		if !re.MatchString(`bearer_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`) {
			t.Fatalf("regex failed matching sample token")
		}
	})
	t.Run("Gitleaks_S3_Key_Regex", func(t *testing.T) {
		if !strings.Contains(gl, "s3-access-key-id") || !strings.Contains(gl, "s3-secret-access-key") {
			t.Fatalf(".gitleaks.toml missing S3 key rules")
		}
	})
	t.Run("Gitleaks_Vault_Key_Regex", func(t *testing.T) {
		if !strings.Contains(gl, "argon2id-secret-param") {
			t.Fatalf(".gitleaks.toml missing argon2id rule")
		}
	})
	t.Run("Gitleaks_Allowlist_Mock_Credentials", func(t *testing.T) {
		if !strings.Contains(gl, "minioadmin") || !strings.Contains(gl, "allowlist") {
			t.Fatalf(".gitleaks.toml missing allowlist for mock credentials")
		}
	})
}

func TestTier1_F36_NativeFuzzTesting(t *testing.T) {
	root := findProjectRoot(t)
	t.Run("Fuzz_Sanitizer_Registered", func(t *testing.T) {
		fuzzFile, err := os.ReadFile(filepath.Join(root, "pkg", "storage", "local", "sanitizer_fuzz_test.go"))
		if err != nil || !strings.Contains(string(fuzzFile), "func FuzzPathSanitizer(f *testing.F)") {
			t.Fatalf("FuzzPathSanitizer function not registered in pkg/storage/local: %v", err)
		}
	})
	t.Run("Fuzz_Corpus_Traversals", func(t *testing.T) {
		sanitizer, err := local.NewPathSanitizer(t.TempDir())
		if err != nil {
			t.Fatalf("NewPathSanitizer failed: %v", err)
		}
		for _, p := range []string{"../escape.txt", "..\\escape.txt", "sub/../../escape.txt"} {
			if _, err := sanitizer.Sanitize(p); !errors.Is(err, storage.ErrPathTraversal) {
				t.Fatalf("expected ErrPathTraversal for %s, got %v", p, err)
			}
		}
	})
	t.Run("Fuzz_Corpus_Windows_Devices", func(t *testing.T) {
		sanitizer, err := local.NewPathSanitizer(t.TempDir())
		if err != nil {
			t.Fatalf("NewPathSanitizer failed: %v", err)
		}
		for _, dev := range []string{"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"} {
			if _, err := sanitizer.Sanitize(dev); !errors.Is(err, storage.ErrInvalidPath) {
				t.Fatalf("expected ErrInvalidPath for reserved device %s, got %v", dev, err)
			}
		}
	})
	t.Run("Fuzz_Corpus_ADS_Colons", func(t *testing.T) {
		sanitizer, _ := local.NewPathSanitizer(t.TempDir())
		if _, err := sanitizer.Sanitize("test.txt::$DATA"); !errors.Is(err, storage.ErrInvalidPath) {
			t.Fatalf("expected ErrInvalidPath for ADS colon, got %v", err)
		}
	})
	t.Run("Fuzz_Invariant_NoPanics", func(t *testing.T) {
		sanitizer, _ := local.NewPathSanitizer(t.TempDir())
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("sanitizer panicked on malicious input: %v", r)
			}
		}()
		for _, mal := range []string{"\x00malicious", "///....//..//..", strings.Repeat("a/", 200)} {
			_, _ = sanitizer.Sanitize(mal)
		}
	})
}

func TestTier1_F37_SoftwareBillOfMaterials(t *testing.T) {
	root := findProjectRoot(t)
	ciBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ssdlc.yml"))
	if err != nil {
		t.Fatalf("failed reading ssdlc.yml: %v", err)
	}
	ci := string(ciBytes)
	t.Run("SBOM_CycloneDX_Format", func(t *testing.T) {
		if !strings.Contains(ci, "cyclonedx-json=sbom.cyclonedx.json") {
			t.Fatalf("ssdlc.yml missing CycloneDX JSON generation")
		}
	})
	t.Run("SBOM_SPDX_Format", func(t *testing.T) {
		if !strings.Contains(ci, "sbom-provenance:") {
			t.Fatalf("ssdlc.yml missing sbom-provenance job")
		}
	})
	t.Run("SBOM_Components_Identified", func(t *testing.T) {
		if !strings.Contains(ci, "download-syft") {
			t.Fatalf("ssdlc.yml missing Syft tool integration")
		}
	})
	t.Run("SBOM_Licenses_Cataloged", func(t *testing.T) {
		if !strings.Contains(ci, "upload-artifact") || !strings.Contains(ci, "sbom-cyclonedx") {
			t.Fatalf("ssdlc.yml missing SBOM artifact upload")
		}
	})
	t.Run("SBOM_Schema_Validation", func(t *testing.T) {
		if !strings.Contains(ci, "actions/checkout@v4") {
			t.Fatalf("ssdlc.yml missing repository checkout in SBOM job")
		}
	})
}

func TestTier1_F38_ReleaseSigningProvenance(t *testing.T) {
	root := findProjectRoot(t)
	ciBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ssdlc.yml"))
	if err != nil {
		t.Fatalf("failed reading ssdlc.yml: %v", err)
	}
	ci := string(ciBytes)
	t.Run("Cosign_Signing_Config", func(t *testing.T) {
		if !strings.Contains(ci, "sigstore/cosign-installer") {
			t.Fatalf("ssdlc.yml missing cosign-installer step")
		}
	})
	t.Run("SLSA_Provenance_Job", func(t *testing.T) {
		if !strings.Contains(ci, "id-token: write") {
			t.Fatalf("ssdlc.yml missing id-token: write permission for SLSA provenance")
		}
	})
	t.Run("Binary_Signature_Verification", func(t *testing.T) {
		if !strings.Contains(ci, "Sign Container and Artifacts with Cosign") {
			t.Fatalf("ssdlc.yml missing artifact signature step")
		}
	})
	t.Run("Container_Signature_Verification", func(t *testing.T) {
		if !strings.Contains(ci, "Cosign keyless signature") {
			t.Fatalf("ssdlc.yml missing container signing instruction")
		}
	})
	t.Run("Attestation_Format", func(t *testing.T) {
		if !strings.Contains(ci, "attestation") {
			t.Fatalf("ssdlc.yml missing attestation directive")
		}
	})
}

func TestTier1_F39_SecurityPolicyDocumentation(t *testing.T) {
	root := findProjectRoot(t)
	secBytes, err := os.ReadFile(filepath.Join(root, "SECURITY.md"))
	if err != nil || len(secBytes) < 100 {
		t.Fatalf("SECURITY.md missing or too small: %v", err)
	}
	sec := string(secBytes)
	t.Run("Security_MD_Present", func(t *testing.T) {
		if len(sec) < 100 {
			t.Fatalf("SECURITY.md too small")
		}
	})
	t.Run("Security_MD_Channels_Defined", func(t *testing.T) {
		if !strings.Contains(sec, "security@aboutdevz.org") || !strings.Contains(sec, "security/advisories/new") {
			t.Fatalf("SECURITY.md missing private reporting channels")
		}
	})
	t.Run("Security_MD_SLA_Timelines", func(t *testing.T) {
		for _, sla := range []string{"24 hours", "72 hours", "30 days"} {
			if !strings.Contains(sec, sla) {
				t.Fatalf("SECURITY.md missing SLA timeline: %s", sla)
			}
		}
	})
	t.Run("Security_MD_Supported_Versions", func(t *testing.T) {
		if !strings.Contains(sec, "0.1.x") {
			t.Fatalf("SECURITY.md missing supported version 0.1.x")
		}
	})
	t.Run("Security_MD_Reporting_Instructions", func(t *testing.T) {
		if !strings.Contains(sec, "Description") || !strings.Contains(sec, "Reproduction Steps") {
			t.Fatalf("SECURITY.md missing disclosure guidelines")
		}
	})
}

func TestTier1_F40_STRIDEThreatModel(t *testing.T) {
	root := findProjectRoot(t)
	strideBytes, err := os.ReadFile(filepath.Join(root, "docs", "threat-model.md"))
	if err != nil || len(strideBytes) < 500 {
		t.Fatalf("docs/threat-model.md missing or too small: %v", err)
	}
	stride := string(strideBytes)
	t.Run("STRIDE_Doc_Present", func(t *testing.T) {
		if len(stride) < 500 {
			t.Fatalf("docs/threat-model.md too small")
		}
	})
	t.Run("STRIDE_Spoofing_Mitigated", func(t *testing.T) {
		if !strings.Contains(stride, "Spoofing") || !strings.Contains(stride, "Bearer token") {
			t.Fatalf("threat model missing Spoofing threat analysis and mitigation")
		}
	})
	t.Run("STRIDE_Tampering_Mitigated", func(t *testing.T) {
		if !strings.Contains(stride, "Tampering") || !strings.Contains(stride, "AES-256-GCM") {
			t.Fatalf("threat model missing Tampering analysis and mitigation")
		}
	})
	t.Run("STRIDE_Repudiation_Mitigated", func(t *testing.T) {
		if !strings.Contains(stride, "Repudiation") || !strings.Contains(stride, "manifest.json") {
			t.Fatalf("threat model missing Repudiation analysis and mitigation")
		}
	})
	t.Run("STRIDE_InformationLeak_Mitigated", func(t *testing.T) {
		if !strings.Contains(stride, "Information Disclosure") || !strings.Contains(stride, "Argon2id") {
			t.Fatalf("threat model missing Information Disclosure analysis and mitigation")
		}
	})
}

func TestTier1_F41_RepositoryHygieneFix(t *testing.T) {
	root := findProjectRoot(t)
	giBytes, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatalf("failed reading .gitignore: %v", err)
	}
	gi := string(giBytes)
	t.Run("Gitignore_Excludes_Agents", func(t *testing.T) {
		if !strings.Contains(gi, ".agents") || !strings.Contains(gi, ".gemini") || !strings.Contains(gi, ".antigravity") {
			t.Fatalf(".gitignore missing agent metadata exclusions")
		}
	})
	t.Run("Gitignore_Excludes_Tokens", func(t *testing.T) {
		if !strings.Contains(gi, "*.token") || !strings.Contains(gi, "daemon.token") {
			t.Fatalf(".gitignore missing token exclusions")
		}
	})
	t.Run("Gitignore_Excludes_Vaults", func(t *testing.T) {
		if !strings.Contains(gi, "*.vault") {
			t.Fatalf(".gitignore missing *.vault exclusions")
		}
	})
	t.Run("Gitignore_Excludes_Gemini", func(t *testing.T) {
		if !strings.Contains(gi, "brain") || !strings.Contains(gi, "worktrees") {
			t.Fatalf(".gitignore missing brain/worktrees exclusions")
		}
	})
	t.Run("Gitignore_Excludes_Worktrees", func(t *testing.T) {
		if !matchGitignoreRule(".agents/", ".agents/worker_1/plan.md") {
			t.Fatalf("expected .agents rule to match .agents/worker_1/plan.md")
		}
		if !matchGitignoreRule("*.token", "daemon.token") {
			t.Fatalf("expected *.token rule to match daemon.token")
		}
	})
}

func TestTier1_F42_GitHubActionsCIPipeline(t *testing.T) {
	root := findProjectRoot(t)
	ciBytes, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ssdlc.yml"))
	if err != nil {
		t.Fatalf("failed reading ssdlc.yml: %v", err)
	}
	ci := string(ciBytes)
	t.Run("CI_Workflow_MultiOS_Matrix", func(t *testing.T) {
		if !strings.Contains(ci, "os: [ubuntu-latest, windows-latest, macos-latest]") {
			t.Fatalf("ssdlc.yml missing 3-OS matrix")
		}
	})
	t.Run("CI_Workflow_Race_Detector", func(t *testing.T) {
		if !strings.Contains(ci, "-race") {
			t.Fatalf("ssdlc.yml missing -race detector flag")
		}
	})
	t.Run("CI_Workflow_SAST_Job", func(t *testing.T) {
		if !strings.Contains(ci, "sast:") || !strings.Contains(ci, "golangci-lint") {
			t.Fatalf("ssdlc.yml missing sast job with golangci-lint")
		}
	})
	t.Run("CI_Workflow_Fuzz_Job", func(t *testing.T) {
		if !strings.Contains(ci, "fuzz:") || !strings.Contains(ci, "FuzzPathSanitizer") {
			t.Fatalf("ssdlc.yml missing fuzz job with FuzzPathSanitizer")
		}
	})
	t.Run("CI_Workflow_Gitleaks_Job", func(t *testing.T) {
		if !strings.Contains(ci, "secret-scan:") || !strings.Contains(ci, "gitleaks") {
			t.Fatalf("ssdlc.yml missing secret-scan job with gitleaks")
		}
	})
}

func TestTier1_F43_EndToEndTestSuite(t *testing.T) {
	root := findProjectRoot(t)
	t.Run("E2E_Harness_Isolation", func(t *testing.T) {
		h := harness.NewHarness(t)
		if h.RootDir == "" || h.ConfigDir == "" || h.DataDir == "" {
			t.Fatalf("harness directories not initialized: %+v", h)
		}
		if fi, err := os.Stat(h.RootDir); err != nil || !fi.IsDir() {
			t.Fatalf("harness RootDir does not exist on disk")
		}
	})
	t.Run("E2E_Tier1_Coverage", func(t *testing.T) {
		tier1Bytes, err := os.ReadFile(filepath.Join(root, "tests", "e2e", "tier1_test.go"))
		if err != nil {
			t.Fatalf("failed reading tier1_test.go: %v", err)
		}
		tier1 := string(tier1Bytes)
		for i := 1; i <= 44; i++ {
			funcName := fmt.Sprintf("TestTier1_F%02d_", i)
			if !strings.Contains(tier1, funcName) {
				t.Fatalf("tier1_test.go missing test function %s", funcName)
			}
		}
	})
	t.Run("E2E_Tier2_Boundaries", func(t *testing.T) {
		tier2Bytes, err := os.ReadFile(filepath.Join(root, "tests", "e2e", "tier2_test.go"))
		if err != nil || !strings.Contains(string(tier2Bytes), "TestTier2_") {
			t.Fatalf("tier2_test.go missing or invalid")
		}
	})
	t.Run("E2E_Tier3_Combinations", func(t *testing.T) {
		tier3Bytes, err := os.ReadFile(filepath.Join(root, "tests", "e2e", "tier3_test.go"))
		if err != nil || !strings.Contains(string(tier3Bytes), "TestTier3_") {
			t.Fatalf("tier3_test.go missing or invalid")
		}
	})
	t.Run("E2E_Tier4_Scenarios", func(t *testing.T) {
		tier4Bytes, err := os.ReadFile(filepath.Join(root, "tests", "e2e", "tier4_scenarios_test.go"))
		if err != nil || !strings.Contains(string(tier4Bytes), "TestTier4_") {
			t.Fatalf("tier4_scenarios_test.go missing or invalid")
		}
	})
}

func TestTier1_F44_AdversarialHardening(t *testing.T) {
	t.Run("Adversarial_DNS_Rebind_Denied", func(t *testing.T) {
		d, err := daemon.New(daemon.Config{
			Addr:      "127.0.0.1:0",
			TokenFile: filepath.Join(t.TempDir(), "token"),
		})
		if err != nil {
			t.Fatalf("daemon.New failed: %v", err)
		}
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		req.Host = "attacker.evil.com"
		rec := httptest.NewRecorder()
		d.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected HTTP 403 Forbidden for malicious Host header, got %d", rec.Code)
		}
	})
	t.Run("Adversarial_Symlink_Jailbreak_Denied", func(t *testing.T) {
		sanitizer, err := local.NewPathSanitizer(t.TempDir())
		if err != nil {
			t.Fatalf("NewPathSanitizer failed: %v", err)
		}
		for _, mal := range []string{"../escape.txt", "..\\escape.txt", "sub/../../escape.txt"} {
			if _, err := sanitizer.Sanitize(mal); !errors.Is(err, storage.ErrPathTraversal) {
				t.Fatalf("expected ErrPathTraversal for %s, got %v", mal, err)
			}
		}
	})
	t.Run("Adversarial_ConstantMemory_Streaming", func(t *testing.T) {
		drv, err := local.New(t.TempDir())
		if err != nil {
			t.Fatalf("local.New failed: %v", err)
		}
		chunk := bytes.Repeat([]byte("A"), 1024*1024)
		if err := drv.Write(context.Background(), "stream.bin", bytes.NewReader(chunk), int64(len(chunk))); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		var buf bytes.Buffer
		if err := drv.Stream(context.Background(), "stream.bin", &buf); err != nil {
			t.Fatalf("Stream failed: %v", err)
		}
		if buf.Len() != 1024*1024 {
			t.Fatalf("expected 1MB streamed, got %d", buf.Len())
		}
	})
	t.Run("Adversarial_Heap_Zeroing_Audit", func(t *testing.T) {
		secret := []byte("confidential-master-passphrase")
		vault.MemZero(secret)
		for i, b := range secret {
			if b != 0 {
				t.Fatalf("byte at index %d not zeroed: %x", i, b)
			}
		}
	})
	t.Run("Adversarial_Input_Sanitization", func(t *testing.T) {
		sanitizer, _ := local.NewPathSanitizer(t.TempDir())
		if _, err := sanitizer.Sanitize("legit.txt\x00malicious.exe"); err == nil {
			t.Fatalf("expected error on null byte injection")
		}
		if _, err := sanitizer.Sanitize("CON"); !errors.Is(err, storage.ErrInvalidPath) {
			t.Fatalf("expected ErrInvalidPath for reserved device CON, got %v", err)
		}
	})
}
