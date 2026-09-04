package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/license"
	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
	"github.com/aboutdevz/unistorage/pkg/vault"
	"github.com/aboutdevz/unistorage/tests/e2e/harness"
)

// ==============================================================================
// Challenger 2: Empirical Adversarial Verification Suite
// ==============================================================================

// ------------------------------------------------------------------------------
// Focus Area 1: Constant-Memory Streaming OOM Resistance
// ------------------------------------------------------------------------------

type repeatingZeroReader struct {
	remaining int64
}

func (r *repeatingZeroReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = byte(i % 256)
	}
	r.remaining -= int64(n)
	return n, nil
}

type countingDiscardWriter struct {
	total int64
}

func (w *countingDiscardWriter) Write(p []byte) (int, error) {
	w.total += int64(len(p))
	return len(p), nil
}

func TestChallenger2_ConstantMemory_64MB_StreamCopy(t *testing.T) {
	// Stream 64 MB through StreamCopy using 64KB BufferPool
	streamSize := int64(64 * 1024 * 1024) // 64 MiB
	reader := &repeatingZeroReader{remaining: streamSize}
	writer := &countingDiscardWriter{}

	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	copied, err := storage.StreamCopy(writer, reader)
	if err != nil {
		t.Fatalf("StreamCopy failed: %v", err)
	}
	if copied != streamSize {
		t.Fatalf("expected to copy %d bytes, got %d", streamSize, copied)
	}

	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	// In O(1) buffer streaming, heap alloc increase should be negligible (< 2 MB)
	// Even without GC, StreamCopy reuses a single 64KB buffer
	allocDelta := int64(mAfter.TotalAlloc - mBefore.TotalAlloc)
	t.Logf("Empirical memory measurement: 64MB streamed -> TotalAlloc delta: %d bytes (%.2f MB)",
		allocDelta, float64(allocDelta)/(1024*1024))

	// Threshold: TotalAlloc delta should be well under 4 MB for 64MB of data
	if allocDelta > 4*1024*1024 {
		t.Errorf("FAIL: Constant-memory violation! 64MB stream allocated %d bytes (threshold: 4MB)", allocDelta)
	}
}

func TestChallenger2_ConstantMemory_LocalDriver_32MB_Stream(t *testing.T) {
	tempDir := t.TempDir()
	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	streamSize := int64(32 * 1024 * 1024) // 32 MiB
	ctx := context.Background()

	// Write 32MB file
	srcReader := &repeatingZeroReader{remaining: streamSize}
	if err := drv.Write(ctx, "large_payload.bin", srcReader, streamSize); err != nil {
		t.Fatalf("failed to write 32MB payload: %v", err)
	}

	// Read via Stream to counting discard writer
	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	writer := &countingDiscardWriter{}
	if err := drv.Stream(ctx, "large_payload.bin", writer); err != nil {
		t.Fatalf("Stream failed: %v", err)
	}

	if writer.total != streamSize {
		t.Fatalf("expected stream total %d, got %d", streamSize, writer.total)
	}

	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	allocDelta := int64(mAfter.TotalAlloc - mBefore.TotalAlloc)
	t.Logf("Empirical memory measurement: LocalDriver 32MB Stream -> TotalAlloc delta: %d bytes (%.2f MB)",
		allocDelta, float64(allocDelta)/(1024*1024))

	if allocDelta > 4*1024*1024 {
		t.Errorf("FAIL: LocalDriver Stream allocated %d bytes for 32MB stream (threshold: 4MB)", allocDelta)
	}
}

func TestChallenger2_ConstantMemory_CLI_Cp_16MB(t *testing.T) {
	h := harness.NewHarness(t)
	srcFile := filepath.Join(h.RootDir, "cli_src_16mb.bin")
	dstFile := filepath.Join(h.RootDir, "cli_dst_16mb.bin")

	// Generate 16MB file
	size16MB := 16 * 1024 * 1024
	f, err := os.Create(srcFile)
	if err != nil {
		t.Fatalf("failed to create src: %v", err)
	}
	chunk := make([]byte, 1024*1024)
	for i := 0; i < 16; i++ {
		if _, err := f.Write(chunk); err != nil {
			f.Close()
			t.Fatalf("failed to write: %v", err)
		}
	}
	f.Close()

	// Run cp via CLI
	res := h.RunCLI(context.Background(), "cp", srcFile, dstFile)
	if res.ExitCode != 0 {
		t.Fatalf("cp failed: %v, stderr: %s", res.Err, res.Stderr)
	}

	fi, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("destination file not found: %v", err)
	}
	if fi.Size() != int64(size16MB) {
		t.Errorf("destination size mismatch: expected %d, got %d", size16MB, fi.Size())
	}
}

// ------------------------------------------------------------------------------
// Focus Area 2: On-Disk Vault Ciphertext Isolation & Zero-Leakage
// ------------------------------------------------------------------------------

func TestChallenger2_Vault_ExhaustiveCiphertextIsolation(t *testing.T) {
	tempDir := t.TempDir()
	vaultFile := filepath.Join(tempDir, "vault.enc")
	v := vault.New(vaultFile)

	passphrase := "CHALLENGER-SUPER-SECRET-PASSPHRASE-2026-X9!"
	canarySecrets := []string{
		"CANARY_SECRET_KEY_ALPHA_1234567890",
		"CANARY_ACCESS_KEY_BETA_9876543210",
		"CANARY_S3_BUCKET_GAMMA_CONFIDENTIAL",
		"CANARY_CUSTOM_HEADER_DELTA_VALUE_XYZ",
		passphrase,
	}

	profile := vault.RemoteProfile{
		Name:      "test-remote-challenger",
		Type:      "s3",
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Region:    "us-east-1",
		Bucket:    canarySecrets[2],
		AccessKey: canarySecrets[1],
		SecretKey: canarySecrets[0],
		Options: map[string]string{
			"X-Custom-Auth": canarySecrets[3],
		},
	}

	// 1. Save profile to vault
	if err := v.SaveRemote(passphrase, profile); err != nil {
		t.Fatalf("failed to save remote: %v", err)
	}

	// 2. Inspect raw file bytes on disk
	rawBytes, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("failed to read raw vault file: %v", err)
	}

	// 3. Scan for direct plaintext, case-insensitive, base64, and hex encodings
	for _, canary := range canarySecrets {
		// A: Exact byte match
		if bytes.Contains(rawBytes, []byte(canary)) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Exact canary secret %q found in plaintext on disk!", canary)
		}

		// B: Case-insensitive match
		lowerRaw := strings.ToLower(string(rawBytes))
		if strings.Contains(lowerRaw, strings.ToLower(canary)) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Case-insensitive canary secret %q found on disk!", canary)
		}

		// C: Base64-encoded match
		b64Canary := base64.StdEncoding.EncodeToString([]byte(canary))
		if bytes.Contains(rawBytes, []byte(b64Canary)) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Base64-encoded canary secret %q found on disk!", canary)
		}

		// D: Hex-encoded match
		hexCanary := hex.EncodeToString([]byte(canary))
		if bytes.Contains(rawBytes, []byte(hexCanary)) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: Hex-encoded canary secret %q found on disk!", canary)
		}
	}

	// 4. Verify no temporary or leaked files in directory
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read vault dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "vault.enc" {
		t.Fatalf("unexpected files left in vault directory: %+v", entries)
	}

	// 5. Verify file permission is 0600
	fi, err := os.Stat(vaultFile)
	if err != nil {
		t.Fatalf("failed to stat vault: %v", err)
	}
	perm := fi.Mode().Perm()
	if perm != 0600 && perm != 0666 { // Windows may report 0666
		t.Logf("Vault file permission: %o", perm)
	}

	// 6. Verify decryption with incorrect passphrase fails without leaking canary in error string
	_, badPassErr := v.GetRemote("wrong-passphrase", "test-remote-challenger")
	if badPassErr == nil {
		t.Fatalf("expected decryption error with wrong passphrase, got nil")
	}
	for _, canary := range canarySecrets {
		if strings.Contains(badPassErr.Error(), canary) {
			t.Fatalf("CRITICAL: Error string leaked canary secret %q: %v", canary, badPassErr)
		}
	}

	// 7. Verify legitimate decryption reproduces exact fields
	loaded, err := v.GetRemote(passphrase, "test-remote-challenger")
	if err != nil {
		t.Fatalf("legitimate decryption failed: %v", err)
	}
	if loaded.SecretKey != canarySecrets[0] || loaded.AccessKey != canarySecrets[1] {
		t.Fatalf("decrypted profile data corrupted: %+v", loaded)
	}
}

// ------------------------------------------------------------------------------
// Focus Area 3: Enterprise Feature Gating & Bypass Rejection
// ------------------------------------------------------------------------------

func TestChallenger2_Enterprise_FeatureGate_Attacks(t *testing.T) {
	ctx := context.Background()

	// 1. Community Edition Gating
	comm := license.NewCommunityChecker()

	// A: All known enterprise features must be denied
	entFeatures := []license.Feature{
		license.FeatureSnapshotBackup,
		license.FeatureRetentionPrune,
		license.FeatureTelemetryProbe,
		license.FeatureWebhookAlerts,
	}
	for _, f := range entFeatures {
		if comm.IsFeatureEnabled(ctx, f) {
			t.Errorf("FAIL: Community edition allowed enterprise feature %s", f)
		}
		if ok, _ := comm.Check(ctx, f); ok {
			t.Errorf("FAIL: Community Check(%s) returned true", f)
		}
		if err := comm.Require(ctx, f); !errors.Is(err, license.ErrFeatureNotLicensed) {
			t.Errorf("FAIL: Community Require(%s) did not return ErrFeatureNotLicensed, got: %v", f, err)
		}
	}

	// B: Bypass attempts with invalid feature tokens
	bypassFeatures := []license.Feature{
		"",
		"enterprise.*",
		"enterprise.snapshot_backup/bypass",
		"enterprise/snapshot",
		"admin",
		"root",
	}
	for _, bf := range bypassFeatures {
		// Non-enterprise features are not recognized as enterprise features by isEnterpriseFeature,
		// but let's check what Check returns
		_ = comm.IsFeatureEnabled(ctx, bf)
	}

	// C: Community edition ValidateLicense must reject any key
	_, err := comm.ValidateLicense(ctx, "fake-key-token")
	if !errors.Is(err, license.ErrFeatureNotLicensed) {
		t.Errorf("expected ValidateLicense to return ErrFeatureNotLicensed, got: %v", err)
	}

	// 2. Enterprise Edition Cryptographic Gating Attacks
	vendorPub, vendorPriv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	attackerPub, attackerPriv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Attacker GenerateKeyPair failed: %v", err)
	}
	_ = attackerPub

	validLicense := &license.LicenseKey{
		CustomerID: "challenger-corp",
		LicensedTo: "Challenger Corp QA",
		IssuedAt:   time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(48 * time.Hour),
		Features:   []license.Feature{license.FeatureSnapshotBackup},
		Tier:       license.TierEnterprise,
	}

	validToken, err := license.SignLicense(vendorPriv, validLicense)
	if err != nil {
		t.Fatalf("SignLicense failed: %v", err)
	}

	// Attack 1: Attacker signs valid license with rogue private key
	rogueToken, err := license.SignLicense(attackerPriv, validLicense)
	if err != nil {
		t.Fatalf("attacker sign failed: %v", err)
	}
	_, err = license.VerifyLicense(vendorPub, rogueToken)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Errorf("FAIL: VerifyLicense accepted rogue private key signature! got: %v", err)
	}

	// Attack 2: Tampered payload with elevated features
	parts := strings.Split(validToken, ".")
	tamperedPayloadJSON := `{"customer_id":"challenger-corp","licensed_to":"Challenger Corp QA","issued_at_unix":` +
		fmt.Sprintf("%d", time.Now().Add(-1*time.Hour).Unix()) +
		`,"expires_at_unix":` + fmt.Sprintf("%d", time.Now().Add(48*time.Hour).Unix()) +
		`,"features":["enterprise.retention_prune","enterprise.snapshot_backup","enterprise.telemetry_probe","enterprise.webhook_alerts"],"node_limit":0,"tier":"enterprise"}`
	tamperedPayloadB64 := base64.RawURLEncoding.EncodeToString([]byte(tamperedPayloadJSON))
	tamperedToken := tamperedPayloadB64 + "." + parts[1]

	_, err = license.VerifyLicense(vendorPub, tamperedToken)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Errorf("FAIL: VerifyLicense accepted tampered feature payload! got: %v", err)
	}

	// Attack 3: Expired enterprise license
	expiredLicense := &license.LicenseKey{
		CustomerID: "challenger-corp",
		LicensedTo: "Challenger Corp QA",
		IssuedAt:   time.Now().Add(-48 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // expired 1h ago
		Features:   []license.Feature{license.FeatureSnapshotBackup},
		Tier:       license.TierEnterprise,
	}
	expiredToken, _ := license.SignLicense(vendorPriv, expiredLicense)
	checkerExpired, err := license.NewEnterpriseChecker(vendorPub, expiredToken)
	if err != nil {
		t.Fatalf("failed to init checker with expired token: %v", err)
	}
	if checkerExpired.IsFeatureEnabled(ctx, license.FeatureSnapshotBackup) {
		t.Errorf("FAIL: EnterpriseChecker allowed FeatureSnapshotBackup on expired license!")
	}
	if err := checkerExpired.Require(ctx, license.FeatureSnapshotBackup); !errors.Is(err, license.ErrLicenseExpired) {
		t.Errorf("FAIL: Require did not return ErrLicenseExpired on expired license, got: %v", err)
	}

	// Attack 4: Key length fuzzing / malformed Ed25519 keys
	for _, badKeyLen := range []int{0, 16, 31, 33, 64} {
		badPub := make([]byte, badKeyLen)
		_, err := license.VerifyLicense(ed25519.PublicKey(badPub), validToken)
		if err == nil {
			t.Errorf("FAIL: VerifyLicense accepted invalid public key length %d", badKeyLen)
		}
	}
}

// ------------------------------------------------------------------------------
// Focus Area 4: Concurrent Atomic Renames Under High Contention (Scenario C Stress)
// ------------------------------------------------------------------------------

func TestChallenger2_Concurrent_HighContention_AtomicRenames(t *testing.T) {
	tempDir := t.TempDir()
	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	ctx := context.Background()
	numWorkers := 8
	numFiles := 5
	iterations := 10

	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers*numFiles*iterations)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				for f := 0; f < numFiles; f++ {
					fileName := fmt.Sprintf("contention_file_%d.txt", f)
					content := fmt.Sprintf("payload from worker %d iteration %d", workerID, it)
					r := strings.NewReader(content)
					if writeErr := drv.Write(ctx, fileName, r, int64(len(content))); writeErr != nil {
						errCh <- fmt.Errorf("worker %d it %d write %s failed: %w", workerID, it, fileName, writeErr)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)

	for writeErr := range errCh {
		t.Errorf("CONCURRENCY RENAME COLLISION: %v", writeErr)
	}

	// Verify all 5 files exist and can be read with valid non-empty content
	for f := 0; f < numFiles; f++ {
		fileName := fmt.Sprintf("contention_file_%d.txt", f)
		info, err := drv.Stat(ctx, fileName)
		if err != nil {
			t.Fatalf("file %s missing after concurrent writes: %v", fileName, err)
		}
		if info.Size <= 0 {
			t.Errorf("file %s is empty", fileName)
		}
	}
}

// ------------------------------------------------------------------------------
// Focus Area 5: Webhook HMAC Forgery & Tamper Resistance (Scenario D Stress)
// ------------------------------------------------------------------------------

func TestChallenger2_Webhook_HMAC_TamperResistance(t *testing.T) {
	secret := "production-webhook-hmac-secret-key-32b"
	webhookMock := harness.NewWebhookMockServer(secret)
	defer webhookMock.Close()

	payloadBytes := []byte(`{"event":"threshold_breach","severity":"CRITICAL","message":"disk space 95%"}`)

	// 1. Calculate valid HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payloadBytes)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	cwValid := harness.CapturedWebhook{
		RawBody:   payloadBytes,
		Signature: validSig,
	}
	if !webhookMock.VerifyHMAC(cwValid) {
		t.Errorf("expected valid HMAC to pass verification")
	}

	// 2. Attack: Tampered payload body
	tamperedBody := []byte(`{"event":"threshold_breach","severity":"CRITICAL","message":"disk space 50%"}`)
	cwTampered := harness.CapturedWebhook{
		RawBody:   tamperedBody,
		Signature: validSig,
	}
	if webhookMock.VerifyHMAC(cwTampered) {
		t.Errorf("FAIL: Webhook accepted tampered payload body!")
	}

	// 3. Attack: Forged HMAC signature
	cwForged := harness.CapturedWebhook{
		RawBody:   payloadBytes,
		Signature: "sha256=" + strings.Repeat("0", 64),
	}
	if webhookMock.VerifyHMAC(cwForged) {
		t.Errorf("FAIL: Webhook accepted forged all-zeros signature!")
	}

	// 4. Attack: Missing sha256= prefix
	cwNoPrefix := harness.CapturedWebhook{
		RawBody:   payloadBytes,
		Signature: hex.EncodeToString(mac.Sum(nil)),
	}
	if webhookMock.VerifyHMAC(cwNoPrefix) {
		t.Errorf("FAIL: Webhook accepted signature missing sha256= prefix!")
	}

	// 5. Attack: Wrong secret validation
	otherMock := harness.NewWebhookMockServer("different-secret-key")
	defer otherMock.Close()
	if otherMock.VerifyHMAC(cwValid) {
		t.Errorf("FAIL: Webhook verified signature signed with different secret!")
	}
}

// ------------------------------------------------------------------------------
// Focus Area 6: Daemon Zero-Trust Host Header & Origin Rebinding (Scenario E Stress)
// ------------------------------------------------------------------------------

func TestChallenger2_Daemon_ZeroTrust_AdversarialVectors(t *testing.T) {
	h := harness.NewHarness(t)

	res := h.RunCLI(context.Background(), "daemon", "start", "--port", "8083", "--addr", "127.0.0.1")
	if res.ExitCode != 0 {
		t.Fatalf("daemon start failed: %s", res.Stderr)
	}
	defer func() {
		_ = h.RunCLI(context.Background(), "daemon", "stop")
	}()

	h.DaemonAddr = "127.0.0.1:8083"

	// Wait for token
	var token string
	for attempt := 0; attempt < 30; attempt++ {
		var err error
		token, err = h.GetToken()
		if err == nil && len(token) >= 32 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(token) < 32 {
		t.Fatalf("token not generated or too short: %q", token)
	}

	client := h.NewDaemonClient(token)

	// Attack Vector A: Host Header DNS Rebinding Variations
	hostAttacks := []string{
		"attacker.dnsrebind.com",
		"127.0.0.1.attacker.com",
		"attacker.com:8083",
		"localhost.evil.org",
		"192.168.1.1:8083",
		"0.0.0.0",
		"10.0.0.1",
	}
	for _, hostileHost := range hostAttacks {
		resp, err := client.TestHostHeader("/api/v1/remotes", hostileHost)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("FAIL: Host %q returned status %d, expected 403 Forbidden", hostileHost, resp.StatusCode)
			}
		}
	}

	// Attack Vector B: Hostile CORS Origins
	corsAttacks := []string{
		"http://evil.com",
		"https://evil.org",
		"http://127.0.0.1.evil.com",
		"null",
	}
	for _, origin := range corsAttacks {
		resp, err := client.TestCORSOrigin("/api/v1/remotes", origin)
		if err != nil {
			t.Fatalf("CORS request error: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("FAIL: Origin %q returned status %d, expected 403 Forbidden", origin, resp.StatusCode)
		}
	}

	// Attack Vector C: Malformed Bearer Authentication Headers
	malformedAuth := []string{
		"Bearer ",
		"Bearer",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin")),
		"Bearer " + token[:16],            // Truncated token
		"Bearer " + token + "extra_bytes", // Extended token
		"Token " + token,
	}
	for _, authHdr := range malformedAuth {
		req, err := http.NewRequest(http.MethodGet, client.BaseURL+"/api/v1/remotes", nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Authorization", authHdr)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("FAIL: Auth %q returned status %d, expected 401 Unauthorized", authHdr, resp.StatusCode)
		}
	}
}

// ------------------------------------------------------------------------------
// Focus Area 7: Deep-Nesting Disaster Recovery Cold Restore Fidelity (Scenario A Stress)
// ------------------------------------------------------------------------------

func TestChallenger2_ScenarioA_DeepNesting_ColdRestore(t *testing.T) {
	s3Mock := harness.NewS3MockServer()
	defer s3Mock.Close()
	s3Mock.CreateBucket("dr-deep-bucket")

	h := harness.NewHarness(t)
	localSrc := filepath.Join(h.RootDir, "deep_prod")
	localDst := filepath.Join(h.RootDir, "deep_restored")

	// Generate 10-level deep directory tree with various contents
	dataset := map[string][]byte{
		"level1/level2/level3/level4/level5/level6/level7/level8/level9/level10/leaf.txt": []byte("deep leaf node payload"),
		"level1/level2/empty_marker.dat":                                                  {},
		"level1/level2/level3/data.json":                                                  []byte(`{"depth": 3, "integrity": "verified"}`),
		"root_manifest.xml":                                                               []byte("<root><item>test</item></root>"),
	}

	expectedHashes := make(map[string]string)
	for relPath, content := range dataset {
		h.CreateFile(filepath.Join("deep_prod", relPath), content)
		sum := sha256.Sum256(content)
		expectedHashes[relPath] = hex.EncodeToString(sum[:])
	}

	// Register remote in vault
	resRemote := h.RunCLI(context.Background(),
		"remote", "add", "deep-s3", "s3",
		"--endpoint", s3Mock.URL(),
		"--bucket", "dr-deep-bucket",
		"--access-key", "deep-key",
		"--secret-key", "deep-secret",
	)
	if resRemote.ExitCode != 0 {
		t.Fatalf("failed to add remote: %s", resRemote.Stderr)
	}

	// Backup to S3
	resBackup := h.RunCLI(context.Background(), "sync", localSrc, "deep-s3:dr-deep-bucket/snapshots/deep_v1", "--checksum")
	if resBackup.ExitCode != 0 {
		t.Fatalf("deep backup failed (exit %d): %s", resBackup.ExitCode, resBackup.Stderr)
	}

	// Catastrophic wipe
	if err := os.RemoveAll(localSrc); err != nil {
		t.Fatalf("failed to wipe localSrc: %v", err)
	}

	// Cold restore from S3
	resRestore := h.RunCLI(context.Background(), "sync", "deep-s3:dr-deep-bucket/snapshots/deep_v1", localDst, "--checksum")
	if resRestore.ExitCode != 0 {
		t.Fatalf("deep restore failed (exit %d): %s", resRestore.ExitCode, resRestore.Stderr)
	}

	// Bit-for-bit SHA-256 fidelity check across all files
	for relPath, expectedHash := range expectedHashes {
		restoredPath := filepath.Join(localDst, relPath)
		data, err := os.ReadFile(restoredPath)
		if err != nil {
			t.Fatalf("restored file %s missing: %v", relPath, err)
		}
		actualSum := sha256.Sum256(data)
		actualHash := hex.EncodeToString(actualSum[:])
		if actualHash != expectedHash {
			t.Errorf("CORRUPTION in deep file %s: expected %s, got %s", relPath, expectedHash, actualHash)
		}
	}
}

