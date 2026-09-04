package license_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/license"
)

// 1. Stress-test forged signatures and corrupted tokens
func TestAdversarial_ForgedSignatures(t *testing.T) {
	vendorPub, vendorPriv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	validKey := &license.LicenseKey{
		CustomerID: "cust-adversarial-1",
		LicensedTo: "Target Corp",
		IssuedAt:   time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Features:   []license.Feature{license.FeatureSnapshotBackup},
		Tier:       license.TierEnterprise,
	}

	validToken, err := license.SignLicense(vendorPriv, validKey)
	if err != nil {
		t.Fatalf("SignLicense failed: %v", err)
	}

	parts := strings.Split(validToken, ".")
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	payloadB64 := parts[0]
	sigB64 := parts[1]

	// Attack A: Completely random signature bytes of valid length (64 bytes)
	fakeSig := make([]byte, ed25519.SignatureSize)
	for i := range fakeSig {
		fakeSig[i] = byte(i + 42)
	}
	forgedTokenA := payloadB64 + "." + base64.RawURLEncoding.EncodeToString(fakeSig)
	_, err = license.VerifyLicense(vendorPub, forgedTokenA)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Fatalf("expected ErrInvalidLicenseSignature for forged signature, got: %v", err)
	}

	// Attack B: Attacker generates their own keypair and signs the payload
	attackerPub, attackerPriv, _ := license.GenerateKeyPair()
	_ = attackerPub
	attackerSignedToken, err := license.SignLicense(attackerPriv, validKey)
	if err != nil {
		t.Fatalf("attacker SignLicense failed: %v", err)
	}
	attackerSig := strings.Split(attackerSignedToken, ".")[1]
	forgedTokenB := payloadB64 + "." + attackerSig
	_, err = license.VerifyLicense(vendorPub, forgedTokenB)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Fatalf("expected ErrInvalidLicenseSignature when verified against vendor public key, got: %v", err)
	}

	// Attack C: Truncated signature (less than 64 bytes)
	truncatedSig := base64.RawURLEncoding.EncodeToString(fakeSig[:32])
	forgedTokenC := payloadB64 + "." + truncatedSig
	_, err = license.VerifyLicense(vendorPub, forgedTokenC)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Fatalf("expected ErrInvalidLicenseSignature for truncated signature, got: %v", err)
	}

	// Attack D: Empty signature
	forgedTokenD := payloadB64 + "."
	_, err = license.VerifyLicense(vendorPub, forgedTokenD)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) && !errors.Is(err, license.ErrInvalidLicenseFormat) {
		t.Fatalf("expected signature or format error for empty signature, got: %v", err)
	}

	// Attack E: Corrupted Base64 in signature
	forgedTokenE := payloadB64 + ".!@#$%^&*()_+"
	_, err = license.VerifyLicense(vendorPub, forgedTokenE)
	if !errors.Is(err, license.ErrInvalidLicenseFormat) {
		t.Fatalf("expected ErrInvalidLicenseFormat for non-base64 signature, got: %v", err)
	}

	// Attack F: Corrupted Base64 in payload
	forgedTokenF := "!@#$%^&*()_+." + sigB64
	_, err = license.VerifyLicense(vendorPub, forgedTokenF)
	if !errors.Is(err, license.ErrInvalidLicenseFormat) {
		t.Fatalf("expected ErrInvalidLicenseFormat for non-base64 payload, got: %v", err)
	}

	// Attack G: Token with missing or extra segments
	for _, malformed := range []string{"", "single_segment", "one.two.three", "...."} {
		_, err = license.VerifyLicense(vendorPub, malformed)
		if !errors.Is(err, license.ErrInvalidLicenseFormat) {
			t.Fatalf("expected ErrInvalidLicenseFormat for %q, got: %v", malformed, err)
		}
	}
}

// 2. Stress-test tampered feature arrays
func TestAdversarial_TamperedFeatureArrays(t *testing.T) {
	vendorPub, vendorPriv, _ := license.GenerateKeyPair()

	// Legitimate key only has FeatureSnapshotBackup
	legitKey := &license.LicenseKey{
		CustomerID: "cust-starter",
		LicensedTo: "Starter Tier User",
		IssuedAt:   time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(48 * time.Hour),
		Features:   []license.Feature{license.FeatureSnapshotBackup},
		Tier:       license.TierEnterprise,
	}

	validToken, err := license.SignLicense(vendorPriv, legitKey)
	if err != nil {
		t.Fatalf("SignLicense failed: %v", err)
	}

	parts := strings.Split(validToken, ".")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode payload failed: %v", err)
	}

	var rawMap map[string]any
	if err := json.Unmarshal(payloadBytes, &rawMap); err != nil {
		t.Fatalf("unmarshal payload failed: %v", err)
	}

	// Tamper: Elevate entitlements by adding enterprise features to the JSON array
	rawMap["features"] = []string{
		string(license.FeatureSnapshotBackup),
		string(license.FeatureRetentionPrune),
		string(license.FeatureTelemetryProbe),
		string(license.FeatureWebhookAlerts),
	}

	tamperedBytes, _ := json.Marshal(rawMap)
	tamperedPayloadB64 := base64.RawURLEncoding.EncodeToString(tamperedBytes)
	tamperedToken := tamperedPayloadB64 + "." + parts[1]

	// VerifyLicense MUST reject tampered feature array
	_, err = license.VerifyLicense(vendorPub, tamperedToken)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Fatalf("expected ErrInvalidLicenseSignature for tampered features, got: %v", err)
	}

	// EnterpriseChecker MUST reject loading tampered token
	_, err = license.NewEnterpriseChecker(vendorPub, tamperedToken)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Fatalf("expected NewEnterpriseChecker to fail with ErrInvalidLicenseSignature, got: %v", err)
	}

	// Valid token should correctly deny unlicensed features
	checker, err := license.NewEnterpriseChecker(vendorPub, validToken)
	if err != nil {
		t.Fatalf("NewEnterpriseChecker failed for valid token: %v", err)
	}

	ctx := context.Background()
	for _, ungranted := range []license.Feature{
		license.FeatureRetentionPrune,
		license.FeatureTelemetryProbe,
		license.FeatureWebhookAlerts,
	} {
		ok, chkErr := checker.Check(ctx, ungranted)
		if ok {
			t.Fatalf("feature %s should not be granted", ungranted)
		}
		if !errors.Is(chkErr, license.ErrFeatureNotLicensed) {
			t.Fatalf("expected ErrFeatureNotLicensed for %s, got: %v", ungranted, chkErr)
		}
		if reqErr := checker.Require(ctx, ungranted); !errors.Is(reqErr, license.ErrFeatureNotLicensed) {
			t.Fatalf("expected Require(%s) to return ErrFeatureNotLicensed, got: %v", ungranted, reqErr)
		}
	}
}

// 3. Stress-test expired license keys
func TestAdversarial_ExpiredLicenses(t *testing.T) {
	vendorPub, vendorPriv, _ := license.GenerateKeyPair()

	// Scenario A: Expired 1 second ago
	subSecondExpiredKey := &license.LicenseKey{
		CustomerID: "cust-expired-now",
		IssuedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Second),
		Features:   []license.Feature{license.FeatureSnapshotBackup},
		Tier:       license.TierEnterprise,
	}
	tokenA, _ := license.SignLicense(vendorPriv, subSecondExpiredKey)

	checkerA, err := license.NewEnterpriseChecker(vendorPub, tokenA)
	if err != nil {
		t.Fatalf("NewEnterpriseChecker failed: %v", err)
	}

	ctx := context.Background()
	ok, err := checkerA.Check(ctx, license.FeatureSnapshotBackup)
	if ok {
		t.Fatalf("expected Check to return false for expired license")
	}
	if !errors.Is(err, license.ErrLicenseExpired) {
		t.Fatalf("expected ErrLicenseExpired, got: %v", err)
	}

	if reqErr := checkerA.Require(ctx, license.FeatureSnapshotBackup); !errors.Is(reqErr, license.ErrLicenseExpired) {
		t.Fatalf("expected Require to return ErrLicenseExpired, got: %v", reqErr)
	}

	infoA, err := checkerA.LicenseInfo()
	if err != nil {
		t.Fatalf("LicenseInfo failed: %v", err)
	}
	if !infoA.IsExpired {
		t.Fatalf("expected infoA.IsExpired to be true")
	}

	// ValidateLicense without loading should also reflect expired status
	valInfo, err := checkerA.ValidateLicense(ctx, tokenA)
	if err != nil {
		t.Fatalf("ValidateLicense failed: %v", err)
	}
	if !valInfo.IsExpired {
		t.Fatalf("expected ValidateLicense to mark IsExpired as true")
	}

	// Scenario B: Expired 10 years ago
	longExpiredKey := &license.LicenseKey{
		CustomerID: "cust-long-expired",
		IssuedAt:   time.Now().Add(-11 * 365 * 24 * time.Hour),
		ExpiresAt:  time.Now().Add(-10 * 365 * 24 * time.Hour),
		Features:   []license.Feature{license.FeatureTelemetryProbe},
		Tier:       license.TierEnterprise,
	}
	tokenB, _ := license.SignLicense(vendorPriv, longExpiredKey)
	checkerB, _ := license.NewEnterpriseChecker(vendorPub, tokenB)

	if reqErr := checkerB.Require(ctx, license.FeatureTelemetryProbe); !errors.Is(reqErr, license.ErrLicenseExpired) {
		t.Fatalf("expected ErrLicenseExpired for 10-year expired key, got: %v", reqErr)
	}
}

// 4. Stress-test public/private key mismatches and malformed keys
func TestAdversarial_KeyMismatches(t *testing.T) {
	vendorPubA, vendorPrivA, _ := license.GenerateKeyPair()
	vendorPubB, _, _ := license.GenerateKeyPair()

	key := &license.LicenseKey{
		CustomerID: "cust-mismatch",
		IssuedAt:   time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Features:   []license.Feature{license.FeatureSnapshotBackup},
		Tier:       license.TierEnterprise,
	}

	tokenSignedByA, err := license.SignLicense(vendorPrivA, key)
	if err != nil {
		t.Fatalf("SignLicense failed: %v", err)
	}

	// Verification using vendorPubA MUST succeed
	if _, err := license.VerifyLicense(vendorPubA, tokenSignedByA); err != nil {
		t.Fatalf("expected verification with vendorPubA to succeed, got: %v", err)
	}

	// Verification using vendorPubB MUST fail
	_, err = license.VerifyLicense(vendorPubB, tokenSignedByA)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Fatalf("expected ErrInvalidLicenseSignature on key mismatch, got: %v", err)
	}

	// Public key length validations: Ed25519 requires exactly 32 bytes
	for _, badPubKey := range [][]byte{
		nil,
		{},
		make([]byte, 16),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	} {
		_, err := license.VerifyLicense(badPubKey, tokenSignedByA)
		if err == nil {
			t.Fatalf("expected error for public key length %d, got nil", len(badPubKey))
		}
	}

	// Private key length validations: Ed25519 requires exactly 64 bytes
	for _, badPrivKey := range [][]byte{
		nil,
		{},
		make([]byte, 32),
		make([]byte, 63),
		make([]byte, 65),
	} {
		_, err := license.SignLicense(badPrivKey, key)
		if err == nil {
			t.Fatalf("expected error for private key length %d, got nil", len(badPrivKey))
		}
	}
}

// 5. Stress-test CommunityChecker strictly rejecting all enterprise capabilities
func TestAdversarial_CommunityCheckerStrictRejection(t *testing.T) {
	checker := license.NewCommunityChecker()
	ctx := context.Background()

	enterpriseFeatures := []license.Feature{
		license.FeatureSnapshotBackup,
		license.FeatureRetentionPrune,
		license.FeatureTelemetryProbe,
		license.FeatureWebhookAlerts,
	}

	// Verify all enterprise features return ErrFeatureNotLicensed across all methods
	for _, feat := range enterpriseFeatures {
		ok, err := checker.Check(ctx, feat)
		if ok {
			t.Fatalf("CommunityChecker.Check(%s) returned true, expected false", feat)
		}
		if !errors.Is(err, license.ErrFeatureNotLicensed) {
			t.Fatalf("CommunityChecker.Check(%s) err = %v, expected ErrFeatureNotLicensed", feat, err)
		}

		err = checker.Require(ctx, feat)
		if !errors.Is(err, license.ErrFeatureNotLicensed) {
			t.Fatalf("CommunityChecker.Require(%s) err = %v, expected ErrFeatureNotLicensed", feat, err)
		}

		if checker.IsFeatureEnabled(ctx, feat) {
			t.Fatalf("CommunityChecker.IsFeatureEnabled(%s) returned true, expected false", feat)
		}
	}

	// ValidateLicense in community edition MUST always return ErrFeatureNotLicensed
	_, err := checker.ValidateLicense(ctx, "any-valid-or-invalid-license-string")
	if !errors.Is(err, license.ErrFeatureNotLicensed) {
		t.Fatalf("CommunityChecker.ValidateLicense returned %v, expected ErrFeatureNotLicensed", err)
	}

	// Concurrency test: 50 goroutines invoking CommunityChecker simultaneously
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f := enterpriseFeatures[idx%len(enterpriseFeatures)]
			if checker.IsFeatureEnabled(ctx, f) {
				t.Errorf("concurrent check failed for %s", f)
			}
			_ = checker.GetLicenseInfo(ctx)
			_, _ = checker.Check(ctx, f)
			_ = checker.Require(ctx, f)
		}(i)
	}
	wg.Wait()
}
