package license_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/license"
)

func TestCommunityChecker(t *testing.T) {
	checker := license.NewCommunityChecker()
	ctx := context.Background()

	// Enterprise features should be rejected
	for _, feat := range []license.Feature{
		license.FeatureSnapshotBackup,
		license.FeatureRetentionPrune,
		license.FeatureTelemetryProbe,
		license.FeatureWebhookAlerts,
	} {
		ok, err := checker.Check(ctx, feat)
		if ok {
			t.Fatalf("expected feature %s to be rejected for community tier", feat)
		}
		if !errors.Is(err, license.ErrFeatureNotLicensed) {
			t.Fatalf("expected ErrFeatureNotLicensed for %s, got %v", feat, err)
		}

		err = checker.Require(ctx, feat)
		if !errors.Is(err, license.ErrFeatureNotLicensed) {
			t.Fatalf("expected ErrFeatureNotLicensed from Require(%s), got %v", feat, err)
		}

		if checker.IsFeatureEnabled(ctx, feat) {
			t.Fatalf("expected IsFeatureEnabled(%s) to be false", feat)
		}
	}

	// Community feature check
	ok, err := checker.Check(ctx, license.Feature("community.basic_storage"))
	if !ok || err != nil {
		t.Fatalf("expected non-enterprise feature to be allowed, got ok=%v err=%v", ok, err)
	}

	info, err := checker.LicenseInfo()
	if err != nil {
		t.Fatalf("unexpected error from LicenseInfo: %v", err)
	}
	if info.Tier != license.TierCommunity {
		t.Fatalf("expected TierCommunity, got %s", info.Tier)
	}

	_, err = checker.ValidateLicense(ctx, "any-token")
	if !errors.Is(err, license.ErrFeatureNotLicensed) {
		t.Fatalf("expected ErrFeatureNotLicensed from ValidateLicense, got %v", err)
	}
}

func TestEnterpriseLicense_ValidWorkflow(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	key := &license.LicenseKey{
		CustomerID: "cust-acme-corp",
		LicensedTo: "ACME Corporation",
		IssuedAt:   time.Now().Add(-1 * time.Hour),
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
		Features: []license.Feature{
			license.FeatureSnapshotBackup,
			license.FeatureRetentionPrune,
		},
		NodeLimit: 10,
		Tier:      license.TierEnterprise,
	}

	token, err := license.SignLicense(priv, key)
	if err != nil {
		t.Fatalf("SignLicense failed: %v", err)
	}

	checker, err := license.NewEnterpriseChecker(pub, token)
	if err != nil {
		t.Fatalf("NewEnterpriseChecker failed: %v", err)
	}

	ctx := context.Background()

	// Licensed features should succeed
	for _, feat := range key.Features {
		ok, err := checker.Check(ctx, feat)
		if !ok || err != nil {
			t.Fatalf("expected feature %s to be allowed, got ok=%v, err=%v", feat, ok, err)
		}
		if err := checker.Require(ctx, feat); err != nil {
			t.Fatalf("expected Require(%s) to succeed, got %v", feat, err)
		}
		if !checker.IsFeatureEnabled(ctx, feat) {
			t.Fatalf("expected IsFeatureEnabled(%s) to be true", feat)
		}
	}

	// Unlicensed feature should be rejected
	unlicensed := license.FeatureWebhookAlerts
	ok, err := checker.Check(ctx, unlicensed)
	if ok {
		t.Fatalf("expected feature %s to be denied", unlicensed)
	}
	if !errors.Is(err, license.ErrFeatureNotLicensed) {
		t.Fatalf("expected ErrFeatureNotLicensed, got %v", err)
	}
	if err := checker.Require(ctx, unlicensed); !errors.Is(err, license.ErrFeatureNotLicensed) {
		t.Fatalf("expected Require(%s) to return ErrFeatureNotLicensed, got %v", unlicensed, err)
	}

	// Info inspection
	info, err := checker.LicenseInfo()
	if err != nil {
		t.Fatalf("LicenseInfo failed: %v", err)
	}
	if info.CustomerID != "cust-acme-corp" {
		t.Fatalf("expected customer cust-acme-corp, got %s", info.CustomerID)
	}
	if info.Tier != license.TierEnterprise {
		t.Fatalf("expected TierEnterprise, got %s", info.Tier)
	}
	if info.IsExpired {
		t.Fatalf("expected license not to be expired")
	}
}

func TestEnterpriseLicense_Expiration(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	expiredKey := &license.LicenseKey{
		CustomerID: "cust-expired",
		LicensedTo: "Expired Corp",
		IssuedAt:   time.Now().Add(-48 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Features: []license.Feature{
			license.FeatureSnapshotBackup,
		},
		Tier: license.TierEnterprise,
	}

	token, err := license.SignLicense(priv, expiredKey)
	if err != nil {
		t.Fatalf("SignLicense failed: %v", err)
	}

	checker, err := license.NewEnterpriseChecker(pub, token)
	if err != nil {
		t.Fatalf("NewEnterpriseChecker failed: %v", err)
	}

	ctx := context.Background()
	ok, err := checker.Check(ctx, license.FeatureSnapshotBackup)
	if ok {
		t.Fatalf("expected expired license check to return false")
	}
	if !errors.Is(err, license.ErrLicenseExpired) {
		t.Fatalf("expected ErrLicenseExpired, got %v", err)
	}

	if err := checker.Require(ctx, license.FeatureSnapshotBackup); !errors.Is(err, license.ErrLicenseExpired) {
		t.Fatalf("expected Require to return ErrLicenseExpired, got %v", err)
	}

	info, err := checker.LicenseInfo()
	if err != nil {
		t.Fatalf("LicenseInfo failed: %v", err)
	}
	if !info.IsExpired {
		t.Fatalf("expected info.IsExpired to be true")
	}
}

func TestEnterpriseLicense_TamperedSignature(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	key := &license.LicenseKey{
		CustomerID: "cust-tamper",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Features:   []license.Feature{license.FeatureSnapshotBackup},
	}

	token, err := license.SignLicense(priv, key)
	if err != nil {
		t.Fatalf("SignLicense failed: %v", err)
	}

	// Tamper with payload (modify first char of base64 payload)
	parts := strings.Split(token, ".")
	tamperedPayload := "X" + parts[0][1:]
	tamperedToken := tamperedPayload + "." + parts[1]

	_, err = license.NewEnterpriseChecker(pub, tamperedToken)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) && !errors.Is(err, license.ErrInvalidLicenseFormat) {
		t.Fatalf("expected signature or format verification error, got %v", err)
	}

	// Tamper with signature
	otherPub, otherPriv, _ := license.GenerateKeyPair()
	_ = otherPub
	otherToken, _ := license.SignLicense(otherPriv, key)
	otherSig := strings.Split(otherToken, ".")[1]
	mismatchedSigToken := parts[0] + "." + otherSig

	_, err = license.NewEnterpriseChecker(pub, mismatchedSigToken)
	if !errors.Is(err, license.ErrInvalidLicenseSignature) {
		t.Fatalf("expected ErrInvalidLicenseSignature, got %v", err)
	}
}

func TestEnterpriseLicense_ValidateLicense(t *testing.T) {
	pub, priv, _ := license.GenerateKeyPair()

	key := &license.LicenseKey{
		CustomerID: "cust-validator",
		ExpiresAt:  time.Now().Add(10 * time.Hour),
		Features:   []license.Feature{license.FeatureTelemetryProbe},
		Tier:       license.TierEvaluation,
	}
	token, _ := license.SignLicense(priv, key)

	checker, _ := license.NewEnterpriseChecker(pub, "")
	info, err := checker.ValidateLicense(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateLicense failed: %v", err)
	}
	if info.CustomerID != "cust-validator" {
		t.Fatalf("expected cust-validator, got %s", info.CustomerID)
	}
	if info.Tier != license.TierEvaluation {
		t.Fatalf("expected TierEvaluation, got %s", info.Tier)
	}

	// Checker's own license should still be empty
	_, err = checker.LicenseInfo()
	if !errors.Is(err, license.ErrLicenseMissing) {
		t.Fatalf("expected ErrLicenseMissing on uninitialized checker, got %v", err)
	}
}

func TestEnterpriseLicense_ConcurrentAccess(t *testing.T) {
	pub, priv, _ := license.GenerateKeyPair()
	key1 := &license.LicenseKey{
		CustomerID: "cust-1",
		ExpiresAt:  time.Now().Add(5 * time.Hour),
		Features:   []license.Feature{license.FeatureSnapshotBackup},
	}
	tok1, _ := license.SignLicense(priv, key1)

	key2 := &license.LicenseKey{
		CustomerID: "cust-2",
		ExpiresAt:  time.Now().Add(5 * time.Hour),
		Features:   []license.Feature{license.FeatureSnapshotBackup, license.FeatureWebhookAlerts},
	}
	tok2, _ := license.SignLicense(priv, key2)

	checker, err := license.NewEnterpriseChecker(pub, tok1)
	if err != nil {
		t.Fatalf("NewEnterpriseChecker failed: %v", err)
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_ = checker.LoadLicense(tok2)
			} else {
				_ = checker.LoadLicense(tok1)
			}
			_, _ = checker.Check(ctx, license.FeatureSnapshotBackup)
			_ = checker.GetLicenseInfo(ctx)
		}(i)
	}

	wg.Wait()
}
