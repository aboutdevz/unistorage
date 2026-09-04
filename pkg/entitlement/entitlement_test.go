package entitlement_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/entitlement"
)

func TestCommunityChecker_DeniesEnterpriseFeatures(t *testing.T) {
	checker := entitlement.NewCommunityChecker()
	ctx := context.Background()

	enterpriseFeatures := []entitlement.Feature{
		entitlement.FeatureSnapshotBackup,
		entitlement.FeatureRetentionPrune,
		entitlement.FeatureTelemetryProbe,
		entitlement.FeatureWebhookAlerts,
	}

	for _, feat := range enterpriseFeatures {
		t.Run(string(feat), func(t *testing.T) {
			ok, err := checker.Check(ctx, feat)
			if ok {
				t.Fatalf("expected feature %s to be denied in community edition", feat)
			}
			if !errors.Is(err, entitlement.ErrFeatureNotLicensed) {
				t.Fatalf("expected ErrFeatureNotLicensed, got: %v", err)
			}

			if checker.IsFeatureEnabled(ctx, feat) {
				t.Fatalf("IsFeatureEnabled returned true for %s", feat)
			}

			reqErr := checker.Require(ctx, feat)
			if !errors.Is(reqErr, entitlement.ErrFeatureNotLicensed) {
				t.Fatalf("Require expected ErrFeatureNotLicensed, got: %v", reqErr)
			}
		})
	}
}

func TestCommunityChecker_AllowsUnknownFeature(t *testing.T) {
	checker := entitlement.NewCommunityChecker()
	ctx := context.Background()

	customFeat := entitlement.Feature("core.basic_sync")
	ok, err := checker.Check(ctx, customFeat)
	if !ok || err != nil {
		t.Fatalf("expected core feature to be allowed, got ok=%v, err=%v", ok, err)
	}
}

func TestCommunityChecker_LicenseInfo(t *testing.T) {
	checker := entitlement.NewCommunityChecker()
	info, err := checker.LicenseInfo()
	if err != nil {
		t.Fatalf("unexpected error getting license info: %v", err)
	}
	if info.Tier != entitlement.TierCommunity {
		t.Fatalf("expected tier %s, got %s", entitlement.TierCommunity, info.Tier)
	}
	if info.IsExpired {
		t.Fatal("community license should not be marked expired")
	}

	_, valErr := checker.ValidateLicense(context.Background(), "invalid-token")
	if !errors.Is(valErr, entitlement.ErrFeatureNotLicensed) {
		t.Fatalf("ValidateLicense expected ErrFeatureNotLicensed, got: %v", valErr)
	}
}

func TestNewDefaultChecker(t *testing.T) {
	checker := entitlement.NewDefaultChecker()
	if checker == nil {
		t.Fatal("NewDefaultChecker returned nil")
	}
	if checker.IsFeatureEnabled(context.Background(), entitlement.FeatureSnapshotBackup) {
		t.Fatal("default checker should deny enterprise feature under OSS build")
	}
}
