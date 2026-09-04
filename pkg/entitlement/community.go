//go:build !enterprise

package entitlement

import (
	"context"
	"fmt"
	"time"
)

// CommunityChecker enforces open-core restrictions for non-enterprise users.
type CommunityChecker struct{}

// NewCommunityChecker constructs an unencumbered community checker.
func NewCommunityChecker() *CommunityChecker {
	return &CommunityChecker{}
}

// NewDefaultChecker returns the active EntitlementChecker based on build configuration.
// Under OSS (!enterprise), this defaults to the unencumbered CommunityChecker.
func NewDefaultChecker() EntitlementChecker {
	return NewCommunityChecker()
}

// Check evaluates whether the feature is licensed. Community denies all enterprise features.
func (c *CommunityChecker) Check(ctx context.Context, feature Feature) (bool, error) {
	if IsEnterpriseFeature(feature) {
		return false, fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
	}
	return true, nil
}

// Require returns an error if the requested feature is not licensed.
func (c *CommunityChecker) Require(ctx context.Context, feature Feature) error {
	ok, err := c.Check(ctx, feature)
	if !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
	}
	return nil
}

// LicenseInfo returns community edition metadata.
func (c *CommunityChecker) LicenseInfo() (*LicenseInfo, error) {
	info := c.GetLicenseInfo(context.Background())
	return &info, nil
}

// IsFeatureEnabled returns false for all enterprise features.
func (c *CommunityChecker) IsFeatureEnabled(ctx context.Context, feat Feature) bool {
	ok, _ := c.Check(ctx, feat)
	return ok
}

// GetLicenseInfo returns metadata for community tier.
func (c *CommunityChecker) GetLicenseInfo(ctx context.Context) LicenseInfo {
	return LicenseInfo{
		Tier:       TierCommunity,
		CustomerID: "community-user",
		LicensedTo: "Community User",
		IssuedAt:   time.Time{},
		ExpiresAt:  time.Time{},
		Features:   []Feature{},
		NodeLimit:  1,
		IsExpired:  false,
	}
}

// ValidateLicense denies validation in community checker.
func (c *CommunityChecker) ValidateLicense(ctx context.Context, licenseKey string) (*LicenseInfo, error) {
	return nil, ErrFeatureNotLicensed
}
