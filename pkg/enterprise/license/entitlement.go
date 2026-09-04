package license

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Feature represents a licensed capability.
type Feature string

const (
	FeatureSnapshotBackup Feature = "enterprise.snapshot_backup"
	FeatureRetentionPrune Feature = "enterprise.retention_prune"
	FeatureTelemetryProbe Feature = "enterprise.telemetry_probe"
	FeatureWebhookAlerts  Feature = "enterprise.webhook_alerts"
)

// LicenseTier designates the edition level.
type LicenseTier string

const (
	TierCommunity  LicenseTier = "community"
	TierEvaluation LicenseTier = "evaluation"
	TierEnterprise LicenseTier = "enterprise"
)

// Standard license errors.
var (
	ErrFeatureNotLicensed      = errors.New("feature not licensed in community edition")
	ErrLicenseExpired          = errors.New("license has expired")
	ErrInvalidLicenseSignature = errors.New("invalid cryptographic license signature")
	ErrInvalidLicenseFormat    = errors.New("invalid license format")
	ErrLicenseMissing          = errors.New("no license configured")
)

// LicenseInfo describes active license metadata.
type LicenseInfo struct {
	Tier       LicenseTier `json:"tier"`
	CustomerID string      `json:"customer_id"`
	LicensedTo string      `json:"licensed_to"`
	IssuedAt   time.Time   `json:"issued_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Features   []Feature   `json:"features"`
	NodeLimit  int         `json:"node_limit"`
	IsExpired  bool        `json:"is_expired"`
	Signature  string      `json:"signature,omitempty"`
}

// EntitlementChecker verifies feature access rights.
type EntitlementChecker interface {
	Check(ctx context.Context, feature Feature) (bool, error)
	Require(ctx context.Context, feature Feature) error
	LicenseInfo() (*LicenseInfo, error)
	IsFeatureEnabled(ctx context.Context, feat Feature) bool
	GetLicenseInfo(ctx context.Context) LicenseInfo
	ValidateLicense(ctx context.Context, licenseKey string) (*LicenseInfo, error)
}

// CommunityChecker enforces open-core restrictions for non-enterprise users.
type CommunityChecker struct{}

// NewCommunityChecker constructs an unencumbered community checker.
func NewCommunityChecker() *CommunityChecker {
	return &CommunityChecker{}
}

// Check evaluates whether the feature is licensed. Community denies all enterprise features.
func (c *CommunityChecker) Check(ctx context.Context, feature Feature) (bool, error) {
	if isEnterpriseFeature(feature) {
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

func isEnterpriseFeature(f Feature) bool {
	switch f {
	case FeatureSnapshotBackup, FeatureRetentionPrune, FeatureTelemetryProbe, FeatureWebhookAlerts:
		return true
	default:
		return false
	}
}
