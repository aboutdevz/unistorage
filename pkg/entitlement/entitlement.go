package entitlement

import (
	"context"
	"errors"
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

// Standard license and entitlement errors.
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

// EntitlementChecker verifies feature access rights across OSS and Enterprise tiers.
type EntitlementChecker interface {
	Check(ctx context.Context, feature Feature) (bool, error)
	Require(ctx context.Context, feature Feature) error
	LicenseInfo() (*LicenseInfo, error)
	IsFeatureEnabled(ctx context.Context, feat Feature) bool
	GetLicenseInfo(ctx context.Context) LicenseInfo
	ValidateLicense(ctx context.Context, licenseKey string) (*LicenseInfo, error)
}

// IsEnterpriseFeature checks if a feature belongs to commercial tiers.
func IsEnterpriseFeature(f Feature) bool {
	switch f {
	case FeatureSnapshotBackup, FeatureRetentionPrune, FeatureTelemetryProbe, FeatureWebhookAlerts:
		return true
	default:
		return false
	}
}
