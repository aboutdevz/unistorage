package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// LicenseKey represents the unmarshaled license data.
type LicenseKey struct {
	CustomerID string      `json:"customer_id"`
	LicensedTo string      `json:"licensed_to"`
	IssuedAt   time.Time   `json:"issued_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Features   []Feature   `json:"features"`
	NodeLimit  int         `json:"node_limit"`
	Tier       LicenseTier `json:"tier"`
	Signature  string      `json:"signature,omitempty"`
}

type canonicalPayload struct {
	CustomerID string   `json:"customer_id"`
	LicensedTo string   `json:"licensed_to"`
	IssuedAt   int64    `json:"issued_at_unix"`
	ExpiresAt  int64    `json:"expires_at_unix"`
	Features   []string `json:"features"`
	NodeLimit  int      `json:"node_limit"`
	Tier       string   `json:"tier"`
}

// GenerateKeyPair generates an Ed25519 keypair for enterprise license signing.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func toPayloadBytes(key *LicenseKey) ([]byte, error) {
	feats := make([]string, len(key.Features))
	for i, f := range key.Features {
		feats[i] = string(f)
	}
	sort.Strings(feats)

	tier := string(key.Tier)
	if tier == "" {
		tier = string(TierEnterprise)
	}

	payload := canonicalPayload{
		CustomerID: key.CustomerID,
		LicensedTo: key.LicensedTo,
		IssuedAt:   key.IssuedAt.UTC().Unix(),
		ExpiresAt:  key.ExpiresAt.UTC().Unix(),
		Features:   feats,
		NodeLimit:  key.NodeLimit,
		Tier:       tier,
	}

	return json.Marshal(payload)
}

// SignLicense creates a signed token string (base64 payload . base64 signature).
func SignLicense(privKey ed25519.PrivateKey, key *LicenseKey) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key length")
	}

	payloadBytes, err := toPayloadBytes(key)
	if err != nil {
		return "", fmt.Errorf("failed to serialize payload: %w", err)
	}

	sig := ed25519.Sign(privKey, payloadBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	return fmt.Sprintf("%s.%s", payloadB64, sigB64), nil
}

// VerifyLicense decodes and validates the cryptographic token using Ed25519.
func VerifyLicense(pubKey ed25519.PublicKey, token string) (*LicenseKey, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length")
	}

	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: expected 2 dot-separated segments", ErrInvalidLicenseFormat)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 payload: %v", ErrInvalidLicenseFormat, err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64 signature: %v", ErrInvalidLicenseFormat, err)
	}

	if !ed25519.Verify(pubKey, payloadBytes, sigBytes) {
		return nil, ErrInvalidLicenseSignature
	}

	var cp canonicalPayload
	if err := json.Unmarshal(payloadBytes, &cp); err != nil {
		return nil, fmt.Errorf("%w: payload json parse error: %v", ErrInvalidLicenseFormat, err)
	}

	features := make([]Feature, len(cp.Features))
	for i, f := range cp.Features {
		features[i] = Feature(f)
	}

	lk := &LicenseKey{
		CustomerID: cp.CustomerID,
		LicensedTo: cp.LicensedTo,
		IssuedAt:   time.Unix(cp.IssuedAt, 0).UTC(),
		ExpiresAt:  time.Unix(cp.ExpiresAt, 0).UTC(),
		Features:   features,
		NodeLimit:  cp.NodeLimit,
		Tier:       LicenseTier(cp.Tier),
		Signature:  parts[1],
	}

	return lk, nil
}

// EnterpriseChecker validates license tokens and enforces licensed feature access.
type EnterpriseChecker struct {
	pubKey     ed25519.PublicKey
	currentKey *LicenseKey
	mu         sync.RWMutex
}

// NewEnterpriseChecker initializes an enterprise entitlement checker with an Ed25519 public key.
func NewEnterpriseChecker(pubKey ed25519.PublicKey, licenseToken string) (*EnterpriseChecker, error) {
	ec := &EnterpriseChecker{
		pubKey: pubKey,
	}

	if licenseToken != "" {
		if err := ec.LoadLicense(licenseToken); err != nil {
			return nil, err
		}
	}

	return ec, nil
}

// LoadLicense verifies and activates a new license token.
func (ec *EnterpriseChecker) LoadLicense(token string) error {
	lk, err := VerifyLicense(ec.pubKey, token)
	if err != nil {
		return err
	}

	ec.mu.Lock()
	ec.currentKey = lk
	ec.mu.Unlock()

	return nil
}

// Check evaluates whether the feature is licensed and current.
func (ec *EnterpriseChecker) Check(ctx context.Context, feature Feature) (bool, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	if ec.currentKey == nil {
		return false, ErrLicenseMissing
	}

	if time.Now().UTC().After(ec.currentKey.ExpiresAt) {
		return false, ErrLicenseExpired
	}

	for _, f := range ec.currentKey.Features {
		if f == feature {
			return true, nil
		}
	}

	return false, fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
}

// Require returns an error if the feature is not licensed.
func (ec *EnterpriseChecker) Require(ctx context.Context, feature Feature) error {
	ok, err := ec.Check(ctx, feature)
	if !ok {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
	}
	return nil
}

// LicenseInfo returns the active license metadata.
func (ec *EnterpriseChecker) LicenseInfo() (*LicenseInfo, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	if ec.currentKey == nil {
		return nil, ErrLicenseMissing
	}

	isExpired := time.Now().UTC().After(ec.currentKey.ExpiresAt)
	info := &LicenseInfo{
		Tier:       ec.currentKey.Tier,
		CustomerID: ec.currentKey.CustomerID,
		LicensedTo: ec.currentKey.LicensedTo,
		IssuedAt:   ec.currentKey.IssuedAt,
		ExpiresAt:  ec.currentKey.ExpiresAt,
		Features:   append([]Feature{}, ec.currentKey.Features...),
		NodeLimit:  ec.currentKey.NodeLimit,
		IsExpired:  isExpired,
		Signature:  ec.currentKey.Signature,
	}

	return info, nil
}

// IsFeatureEnabled returns boolean status of feature license.
func (ec *EnterpriseChecker) IsFeatureEnabled(ctx context.Context, feat Feature) bool {
	ok, _ := ec.Check(ctx, feat)
	return ok
}

// GetLicenseInfo returns metadata snapshot.
func (ec *EnterpriseChecker) GetLicenseInfo(ctx context.Context) LicenseInfo {
	info, err := ec.LicenseInfo()
	if err != nil || info == nil {
		return LicenseInfo{
			Tier:      TierCommunity,
			IsExpired: true,
		}
	}
	return *info
}

// ValidateLicense parses and verifies a candidate license token without activating it.
func (ec *EnterpriseChecker) ValidateLicense(ctx context.Context, token string) (*LicenseInfo, error) {
	lk, err := VerifyLicense(ec.pubKey, token)
	if err != nil {
		return nil, err
	}

	isExpired := time.Now().UTC().After(lk.ExpiresAt)
	return &LicenseInfo{
		Tier:       lk.Tier,
		CustomerID: lk.CustomerID,
		LicensedTo: lk.LicensedTo,
		IssuedAt:   lk.IssuedAt,
		ExpiresAt:  lk.ExpiresAt,
		Features:   append([]Feature{}, lk.Features...),
		NodeLimit:  lk.NodeLimit,
		IsExpired:  isExpired,
		Signature:  lk.Signature,
	}, nil
}
