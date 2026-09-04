//go:build enterprise

package entitlement

import (
	"sync"
)

var (
	enterpriseCheckerFactory func() EntitlementChecker
	factoryMu                sync.RWMutex
)

// RegisterEnterpriseChecker registers the commercial entitlement checker factory.
// This is called during init() by the private enterprise module.
func RegisterEnterpriseChecker(factory func() EntitlementChecker) {
	factoryMu.Lock()
	defer factoryMu.Unlock()
	enterpriseCheckerFactory = factory
}

// NewDefaultChecker returns the enterprise entitlement checker if registered,
// falling back to CommunityChecker.
func NewDefaultChecker() EntitlementChecker {
	factoryMu.RLock()
	defer factoryMu.RUnlock()
	if enterpriseCheckerFactory != nil {
		return enterpriseCheckerFactory()
	}
	return &CommunityChecker{}
}

// CommunityChecker remains available in enterprise builds as fallback.
type CommunityChecker struct{}

func NewCommunityChecker() *CommunityChecker {
	return &CommunityChecker{}
}
