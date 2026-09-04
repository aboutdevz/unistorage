package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestMain coordinates pre-flight discovery and summary logging for the E2E test suite.
func TestMain(m *testing.M) {
	fmt.Println("=== UniStorage MVP Opaque-Box E2E Test Suite ===")
	fmt.Println("Methodology: Opaque-Box Requirement-Driven Testing")
	fmt.Println("Tiers: Tier 1 (Coverage), Tier 2 (Boundaries), Tier 3 (Cross-Feature), Tier 4 (Scenarios)")

	// Inspect environment
	if _, err := exec.LookPath("unistorage"); err == nil {
		fmt.Println("[E2E Info] Detected unistorage CLI executable in PATH.")
	} else if _, err := os.Stat("../../bin/unistorage.exe"); err == nil {
		fmt.Println("[E2E Info] Detected bin/unistorage.exe binary.")
	} else if _, err := os.Stat("../../bin/unistorage"); err == nil {
		fmt.Println("[E2E Info] Detected bin/unistorage binary.")
	} else {
		fmt.Println("[E2E Info] Binary not pre-compiled; progressive test runner active.")
	}

	exitCode := m.Run()
	fmt.Println("=== E2E Test Suite Execution Complete ===")
	os.Exit(exitCode)
}
