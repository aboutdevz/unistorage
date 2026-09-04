package ssdlc_test

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find project root containing go.mod from %s", dir)
		}
		dir = parent
	}
}

// -----------------------------------------------------------------------------
// 1. Golangci-lint SAST Configuration Test
// -----------------------------------------------------------------------------
func TestGolangciLint_Config(t *testing.T) {
	root := findProjectRoot(t)
	configPath := filepath.Join(root, ".golangci.yml")

	contentBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read .golangci.yml: %v", err)
	}
	content := string(contentBytes)

	// Verify run settings
	runSettings := []string{
		"timeout: 5m",
		"go: '1.22'",
		"tests: true",
		"- vendor",
		"- testdata",
		"- .agents",
		"- bin",
	}
	for _, setting := range runSettings {
		if !strings.Contains(content, setting) {
			t.Errorf(".golangci.yml missing run setting %q", setting)
		}
	}

	// Verify linters-settings
	lintersSettings := []string{
		"gosec:",
		"severity: medium",
		"confidence: medium",
		"- G104",
		"errcheck:",
		"check-type-assertions: true",
		"check-blank: true",
		"govet:",
		"check-shadowing: true",
		"enable-all: true",
		"revive:",
		"name: exported",
		"name: var-naming",
		"gocritic:",
		"- diagnostic",
		"- style",
		"- performance",
		"- security",
	}
	for _, linterSetting := range lintersSettings {
		if !strings.Contains(content, linterSetting) {
			t.Errorf(".golangci.yml missing linters-setting %q", linterSetting)
		}
	}

	// Verify enabled linters
	requiredLinters := []string{
		"- gosec",
		"- errcheck",
		"- ineffassign",
		"- staticcheck",
		"- unused",
		"- govet",
		"- revive",
		"- gocritic",
		"- bodyclose",
		"- noctx",
		"- prealloc",
		"- exportloopref",
	}
	for _, linter := range requiredLinters {
		if !strings.Contains(content, linter) {
			t.Errorf(".golangci.yml missing required enabled linter %q", linter)
		}
	}
}

// -----------------------------------------------------------------------------
// 2. Gitleaks Secret Detection Configuration Test
// -----------------------------------------------------------------------------
func TestGitleaks_Config(t *testing.T) {
	root := findProjectRoot(t)
	configPath := filepath.Join(root, ".gitleaks.toml")

	contentBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read .gitleaks.toml: %v", err)
	}
	content := string(contentBytes)

	// Verify base settings
	if !strings.Contains(content, "useDefault = true") {
		t.Errorf(".gitleaks.toml missing 'useDefault = true'")
	}

	// Verify custom rules exist
	customRules := []struct {
		id          string
		description string
		regex       string
		testSecret  string
		mustMatch   bool
	}{
		{
			id:          "unistorage-bearer-token",
			description: "Detected UniStorage Daemon Bearer Token",
			regex:       `(?i)(?:unistorage[_-]?token|bearer[_-]?token)[\s:=]+["']?([a-f0-9]{64})["']?`,
			testSecret:  `unistorage_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
			mustMatch:   true,
		},
		{
			id:          "s3-access-key-id",
			description: "Detected S3 Access Key ID",
			regex:       `(?i)(?:aws_access_key_id|minio_root_user|s3_access_key)[\s:=]+["']?(AKIA[0-9A-Z]{16}|minioadmin|[a-zA-Z0-9]{20})["']?`,
			testSecret:  `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`,
			mustMatch:   true,
		},
		{
			id:          "s3-secret-access-key",
			description: "Detected S3 Secret Access Key",
			regex:       `(?i)(?:aws_secret_access_key|minio_root_password|s3_secret_key)[\s:=]+["']?([a-zA-Z0-9/+=]{40})["']?`,
			testSecret:  `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			mustMatch:   true,
		},
		{
			id:          "argon2id-secret-param",
			description: "Detected Argon2id Passphrase or Seed",
			regex:       `(?i)(?:argon2id_passphrase|vault_master_key)[\s:=]+["']?([^'"\s]{12,})["']?`,
			testSecret:  `vault_master_key = "verySecretMasterPassphrase123"`,
			mustMatch:   true,
		},
	}

	for _, rule := range customRules {
		if !strings.Contains(content, `id = "`+rule.id+`"`) {
			t.Errorf(".gitleaks.toml missing custom rule id %q", rule.id)
		}
		if !strings.Contains(content, rule.description) {
			t.Errorf(".gitleaks.toml missing description for rule %q", rule.id)
		}

		// Compile and verify regex matches target pattern
		re, err := regexp.Compile(rule.regex)
		if err != nil {
			t.Errorf("failed to compile regex for rule %q: %v", rule.id, err)
			continue
		}
		matched := re.MatchString(rule.testSecret)
		if matched != rule.mustMatch {
			t.Errorf("rule %q regex match got %v, want %v for input %q", rule.id, matched, rule.mustMatch, rule.testSecret)
		}
	}

	// Verify allowlist entries
	requiredAllowlistPaths := []string{
		`pkg/storage/s3/.*_test\.go`,
		`pkg/vault/.*_test\.go`,
		`docker-compose\.yml`,
		`tests/.*_test\.go`,
	}
	for _, path := range requiredAllowlistPaths {
		if !strings.Contains(content, path) {
			t.Errorf(".gitleaks.toml allowlist missing path pattern %q", path)
		}
	}

	if !strings.Contains(content, "minioadmin") {
		t.Errorf(".gitleaks.toml allowlist missing regex 'minioadmin'")
	}
}

// -----------------------------------------------------------------------------
// 3. GitHub Actions SSDLC Workflow Test
// -----------------------------------------------------------------------------
func TestGitHubActions_SSDLCWorkflow(t *testing.T) {
	root := findProjectRoot(t)
	workflowPath := filepath.Join(root, ".github", "workflows", "ssdlc.yml")

	contentBytes, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("failed to read .github/workflows/ssdlc.yml: %v", err)
	}
	content := string(contentBytes)

	// Verify triggers & permissions
	triggerChecks := []string{
		"push:",
		"branches: [ main, \"release/*\" ]",
		"pull_request:",
		"branches: [ main ]",
		"contents: read",
		"id-token: write",
		"security-events: write",
	}
	for _, check := range triggerChecks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml missing trigger/permission directive %q", check)
		}
	}

	// Verify all 7 jobs exist
	requiredJobs := []string{
		"test:",
		"sast:",
		"sca:",
		"secret-scan:",
		"fuzz:",
		"docker-verify:",
		"sbom-provenance:",
	}
	for _, job := range requiredJobs {
		if !strings.Contains(content, job) {
			t.Errorf("ssdlc.yml missing job definition %q", job)
		}
	}

	// Verify Job 1 (test matrix)
	job1Checks := []string{
		"os: [ubuntu-latest, windows-latest, macos-latest]",
		"go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...",
		"actions/upload-artifact@v4",
	}
	for _, check := range job1Checks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml job 'test' missing %q", check)
		}
	}

	// Verify Job 2 (sast)
	job2Checks := []string{
		"golangci/golangci-lint-action@v6",
		"--config=.golangci.yml",
		"gosec -fmt=sarif -out=gosec-results.sarif",
		"github/codeql-action/upload-sarif@v3",
	}
	for _, check := range job2Checks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml job 'sast' missing %q", check)
		}
	}

	// Verify Job 3 (sca)
	job3Checks := []string{
		"golang.org/x/vuln/cmd/govulncheck@latest",
		"govulncheck ./...",
	}
	for _, check := range job3Checks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml job 'sca' missing %q", check)
		}
	}

	// Verify Job 4 (secret-scan)
	job4Checks := []string{
		"fetch-depth: 0",
		"gitleaks/gitleaks-action@v2",
		"GITLEAKS_CONFIG: .gitleaks.toml",
	}
	for _, check := range job4Checks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml job 'secret-scan' missing %q", check)
		}
	}

	// Verify Job 5 (fuzz)
	job5Checks := []string{
		"go test -v -fuzz=FuzzPathSanitizer -fuzztime=30s ./pkg/storage/local",
	}
	for _, check := range job5Checks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml job 'fuzz' missing %q", check)
		}
	}

	// Verify Job 6 (docker-verify)
	job6Checks := []string{
		"docker/setup-buildx-action@v3",
		"docker/build-push-action@v5",
		"tags: unistorage:test",
		"10001",
	}
	for _, check := range job6Checks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml job 'docker-verify' missing %q", check)
		}
	}

	// Verify Job 7 (sbom-provenance)
	job7Checks := []string{
		"needs: [test, sast, sca, secret-scan, fuzz, docker-verify]",
		"sigstore/cosign-installer@v3.5.0",
		"anchore/sbom-action/download-syft@v0.16.0",
		"syft dir:. -o cyclonedx-json=sbom.cyclonedx.json",
		"sbom-cyclonedx",
	}
	for _, check := range job7Checks {
		if !strings.Contains(content, check) {
			t.Errorf("ssdlc.yml job 'sbom-provenance' missing %q", check)
		}
	}
}

// -----------------------------------------------------------------------------
// 4. Security Policy Content Test
// -----------------------------------------------------------------------------
func TestSecurityPolicy_Content(t *testing.T) {
	root := findProjectRoot(t)
	policyPath := filepath.Join(root, "SECURITY.md")

	contentBytes, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("failed to read SECURITY.md: %v", err)
	}
	content := string(contentBytes)

	// Check Supported Versions
	if !strings.Contains(content, "0.1.x") || !strings.Contains(content, "< 0.1.0") {
		t.Errorf("SECURITY.md missing supported versions 0.1.x / < 0.1.0")
	}

	// Check reporting channels
	if !strings.Contains(content, "security@aboutdevz.org") {
		t.Errorf("SECURITY.md missing disclosure email 'security@aboutdevz.org'")
	}
	if !strings.Contains(content, "github.com/aboutdevz/unistorage/security/advisories/new") {
		t.Errorf("SECURITY.md missing GitHub Private Vulnerability Reporting link")
	}

	// Check strict prohibition of public issues
	prohibitionRegex := regexp.MustCompile(`(?i)DO\s+NOT\s+submit\s+public\s+github\s+issues`)
	if !prohibitionRegex.MatchString(content) {
		t.Errorf("SECURITY.md missing strict prohibition against submitting public GitHub issues")
	}

	// Check disclosure report guidelines
	guidelines := []string{
		"Description",
		"Reproduction Steps",
		"Impact Assessment",
		"Affected Components",
		"cmd/unistorage",
		"pkg/storage",
		"pkg/vault",
		"internal/daemon",
	}
	for _, item := range guidelines {
		if !strings.Contains(content, item) {
			t.Errorf("SECURITY.md missing disclosure guideline item %q", item)
		}
	}

	// Check SLA timelines
	slas := []string{
		"24 hours",
		"72 hours",
		"30 days",
	}
	for _, sla := range slas {
		if !strings.Contains(content, sla) {
			t.Errorf("SECURITY.md missing SLA timeline requirement %q", sla)
		}
	}
}

// -----------------------------------------------------------------------------
// 5. Formal STRIDE Threat Model Content Test
// -----------------------------------------------------------------------------
func TestSTRIDEThreatModel_Content(t *testing.T) {
	root := findProjectRoot(t)
	modelPath := filepath.Join(root, "docs", "threat-model.md")

	contentBytes, err := os.ReadFile(modelPath)
	if err != nil {
		t.Fatalf("failed to read docs/threat-model.md: %v", err)
	}
	content := string(contentBytes)

	// Check STRIDE categories
	strideCategories := []string{
		"Spoofing",
		"Tampering",
		"Repudiation",
		"Information Disclosure",
		"Denial of Service",
		"Elevation of Privilege",
	}
	for _, cat := range strideCategories {
		if !strings.Contains(content, cat) {
			t.Errorf("docs/threat-model.md missing STRIDE category %q", cat)
		}
	}

	// Check Core Components
	components := []string{
		"internal/daemon",
		"pkg/storage/local",
		"pkg/storage/s3",
		"pkg/vault",
		"pkg/entitlement",
		"cmd/unistorage",
		"Dockerfile",
	}
	for _, comp := range components {
		if !strings.Contains(content, comp) {
			t.Errorf("docs/threat-model.md missing core component reference %q", comp)
		}
	}

	// Check Specific Mitigations & Controls
	mitigations := []string{
		"Bearer token",
		"0600",
		"Host header validation",
		"CORS",
		"SanitizePath",
		"FuzzPathSanitizer",
		"Argon2id",
		"AES-256-GCM",
		"MemZero",
		"manifest.json",
		"anti-double-run mutex",
		"10001:10001",
		"read_only",
	}
	for _, mit := range mitigations {
		if !strings.Contains(content, mit) {
			t.Errorf("docs/threat-model.md missing security mitigation %q", mit)
		}
	}
}

// -----------------------------------------------------------------------------
// 6. Gitignore Rules Validation Test
// -----------------------------------------------------------------------------
func matchGitignoreRule(rule string, path string) bool {
	cleanRule := strings.TrimSpace(rule)
	if cleanRule == "" || strings.HasPrefix(cleanRule, "#") {
		return false
	}

	isDirOnly := strings.HasSuffix(cleanRule, "/")
	cleanRule = strings.TrimSuffix(cleanRule, "/")

	normalizedPath := filepath.ToSlash(path)
	parts := strings.Split(normalizedPath, "/")
	baseName := filepath.Base(normalizedPath)

	if isDirOnly {
		for i, part := range parts {
			if matched, _ := filepath.Match(cleanRule, part); matched {
				if i < len(parts)-1 || isDirOnly {
					return true
				}
			}
		}
		if matched, _ := filepath.Match(cleanRule, normalizedPath); matched {
			return true
		}
	} else {
		if matched, _ := filepath.Match(cleanRule, baseName); matched {
			return true
		}
		if matched, _ := filepath.Match(cleanRule, normalizedPath); matched {
			return true
		}
		for _, part := range parts {
			if matched, _ := filepath.Match(cleanRule, part); matched {
				return true
			}
		}
	}

	return false
}

func TestGitignore_Rules(t *testing.T) {
	root := findProjectRoot(t)
	gitignorePath := filepath.Join(root, ".gitignore")

	file, err := os.Open(gitignorePath)
	if err != nil {
		t.Fatalf("failed to open .gitignore: %v", err)
	}
	defer file.Close()

	var rules []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			rules = append(rules, line)
		}
	}

	isIgnored := func(path string) bool {
		for _, rule := range rules {
			if matchGitignoreRule(rule, path) {
				return true
			}
		}
		return false
	}

	// Must be ignored
	mustIgnore := []string{
		".agents",
		".agents/worker_1/plan.md",
		".agent",
		".gemini",
		".antigravity",
		"brain",
		"worktrees",
		"task.plan.md",
		"prompt_draft.md",
		"bin/unistorage",
		"dist/bundle.zip",
		"unistorage.exe",
		"license.test.exe",
		"temp.test",
		"output.out",
		"coverage.html",
		"coverage.txt",
		"coverage.out",
		"daemon.token",
		"my.token",
		"secrets.vault",
		"vault.db",
		".conflicts",
		".conflicts/backup.dat",
		"data/store.db",
		"tmp/scratch.bin",
		".minio_data",
		"docker-data",
		"id_rsa",
		"id_rsa.pub",
		"id_ed25519",
		"id_ed25519.pub",
		"id_ecdsa",
		"id_dsa",
		"id_custom_key",
		".ssh/id_rsa",
		".ssh/config",
		"known_hosts",
		"authorized_keys",
		".env",
		".env.local",
		".env.production",
		"credentials.json",
		"server.key",
		"server.cert",
		"server.crt",
		"server.pem",
	}

	for _, path := range mustIgnore {
		if !isIgnored(path) {
			t.Errorf("expected .gitignore to filter %q, but it did not", path)
		}
	}

	// Must NOT be ignored (critical source files)
	mustKeep := []string{
		"go.mod",
		"go.sum",
		"Dockerfile",
		"docker-compose.yml",
		"SECURITY.md",
		".golangci.yml",
		".gitleaks.toml",
		"cmd/unistorage/main.go",
		"pkg/storage/driver.go",
		"pkg/vault/vault.go",
		"docs/threat-model.md",
		"tests/ssdlc/ssdlc_test.go",
	}

	for _, path := range mustKeep {
		if isIgnored(path) {
			t.Errorf("expected .gitignore to KEEP %q, but it matched an ignore rule", path)
		}
	}
}

// -----------------------------------------------------------------------------
// 7. Native FuzzPathSanitizer Execution Test
// -----------------------------------------------------------------------------
func TestFuzzPathSanitizer_Execution(t *testing.T) {
	tempRoot := t.TempDir()
	sanitizer, err := local.NewPathSanitizer(tempRoot)
	if err != nil {
		t.Fatalf("failed to create path sanitizer: %v", err)
	}

	// Test a battery of malicious traversal attack vectors
	attackVectors := []struct {
		name string
		path string
	}{
		{"dotdot parent", "../outside.txt"},
		{"windows dotdot", `..\outside.txt`},
		{"nested dotdot", "sub/../../outside.txt"},
		{"double slash traversal", "....//....//etc/passwd"},
		{"null byte injection", "file\x00malicious.txt"},
		{"windows device con", "CON"},
		{"windows device prn", "PRN"},
		{"windows device aux", "AUX"},
		{"windows device nul", "NUL"},
		{"windows device com1", "COM1"},
		{"windows device lpt1", "LPT1"},
		{"windows device in subdir", "sub/dir/CON.txt"},
		{"windows ADS", "file.txt::$DATA"},
	}

	for _, tc := range attackVectors {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sanitizer.Sanitize(tc.path)
			if err == nil {
				t.Fatalf("expected error for attack vector %q, got nil", tc.path)
			}
			if !errors.Is(err, storage.ErrPathTraversal) && !errors.Is(err, storage.ErrInvalidPath) {
				t.Fatalf("expected ErrPathTraversal or ErrInvalidPath for %q, got %v", tc.path, err)
			}
		})
	}

	// Verify valid paths sanitize cleanly inside root
	validPaths := []string{
		"simple.txt",
		"sub/dir/nested.log",
		"dir/./file.txt",
	}
	for _, p := range validPaths {
		sanitized, err := sanitizer.Sanitize(p)
		if err != nil {
			t.Errorf("unexpected error for valid path %q: %v", p, err)
		}
		rel, err := filepath.Rel(sanitizer.CanonicalRoot(), sanitized)
		if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
			t.Errorf("sanitized path %q escaped canonical root: rel=%q", sanitized, rel)
		}
	}

	// Run quick fuzz test invocation via go test command if not short
	if !testing.Short() {
		root := findProjectRoot(t)
		goBin := "go"
		if customGo := os.Getenv("GOROOT"); customGo != "" {
			candidate := filepath.Join(customGo, "bin", "go.exe")
			if _, err := os.Stat(candidate); err == nil {
				goBin = candidate
			}
		} else if _, err := os.Stat(`C:\Program Files\Go\bin\go.exe`); err == nil {
			goBin = `C:\Program Files\Go\bin\go.exe`
		}

		cmd := exec.Command(goBin, "test", "-v", "-fuzz=FuzzPathSanitizer", "-fuzztime=3s", "./pkg/storage/local")
		cmd.Dir = root
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("FuzzPathSanitizer execution failed: %v\nOutput:\n%s", err, string(output))
		}
	}
}

// -----------------------------------------------------------------------------
// 8. Open-Source Community Health & Configuration Files Test
// -----------------------------------------------------------------------------
func TestCommunityAndRepoHealth_Files(t *testing.T) {
	root := findProjectRoot(t)

	requiredFiles := map[string][]string{
		"LICENSE": {
			"Apache License",
			"Version 2.0",
			"http://www.apache.org/licenses/",
		},
		"CONTRIBUTING.md": {
			"Contributing to UniStorage",
			"Open-Core Architecture Philosophy",
			"Conventional Commits",
			"docker compose up -d",
			"FuzzPathSanitizer",
		},
		"CODE_OF_CONDUCT.md": {
			"Contributor Covenant Code of Conduct",
			"Our Pledge",
			"Our Standards",
		},
		"SUPPORT.md": {
			"Getting Support for UniStorage",
			"GitHub Discussions",
			"Diagnostic Checklist Before Asking",
		},
		"CHANGELOG.md": {
			"Keep a Changelog",
			"Semantic Versioning",
			"[0.1.0]",
		},
		".github/CODEOWNERS": {
			"* @aboutdevz/core-maintainers",
			"/pkg/vault/ @aboutdevz/security-team",
			"/.github/workflows/ @aboutdevz/devops-team",
		},
		".github/dependabot.yml": {
			`package-ecosystem: "gomod"`,
			`package-ecosystem: "github-actions"`,
			`package-ecosystem: "docker"`,
		},
		".github/ISSUE_TEMPLATE/config.yml": {
			"blank_issues_enabled: false",
			"security/advisories/new",
		},
		".github/ISSUE_TEMPLATE/bug_report.yml": {
			`name: "Bug Report"`,
			"UniStorage Version",
			"Storage Backend Affected",
		},
		".github/ISSUE_TEMPLATE/feature_request.yml": {
			`name: "Feature Request"`,
			"Target Subsystem",
		},
		".goreleaser.yml": {
			"version: 2",
			"project_name: unistorage",
			"main.Version={{.Version}}",
		},
		".pre-commit-config.yaml": {
			"repo: https://github.com/pre-commit/pre-commit-hooks",
			"repo: https://github.com/gitleaks/gitleaks",
			"repo: https://github.com/golangci/golangci-lint",
		},
		".githooks/pre-commit": {
			"UniStorage Pre-Commit Hook",
			"gofmt",
		},
		"docs/repository-setup.md": {
			"UniStorage GitHub Repository Setup & Maintainer Guide",
			"Branch Protection Rules",
			"First Release Tagging Workflow",
		},
	}

	for relPath, patterns := range requiredFiles {
		fullPath := filepath.Join(root, filepath.FromSlash(relPath))
		contentBytes, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("missing required open-source health file: %s (%v)", relPath, err)
			continue
		}
		content := string(contentBytes)
		for _, pat := range patterns {
			if !strings.Contains(content, pat) {
				t.Errorf("file %s missing required content pattern %q", relPath, pat)
			}
		}
	}
}

