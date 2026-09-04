package infra_test

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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

func TestDockerfile_StructureAndHardening(t *testing.T) {
	root := findProjectRoot(t)
	dockerfilePath := filepath.Join(root, "Dockerfile")

	contentBytes, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read Dockerfile at %s: %v", dockerfilePath, err)
	}
	content := strings.ReplaceAll(string(contentBytes), "\r\n", "\n")

	// 1. Multi-Stage Verification
	stage1Regex := regexp.MustCompile(`(?i)FROM\s+golang:(?:1\.[0-9]+-alpine|alpine)\s+AS\s+builder`)
	if !stage1Regex.MatchString(content) {
		t.Errorf("Dockerfile missing Stage 1 builder: expected 'FROM golang:<version>-alpine AS builder'")
	}

	stage2Regex := regexp.MustCompile(`(?i)FROM\s+alpine:3\.20`)
	if !stage2Regex.MatchString(content) {
		t.Errorf("Dockerfile missing Stage 2 runtime: expected 'FROM alpine:3.20'")
	}

	// 2. Static Binary Compilation Flags
	requiredBuildFlags := []string{
		"CGO_ENABLED=0",
		"-trimpath",
		`-ldflags="-s -w"`,
		"-o /build/unistorage",
		"./cmd/unistorage",
	}
	for _, flag := range requiredBuildFlags {
		if !strings.Contains(content, flag) {
			t.Errorf("Dockerfile builder missing compilation flag %q", flag)
		}
	}

	// 3. Unprivileged User Creation (UID:GID 10001:10001, /sbin/nologin)
	if !strings.Contains(content, "addgroup -g 10001 -S unistorage") {
		t.Errorf("Dockerfile missing addgroup for GID 10001")
	}
	if !strings.Contains(content, "adduser -u 10001 -S -G unistorage -h /home/unistorage -s /sbin/nologin unistorage") {
		t.Errorf("Dockerfile missing adduser for UID 10001 with /sbin/nologin shell")
	}

	// 4. Pre-create directories and permissions
	requiredDirsAndPerms := []string{
		"mkdir -p /build/config /build/data /build/tmp",
		"chown -R 10001:10001 /build/config /build/data /build/tmp",
		"chmod 0700 /build/config",
		"chmod 0750 /build/data",
		"chmod 1777 /build/tmp",
	}
	for _, p := range requiredDirsAndPerms {
		if !strings.Contains(content, p) {
			t.Errorf("Dockerfile missing directory permission step %q", p)
		}
	}

	// 5. Runtime Minimal Packages
	requiredPkgs := []string{"ca-certificates", "tzdata", "curl"}
	for _, pkg := range requiredPkgs {
		if !strings.Contains(content, pkg) {
			t.Errorf("Dockerfile runtime missing essential package %q", pkg)
		}
	}

	// 6. Copy artifacts from builder
	requiredCopies := []string{
		"COPY --from=builder /etc/passwd /etc/passwd",
		"COPY --from=builder /etc/group /etc/group",
		"--chown=10001:10001 /build/config /config",
		"--chown=10001:10001 /build/data /data",
		"--chown=10001:10001 /build/tmp /tmp",
		"--chown=10001:10001 /build/unistorage /usr/local/bin/unistorage",
	}
	for _, cp := range requiredCopies {
		if !strings.Contains(content, cp) {
			t.Errorf("Dockerfile runtime missing artifact copy step %q", cp)
		}
	}

	// 7. Hardened Runtime Directives
	userRegex := regexp.MustCompile(`(?m)^USER\s+10001:10001`)
	if !userRegex.MatchString(content) {
		t.Errorf("Dockerfile missing runtime 'USER 10001:10001'")
	}

	workdirRegex := regexp.MustCompile(`(?m)^WORKDIR\s+/home/unistorage`)
	if !workdirRegex.MatchString(content) {
		t.Errorf("Dockerfile missing 'WORKDIR /home/unistorage'")
	}

	volRegex := regexp.MustCompile(`(?m)^VOLUME\s+\["/config",\s*"/data"\]`)
	if !volRegex.MatchString(content) {
		t.Errorf(`Dockerfile missing 'VOLUME ["/config", "/data"]'`)
	}

	exposeRegex := regexp.MustCompile(`(?m)^EXPOSE\s+8080`)
	if !exposeRegex.MatchString(content) {
		t.Errorf("Dockerfile missing 'EXPOSE 8080'")
	}

	// 8. Healthcheck
	healthcheckRegex := regexp.MustCompile(`HEALTHCHECK.*CMD\s+curl\s+-f\s+http://127\.0\.0\.1:8080/api/v1/health\s+\|\|\s+exit\s+1`)
	if !healthcheckRegex.MatchString(strings.ReplaceAll(content, "\\\n", " ")) {
		t.Errorf("Dockerfile missing or incorrect HEALTHCHECK probing /api/v1/health")
	}

	// 9. Entrypoint & CMD
	entrypointRegex := regexp.MustCompile(`(?m)^ENTRYPOINT\s+\["/usr/local/bin/unistorage"\]`)
	if !entrypointRegex.MatchString(content) {
		t.Errorf(`Dockerfile missing 'ENTRYPOINT ["/usr/local/bin/unistorage"]'`)
	}

	cmdRegex := regexp.MustCompile(`(?m)^CMD\s+\["daemon",\s*"start",\s*"--foreground",\s*"--config",\s*"/config",\s*"--data",\s*"/data"\]`)
	if !cmdRegex.MatchString(content) {
		t.Errorf(`Dockerfile missing 'CMD ["daemon", "start", "--foreground", "--config", "/config", "--data", "/data"]'`)
	}
}

func TestDockerCompose_SyntaxAndServices(t *testing.T) {
	root := findProjectRoot(t)
	composePath := filepath.Join(root, "docker-compose.yml")

	contentBytes, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read docker-compose.yml at %s: %v", composePath, err)
	}
	content := string(contentBytes)

	// 1. Top-Level Elements & YAML Validity
	lines := strings.Split(content, "\n")
	hasVersion := false
	hasNetworks := false
	hasVolumes := false
	hasServices := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version:") {
			hasVersion = true
		}
		if strings.HasPrefix(trimmed, "networks:") {
			hasNetworks = true
		}
		if strings.HasPrefix(trimmed, "volumes:") {
			hasVolumes = true
		}
		if strings.HasPrefix(trimmed, "services:") {
			hasServices = true
		}
	}

	if !hasVersion {
		t.Errorf("docker-compose.yml missing version directive")
	}
	if !hasNetworks {
		t.Errorf("docker-compose.yml missing networks directive")
	}
	if !hasVolumes {
		t.Errorf("docker-compose.yml missing volumes directive")
	}
	if !hasServices {
		t.Errorf("docker-compose.yml missing services directive")
	}

	// 2. Specific Network and Volume Definitions
	if !strings.Contains(content, "unistorage-dev-net:") {
		t.Errorf("docker-compose.yml missing unistorage-dev-net network")
	}
	if !strings.Contains(content, "unistorage-config:") {
		t.Errorf("docker-compose.yml missing unistorage-config volume")
	}
	if !strings.Contains(content, "unistorage-data:") {
		t.Errorf("docker-compose.yml missing unistorage-data volume")
	}
	if !strings.Contains(content, "minio-data:") {
		t.Errorf("docker-compose.yml missing minio-data volume")
	}

	// 3. MinIO Service
	minioChecks := []string{
		"minio:",
		"image: minio/minio:RELEASE.2024-05-10T01-41-38Z",
		`"9000:9000"`,
		`"9001:9001"`,
		"minio-data:/data",
		"MINIO_ROOT_USER: minioadmin",
		"MINIO_ROOT_PASSWORD: minioadmin",
		"http://localhost:9000/minio/health/live",
	}
	for _, check := range minioChecks {
		if !strings.Contains(content, check) {
			t.Errorf("docker-compose.yml minio service missing %q", check)
		}
	}

	// 4. MinIO-Init Service
	initChecks := []string{
		"minio-init:",
		"image: minio/mc:RELEASE.2024-05-09T17-04-24Z",
		"condition: service_healthy",
		"alias set dev-s3 http://minio:9000 minioadmin minioadmin",
		"mb --ignore-existing dev-s3/unistorage-dev-bucket",
		"mb --ignore-existing dev-s3/test-bucket",
		"mb --ignore-existing dev-s3/backup-bucket",
		`restart: "no"`,
	}
	for _, check := range initChecks {
		if !strings.Contains(content, check) {
			t.Errorf("docker-compose.yml minio-init service missing %q", check)
		}
	}

	// 5. UniStorage Daemon Service & Hardening Constraints
	unistorageChecks := []string{
		"unistorage:",
		"context: .",
		"dockerfile: Dockerfile",
		"condition: service_completed_successfully",
		`"8080:8080"`,
		"UNISTORAGE_DAEMON_PORT: \"8080\"",
		"UNISTORAGE_CONFIG_DIR: \"/config\"",
		"UNISTORAGE_DATA_DIR: \"/data\"",
		"UNISTORAGE_S3_ENDPOINT: \"http://minio:9000\"",
		"UNISTORAGE_S3_BUCKET: \"unistorage-dev-bucket\"",
		"unistorage-config:/config",
		"unistorage-data:/data",
		"/tmp:rw,noexec,nosuid,size=64m",
		"read_only: true",
		"no-new-privileges:true",
		"- ALL",
		`user: "10001:10001"`,
	}
	for _, check := range unistorageChecks {
		if !strings.Contains(content, check) {
			t.Errorf("docker-compose.yml unistorage service missing %q", check)
		}
	}
}

func matchDockerignoreRule(rule string, path string) bool {
	cleanRule := strings.TrimSpace(rule)
	if cleanRule == "" || strings.HasPrefix(cleanRule, "#") {
		return false
	}

	isDirOnly := strings.HasSuffix(cleanRule, "/")
	cleanRule = strings.TrimSuffix(cleanRule, "/")

	normalizedPath := filepath.ToSlash(path)
	parts := strings.Split(normalizedPath, "/")

	// Check directory / exact match or prefix match
	if isDirOnly {
		for i, part := range parts {
			if matched, _ := filepath.Match(cleanRule, part); matched {
				// If matched part is not the terminal file, or is a directory
				if i < len(parts)-1 || isDirOnly {
					return true
				}
			}
		}
		if matched, _ := filepath.Match(cleanRule, normalizedPath); matched {
			return true
		}
	} else {
		// File or directory glob match against base name or entire path
		baseName := filepath.Base(normalizedPath)
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

func TestDockerignore_Rules(t *testing.T) {
	root := findProjectRoot(t)
	ignorePath := filepath.Join(root, ".dockerignore")

	file, err := os.Open(ignorePath)
	if err != nil {
		t.Fatalf("failed to open .dockerignore: %v", err)
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
			if matchDockerignoreRule(rule, path) {
				return true
			}
		}
		return false
	}

	// Must be ignored
	mustIgnore := []string{
		".git",
		".git/config",
		".gitignore",
		".gitattributes",
		".gitmodules",
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
		"temp.exe~",
		"plugin.dll",
		"driver.so",
		"lib.dylib",
		"daemon.token",
		".unistorage",
		".unistorage/vault.enc",
		"credentials.json",
		".env",
		".env.production",
		"private.key",
		"certificate.pem",
		"id_rsa",
		"id_rsa.pub",
		"id_ed25519",
		"id_ed25519.pub",
		"id_ecdsa",
		"id_ecdsa.pub",
		"id_dsa",
		"id_dsa.pub",
		".ssh/id_rsa",
		".ssh/config",
		"known_hosts",
		"authorized_keys",
		"coverage.html",
		"coverage.txt",
		"app.out",
	}

	for _, path := range mustIgnore {
		if !isIgnored(path) {
			t.Errorf("expected .dockerignore to filter %q, but it did not", path)
		}
	}

	// Must NOT be ignored (source code and critical configs)
	mustKeep := []string{
		"go.mod",
		"go.sum",
		"Dockerfile",
		"docker-compose.yml",
		"cmd/unistorage/main.go",
		"pkg/storage/driver.go",
		"pkg/vault/vault.go",
		"internal/daemon/server.go",
	}

	for _, path := range mustKeep {
		if isIgnored(path) {
			t.Errorf("expected .dockerignore to KEEP %q, but it matched an ignore rule", path)
		}
	}
}

func TestDocker_LinuxCompilation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping linux cross-compilation test in short mode")
	}

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

	tempOut := filepath.Join(t.TempDir(), "unistorage_test_linux")
	cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", tempOut, "./cmd/unistorage")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to compile static linux binary matching Dockerfile flags: %v\nOutput:\n%s", err, string(output))
	}

	info, err := os.Stat(tempOut)
	if err != nil {
		t.Fatalf("compiled binary not found: %v", err)
	}
	if info.Size() == 0 {
		t.Errorf("compiled binary is 0 bytes")
	}
}

