package harness

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// CLIResult records the outcome of a CLI process execution.
type CLIResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	Err      error
}

// Harness provides an isolated testing environment for UniStorage CLI and Daemon.
type Harness struct {
	t          *testing.T
	RootDir    string
	ConfigDir  string
	DataDir    string
	DaemonAddr string
	BinaryPath string
	Env        []string
}

// NewHarness creates a new self-contained test harness with isolated temporary directories.
func NewHarness(t *testing.T) *Harness {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, ".unistorage")
	dataDir := filepath.Join(root, "data")

	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		t.Fatalf("failed to create data dir: %v", err)
	}

	// Look for compiled binary in standard locations or fallback
	binPath := findBinary(t)

	h := &Harness{
		t:          t,
		RootDir:    root,
		ConfigDir:  configDir,
		DataDir:    dataDir,
		DaemonAddr: "127.0.0.1:8080",
		BinaryPath: binPath,
		Env: []string{
			"UNISTORAGE_CONFIG_DIR=" + configDir,
			"UNISTORAGE_DATA_DIR=" + dataDir,
			"HOME=" + root,
			"USERPROFILE=" + root,
		},
	}
	return h
}

func findProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func findBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../bin/unistorage",
		"../../bin/unistorage.exe",
		"../bin/unistorage",
		"../bin/unistorage.exe",
		"./unistorage",
		"./unistorage.exe",
		"../../../bin/unistorage",
		"../../../bin/unistorage.exe",
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err == nil {
			if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
				return abs
			}
		}
	}
	// Also check PATH
	if p, err := exec.LookPath("unistorage"); err == nil {
		return p
	}

	// Auto-compile binary if not found
	root := findProjectRoot()
	if root != "" {
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		target := filepath.Join(root, "bin", "unistorage"+ext)
		_ = os.MkdirAll(filepath.Dir(target), 0750)
		// #nosec G204 -- test harness compiles local CLI binary
		buildCmd := exec.Command("go", "build", "-o", target, "./cmd/unistorage")
		buildCmd.Dir = root
		if err := buildCmd.Run(); err == nil {
			return target
		}
	}

	return ""
}

// RunCLI executes the unistorage command with arguments within the isolated harness.
func (h *Harness) RunCLI(ctx context.Context, args ...string) *CLIResult {
	h.t.Helper()
	start := time.Now()

	var cmd *exec.Cmd
	if h.BinaryPath != "" {
		// #nosec G204 -- test harness executes local CLI binary
		cmd = exec.CommandContext(ctx, h.BinaryPath, args...)
	} else {
		// Fallback to go run if binary is not yet compiled
		goArgs := append([]string{"run", "./cmd/unistorage"}, args...)
		// #nosec G204 -- test harness executes go run
		cmd = exec.CommandContext(ctx, "go", goArgs...)
	}

	cmd.Dir = h.RootDir
	cmd.Env = append(os.Environ(), h.Env...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	duration := time.Since(start)

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return &CLIResult{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
		ExitCode: exitCode,
		Duration: duration,
		Err:      err,
	}
}

// CreateFile writes content to a file relative to the harness root directory.
func (h *Harness) CreateFile(relPath string, content []byte) string {
	h.t.Helper()
	fullPath := filepath.Join(h.RootDir, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0750); err != nil {
		h.t.Fatalf("failed to create directory for file %s: %v", relPath, err)
	}
	if err := os.WriteFile(fullPath, content, 0600); err != nil {
		h.t.Fatalf("failed to write file %s: %v", relPath, err)
	}
	return fullPath
}

// ReadFile reads content of a file relative to harness root directory.
func (h *Harness) ReadFile(relPath string) []byte {
	h.t.Helper()
	fullPath := filepath.Join(h.RootDir, relPath)
	// #nosec G304 -- test harness reads file within isolated root dir
	data, err := os.ReadFile(fullPath)
	if err != nil {
		h.t.Fatalf("failed to read file %s: %v", relPath, err)
	}
	return data
}

// FileExists checks whether a file exists at relative path.
func (h *Harness) FileExists(relPath string) bool {
	fullPath := filepath.Join(h.RootDir, relPath)
	_, err := os.Stat(fullPath)
	return err == nil
}

// GetToken reads the daemon Bearer token from the isolated config directory.
func (h *Harness) GetToken() (string, error) {
	tokenPath := filepath.Join(h.ConfigDir, "daemon.token")
	// #nosec G304 -- test harness reads daemon token within isolated config dir
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// VerifyTokenPermissions checks that daemon.token has strict 0600 permissions.
func (h *Harness) VerifyTokenPermissions() bool {
	tokenPath := filepath.Join(h.ConfigDir, "daemon.token")
	fi, err := os.Stat(tokenPath)
	if err != nil {
		return false
	}
	// Mode check (on Unix mode should be 0600; on Windows Go sets 0666/0600)
	if runtime.GOOS == "windows" {
		return fi.Mode().Perm() == 0666 || fi.Mode().Perm() == 0600
	}
	mode := fi.Mode().Perm()
	return mode&0077 == 0 || mode == 0600
}
