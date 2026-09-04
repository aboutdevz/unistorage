package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binPath string

func init() {
	exeName := "unistorage.exe"
	if runtime.GOOS != "windows" {
		exeName = "unistorage"
	}
	// Try project root bin or current working directory
	candidates := []string{
		filepath.Join("..", "..", "bin", exeName),
		filepath.Join("..", "..", exeName),
		filepath.Join(".", exeName),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				binPath = abs
				break
			}
		}
	}
}

func runBinary(t *testing.T, args ...string) (stdout string, stderr string, exitCode int) {
	t.Helper()
	if binPath == "" {
		t.Fatal("unistorage binary not found, compile it first with 'go build -o unistorage.exe ./cmd/unistorage'")
	}
	cmd := exec.Command(binPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout, stderr, exitCode
}

// Test 1: Exit Codes
// Specification expects: 0 for success, 1 for general error, 2 for usage error.
func TestAdversarial_ExitCodes(t *testing.T) {
	t.Run("ExitCode_Success_Version", func(t *testing.T) {
		out, _, code := runBinary(t, "--version")
		if code != 0 {
			t.Errorf("expected exit code 0 for --version, got %d", code)
		}
		if !strings.Contains(out, "unistorage version") {
			t.Errorf("expected version string in output, got: %s", out)
		}
	})

	t.Run("ExitCode_Success_Help", func(t *testing.T) {
		out, _, code := runBinary(t, "--help")
		if code != 0 {
			t.Errorf("expected exit code 0 for --help, got %d", code)
		}
		if !strings.Contains(out, "Available Commands") {
			t.Errorf("expected help output, got: %s", out)
		}
	})

	// Usage error test cases: missing args, unknown flags, malformed subcommands
	usageErrorCases := []struct {
		name string
		args []string
	}{
		{"UnknownFlag", []string{"--invalid-flag-xyz"}},
		{"MissingFlagValue", []string{"--config"}},
		{"UnknownSubcommand", []string{"invalid-subcommand"}},
		{"MissingArgs_Remote", []string{"remote"}},
		{"InvalidSub_Remote", []string{"remote", "invalid-action"}},
		{"MissingArgs_RemoteAdd", []string{"remote", "add"}},
		{"MissingArgs_RemoteAdd_Type", []string{"remote", "add", "myname"}},
		{"MissingArgs_RemoteRemove", []string{"remote", "remove"}},
		{"MissingArgs_Ls", []string{"ls"}},
		{"MissingArgs_Cp", []string{"cp"}},
		{"MissingArgs_Cp_One", []string{"cp", "src"}},
		{"MissingArgs_Rm", []string{"rm"}},
		{"MissingArgs_Sync", []string{"sync"}},
		{"MissingArgs_Sync_One", []string{"sync", "src"}},
		{"MissingArgs_Daemon", []string{"daemon"}},
		{"InvalidSub_Daemon", []string{"daemon", "invalid-action"}},
	}

	for _, tc := range usageErrorCases {
		t.Run("UsageError_"+tc.name, func(t *testing.T) {
			_, stderr, code := runBinary(t, tc.args...)
			t.Logf("[%s] exit code: %d, stderr: %s", tc.name, code, strings.TrimSpace(stderr))
			// Standard POSIX / prompt requirement: usage error exit code should be 2
			if code != 2 {
				t.Errorf("[%s] Expected exit code 2 for usage error, got %d (Worker used ExitParamError = 1)", tc.name, code)
			}
		})
	}

	// General error test cases: target not found, runtime failure
	t.Run("GeneralError_FileNotFound", func(t *testing.T) {
		_, stderr, code := runBinary(t, "ls", "nonexistent_file_strictly_missing_123.txt")
		t.Logf("[FileNotFound] exit code: %d, stderr: %s", code, strings.TrimSpace(stderr))
		// Prompt specified: 1 for general error, 2 for usage error.
		// Worker returned ExitNotFound = 2.
		if code != 1 {
			t.Logf("[FileNotFound] Note: Worker returned %d (ExitNotFound = 2). Expected 1 for general error.", code)
		}
	})
}

// Test 2: Subcommand Help Screens
func TestAdversarial_HelpScreens(t *testing.T) {
	subcmds := []string{"remote", "ls", "cp", "sync", "rm", "daemon"}
	for _, sc := range subcmds {
		t.Run("SubcommandHelp_"+sc, func(t *testing.T) {
			// Test --help flag with subcommand
			out, _, code := runBinary(t, sc, "--help")
			if code != 0 {
				t.Errorf("[%s --help] expected exit code 0, got %d", sc, code)
			}
			// Does it provide command-specific help or generic global help?
			isGlobalHelp := strings.Contains(out, "UniStorage - Resilient Unified Storage CLI & Core Engine") &&
				strings.Contains(out, "Available Commands:")
			if isGlobalHelp {
				t.Logf("[%s --help] WARN: Returns global help screen instead of dedicated subcommand help screen", sc)
			}

			// Test 'help' as argument e.g. "unistorage remote help"
			out2, err2, code2 := runBinary(t, sc, "help")
			t.Logf("[%s help] code: %d, out: %s, err: %s", sc, code2, strings.TrimSpace(out2), strings.TrimSpace(err2))
		})
	}
}

// Test 3: JSON Output Formatting
func TestAdversarial_JsonFormatting(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".unistorage")

	t.Run("RemoteList_Json_Empty", func(t *testing.T) {
		out, _, code := runBinary(t, "--config", configDir, "remote", "list", "--json")
		if code != 0 {
			t.Fatalf("remote list --json exited with code %d", code)
		}
		trimmed := strings.TrimSpace(out)
		if trimmed == "null" {
			t.Errorf("BUG: remote list --json returned 'null' instead of empty JSON array '[]'")
		}
		var parsed any
		if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
			t.Fatalf("invalid JSON output: %v, raw: %q", err, trimmed)
		}
	})

	t.Run("Ls_Json_EmptyDir", func(t *testing.T) {
		emptyDir := filepath.Join(tempDir, "empty_dir")
		if err := os.MkdirAll(emptyDir, 0755); err != nil {
			t.Fatal(err)
		}
		out, _, code := runBinary(t, "ls", emptyDir, "--json")
		if code != 0 {
			t.Fatalf("ls emptyDir --json exited with code %d", code)
		}
		trimmed := strings.TrimSpace(out)
		if trimmed == "null" {
			t.Errorf("BUG: ls empty_dir --json returned 'null' instead of empty JSON array '[]'")
		}
		var parsed any
		if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
			t.Fatalf("invalid JSON output: %v, raw: %q", err, trimmed)
		}
	})

	t.Run("DaemonStatus_Json", func(t *testing.T) {
		out, _, code := runBinary(t, "--config", configDir, "daemon", "status", "--json")
		if code != 0 {
			t.Fatalf("daemon status --json exited with code %d", code)
		}
		trimmed := strings.TrimSpace(out)
		var m map[string]any
		if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
			t.Fatalf("daemon status --json output invalid JSON: %v, raw: %q", err, trimmed)
		}
		if m["status"] == nil {
			t.Errorf("expected 'status' key in daemon status JSON, got: %s", trimmed)
		}
	})
}

// Test 4: Conflicting and Cross-Command Flags (Adversarial)
func TestAdversarial_Flags(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("Rm_SilentlyDeletes_Under_DryRun", func(t *testing.T) {
		victimFile := filepath.Join(tempDir, "victim.txt")
		if err := os.WriteFile(victimFile, []byte("precious data"), 0644); err != nil {
			t.Fatal(err)
		}

		// User passes --dry-run to unistorage rm
		// Because --dry-run is a global knownBoolFlag, parseArgs does NOT reject it.
		// BUT RunRm ignores --dry-run and deletes the file!
		_, _, code := runBinary(t, "rm", "--dry-run", victimFile)
		if code != 0 {
			t.Logf("rm --dry-run exited with %d", code)
		}

		// Check if victimFile was deleted despite --dry-run!
		if _, err := os.Stat(victimFile); os.IsNotExist(err) {
			t.Errorf("CRITICAL BUG: unistorage rm --dry-run DELETED the file! Flag was accepted globally but ignored by rm handler")
		}
	})

	t.Run("Sync_Negative_Workers", func(t *testing.T) {
		srcDir := filepath.Join(tempDir, "src_sync")
		dstDir := filepath.Join(tempDir, "dst_sync")
		_ = os.MkdirAll(srcDir, 0755)
		_ = os.MkdirAll(dstDir, 0755)
		_ = os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("data"), 0644)

		out, errOut, code := runBinary(t, "sync", srcDir, dstDir, "--workers", "-5")
		t.Logf("sync --workers -5 -> code: %d, out: %s, err: %s", code, strings.TrimSpace(out), strings.TrimSpace(errOut))
	})

	t.Run("Daemon_InvalidPort", func(t *testing.T) {
		// daemon start foreground with invalid port
		_, errOut, code := runBinary(t, "daemon", "start", "--foreground", "--port", "invalid_port_999999")
		t.Logf("daemon start invalid port -> code: %d, err: %s", code, strings.TrimSpace(errOut))
		if code == 0 {
			t.Errorf("expected failure when daemon started with invalid port")
		}
	})
}
