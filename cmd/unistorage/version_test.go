package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func captureOutput(f func()) string {
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestVersionInfo(t *testing.T) {
	info := GetVersionInfo()

	if info.Version == "" {
		t.Errorf("expected non-empty Version, got empty")
	}
	if info.GoVersion == "" {
		t.Errorf("expected non-empty GoVersion, got empty")
	}
	if info.Platform == "" {
		t.Errorf("expected non-empty Platform, got empty")
	}
}

func TestPrintVersion_PlainText(t *testing.T) {
	out := captureOutput(func() {
		printVersion(false)
	})

	if !strings.Contains(out, "unistorage version") {
		t.Errorf("expected output to contain 'unistorage version', got: %q", out)
	}
	if !strings.Contains(out, Version) {
		t.Errorf("expected output to contain version %q, got: %q", Version, out)
	}
}

func TestPrintVersion_WithCommit(t *testing.T) {
	origCommit := Commit
	origBuildTime := BuildTime
	defer func() {
		Commit = origCommit
		BuildTime = origBuildTime
	}()

	Commit = "a1b2c3d"
	BuildTime = "2026-09-05T00:00:00Z"

	out := captureOutput(func() {
		printVersion(false)
	})

	if !strings.Contains(out, "unistorage version") {
		t.Errorf("expected 'unistorage version' in output, got: %q", out)
	}
	if !strings.Contains(out, "a1b2c3d") {
		t.Errorf("expected commit hash in output, got: %q", out)
	}
	if !strings.Contains(out, "2026-09-05T00:00:00Z") {
		t.Errorf("expected build time in output, got: %q", out)
	}
}

func TestPrintVersion_JSON(t *testing.T) {
	out := captureOutput(func() {
		printVersion(true)
	})

	var data VersionInfo
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("failed to parse json output: %v, raw: %q", err, out)
	}

	if data.Version != Version {
		t.Errorf("expected version %q, got %q", Version, data.Version)
	}
	if data.GoVersion == "" {
		t.Errorf("expected non-empty go_version in json")
	}
	if data.Platform == "" {
		t.Errorf("expected non-empty platform in json")
	}
}

func TestAppVersion_Compatibility(t *testing.T) {
	if AppVersion != Version {
		t.Errorf("expected AppVersion (%s) to match Version (%s)", AppVersion, Version)
	}
}

