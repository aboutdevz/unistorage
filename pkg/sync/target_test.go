package sync

import (
	"path/filepath"
	"testing"
)

func TestTargetParser_WindowsDrive(t *testing.T) {
	cases := []struct {
		input       string
		expectPath  string
		expectIsRem bool
	}{
		{"C:\\data\\file.txt", filepath.Clean("C:\\data\\file.txt"), false},
		{"D:/backups/db.dump", filepath.Clean("D:/backups/db.dump"), false},
		{"c:\\windows\\system32", filepath.Clean("c:\\windows\\system32"), false},
		{"E:/", filepath.Clean("E:/"), false},
		{"C:", filepath.Clean("C:"), false},
		{"Z:\\", filepath.Clean("Z:\\"), false},
	}

	for _, tc := range cases {
		loc, err := ParseTarget(tc.input)
		if err != nil {
			t.Fatalf("unexpected error parsing %q: %v", tc.input, err)
		}
		if loc.IsRemote != tc.expectIsRem {
			t.Errorf("%q: expected IsRemote=%v, got %v", tc.input, tc.expectIsRem, loc.IsRemote)
		}
		if loc.Path != tc.expectPath {
			t.Errorf("%q: expected Path=%q, got %q", tc.input, tc.expectPath, loc.Path)
		}
	}
}

func TestTargetParser_RemoteSpecs(t *testing.T) {
	cases := []struct {
		input        string
		expectRemote string
		expectPath   string
	}{
		{"s3-backup:bucket/prefix/file.txt", "s3-backup", "bucket/prefix/file.txt"},
		{"my-s3:/leading/slash/trimmed.pdf", "my-s3", "leading/slash/trimmed.pdf"},
		{"local-fs:/folder", "local-fs", "folder"},
		{"remote-name:single-file.txt", "remote-name", "single-file.txt"},
		{"s3:root-only", "s3", "root-only"},
		{"remote:", "remote", ""},
		{"remote-a:relative/path", "remote-a", "relative/path"},
		{"D:path", "D", "path"},
		{"C:file.txt", "C", "file.txt"},
		{"a:path", "a", "path"},
	}

	for _, tc := range cases {
		loc, err := ParseTarget(tc.input)
		if err != nil {
			t.Fatalf("unexpected error parsing %q: %v", tc.input, err)
		}
		if !loc.IsRemote {
			t.Errorf("%q: expected IsRemote=true", tc.input)
		}
		if loc.RemoteName != tc.expectRemote {
			t.Errorf("%q: expected RemoteName=%q, got %q", tc.input, tc.expectRemote, loc.RemoteName)
		}
		if loc.Path != tc.expectPath {
			t.Errorf("%q: expected Path=%q, got %q", tc.input, tc.expectPath, loc.Path)
		}
	}
}

func TestTargetParser_LocalPaths(t *testing.T) {
	cases := []struct {
		input      string
		expectPath string
	}{
		{"relative/path/to/file.txt", filepath.Clean("relative/path/to/file.txt")},
		{"./data/file.csv", filepath.Clean("./data/file.csv")},
		{"../parent/file.txt", filepath.Clean("../parent/file.txt")},
		{"just_a_file.txt", "just_a_file.txt"},
	}

	for _, tc := range cases {
		loc, err := ParseTarget(tc.input)
		if err != nil {
			t.Fatalf("unexpected error parsing %q: %v", tc.input, err)
		}
		if loc.IsRemote {
			t.Errorf("%q: expected IsRemote=false", tc.input)
		}
		if loc.Path != tc.expectPath {
			t.Errorf("%q: expected Path=%q, got %q", tc.input, tc.expectPath, loc.Path)
		}
	}
}

func TestTargetParser_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		":missing-remote",
		":",
	}

	for _, tc := range invalid {
		_, err := ParseTarget(tc)
		if err == nil {
			t.Errorf("expected error parsing %q, but got nil", tc)
		}
	}
}

func TestTargetParser_String(t *testing.T) {
	rem := &TargetLocation{IsRemote: true, RemoteName: "my-s3", Path: "bucket/file"}
	if rem.String() != "my-s3:bucket/file" {
		t.Errorf("expected my-s3:bucket/file, got %q", rem.String())
	}

	remRoot := &TargetLocation{IsRemote: true, RemoteName: "my-s3", Path: ""}
	if remRoot.String() != "my-s3:" {
		t.Errorf("expected my-s3:, got %q", remRoot.String())
	}

	loc := &TargetLocation{IsRemote: false, Path: "C:\\local\\path"}
	if loc.String() != "C:\\local\\path" {
		t.Errorf("expected C:\\local\\path, got %q", loc.String())
	}
}
