package local

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

func FuzzPathSanitizer(f *testing.F) {
	// Seed corpus with targeted edge cases and attack payloads
	corpus := []string{
		"simple.txt",
		"sub/dir/file.log",
		"../escaped.txt",
		"..\\win_escaped.txt",
		"/absolute/path.txt",
		"C:\\Windows\\System32\\cmd.exe",
		"file\x00nullbyte.txt",
		"..%2f..%2fetc/passwd",
		"....//....//etc/passwd",
		"CON",
		"PRN",
		"AUX",
		"NUL",
		"COM1",
		"LPT1",
		"test.txt::$DATA",
		"dir/./././file.txt",
		"a/b/../../c/../../d",
		strings.Repeat("a/", 50) + "deep.txt",
	}

	for _, seed := range corpus {
		f.Add(seed)
	}

	// Create temporary sandbox root directory
	tempRoot, err := os.MkdirTemp("", "unistorage-fuzz-root-*")
	if err != nil {
		f.Fatalf("failed to create temp root: %v", err)
	}
	defer os.RemoveAll(tempRoot)

	sanitizer, err := NewPathSanitizer(tempRoot)
	if err != nil {
		f.Fatalf("failed to create sanitizer: %v", err)
	}
	canonicalRoot := sanitizer.CanonicalRoot()

	f.Fuzz(func(t *testing.T, inputPath string) {
		sanitized, err := sanitizer.Sanitize(inputPath)
		if err != nil {
			// Expected security error
			if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
				t.Fatalf("unexpected error type for path %q: %v", inputPath, err)
			}
			return
		}

		// Invariant 1: Sanitized path must be clean
		if filepath.Clean(sanitized) != sanitized {
			t.Errorf("sanitized path not clean: %q vs %q", sanitized, filepath.Clean(sanitized))
		}

		// Invariant 2: Sanitized path must be strictly inside canonical root
		rel, err := filepath.Rel(canonicalRoot, sanitized)
		if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
			t.Fatalf("TRAVERSAL ESCAPE DETECTED! Root: %q, Result: %q, Rel: %q", canonicalRoot, sanitized, rel)
		}

		// Invariant 3: Sanitized path must not contain null bytes
		if strings.ContainsRune(sanitized, '\x00') {
			t.Fatalf("sanitized path contains null byte: %q", sanitized)
		}
	})
}
