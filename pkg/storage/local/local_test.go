package local_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

func TestSanitizePath_Traversals(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-test-sanitizer-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	traversalPayloads := []string{
		"../outside.txt",
		"..\\win_outside.txt",
		"sub/../../outside.txt",
		"/../../etc/passwd",
		"....//....//etc/shadow",
		".../something",
		"a/b/../../../../c",
	}

	for _, payload := range traversalPayloads {
		t.Run(payload, func(t *testing.T) {
			_, err := drv.SanitizePath(payload)
			if err == nil {
				t.Fatalf("expected error for traversal payload %q, got nil", payload)
			}
			if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
				t.Fatalf("expected ErrInvalidPath or ErrPathTraversal, got %v", err)
			}
		})
	}
}

func TestSanitizePath_Attacks(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-test-attacks-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	attackCases := []struct {
		name    string
		payload string
	}{
		{"null_byte_middle", "safe.png\x00.evil.exe"},
		{"null_byte_start", "\x00/../../etc/passwd"},
		{"url_encoded_dotdot", "%2e%2e%2f%2e%2e%2fetc/passwd"},
		{"url_encoded_null", "safe%00evil.txt"},
		{"windows_device_con", "CON"},
		{"windows_device_prn", "PRN"},
		{"windows_device_aux", "AUX"},
		{"windows_device_nul", "NUL"},
		{"windows_device_com1", "COM1"},
		{"windows_device_lpt1", "LPT1"},
		{"windows_device_with_ext", "con.txt"},
		{"windows_device_in_subdir", "sub/nul.dat"},
		{"windows_ads", "test.txt::$DATA"},
		{"windows_ads_custom", "test.txt:stream"},
		{"windows_drive_letter", "C:\\Windows\\System32\\cmd.exe"},
	}

	for _, tc := range attackCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := drv.SanitizePath(tc.payload)
			if err == nil {
				t.Fatalf("expected security error for %q, got nil", tc.payload)
			}
			if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
				t.Fatalf("expected ErrInvalidPath or ErrPathTraversal, got %v", err)
			}
		})
	}
}

func TestLocalDriver_SymlinkEscape(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-test-symlink-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outsideDir, err := os.MkdirTemp("", "unistorage-outside-*")
	if err != nil {
		t.Fatalf("failed to create outside dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)

	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("sensitive"), 0644); err != nil {
		t.Fatalf("failed to write outside file: %v", err)
	}

	// Try creating symlink inside tempDir pointing to outsideFile
	linkPath := filepath.Join(tempDir, "link_to_secret")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Skipf("symlink creation not supported in this environment: %v", err)
	}

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init driver: %v", err)
	}

	_, err = drv.SanitizePath("link_to_secret")
	if err == nil {
		t.Fatalf("expected symlink escape to be rejected, but succeeded")
	}
	if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
		t.Fatalf("expected ErrInvalidPath/ErrPathTraversal, got %v", err)
	}
}

func TestLocalDriver_CRUDAndStreaming(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-test-crud-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init driver: %v", err)
	}

	if drv.Name() != "local" {
		t.Fatalf("expected name 'local', got %q", drv.Name())
	}

	// 1. Stat non-existent
	_, err = drv.Stat(ctx, "sub/missing.txt")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// 2. Write with auto parent dir creation and atomic replacement
	data := []byte("hello local filesystem driver with atomic write guarantee")
	targetPath := "nested/dirs/document.txt"
	err = drv.Write(ctx, targetPath, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// 3. Stat
	info, err := drv.Stat(ctx, targetPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Size != int64(len(data)) {
		t.Errorf("size mismatch: got %d, want %d", info.Size, len(data))
	}

	// 4. Read
	rc, err := drv.Read(ctx, targetPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	readBytes, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("read all failed: %v", err)
	}
	if !bytes.Equal(readBytes, data) {
		t.Fatalf("content mismatch: got %q, want %q", string(readBytes), string(data))
	}

	// 5. Stream
	var streamBuf bytes.Buffer
	err = drv.Stream(ctx, targetPath, &streamBuf)
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	if !bytes.Equal(streamBuf.Bytes(), data) {
		t.Fatalf("streamed mismatch: got %q, want %q", streamBuf.String(), string(data))
	}

	// 6. Overwrite check
	err = drv.WriteWithOptions(ctx, targetPath, bytes.NewReader([]byte("conflict")), 8, storage.WithNoOverwrite())
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}

	// 7. List
	// Add another file
	_ = drv.Write(ctx, "nested/dirs/another.txt", bytes.NewReader([]byte("123")), 3)
	list, err := drv.List(ctx, "nested/dirs")
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(list) < 2 {
		t.Fatalf("expected at least 2 items in list, got %d", len(list))
	}

	// 8. Delete
	err = drv.Delete(ctx, targetPath)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// 9. Delete idempotent
	err = drv.Delete(ctx, targetPath)
	if err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}

	// 10. Stat after delete returns ErrNotFound
	_, err = drv.Stat(ctx, targetPath)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestLocalDriver_LargeStreaming(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-test-stream-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init driver: %v", err)
	}

	// 1 MB test stream
	chunk := bytes.Repeat([]byte("A"), 64*1024)
	totalChunks := 16
	var fullContent []byte
	for i := 0; i < totalChunks; i++ {
		fullContent = append(fullContent, chunk...)
	}

	err = drv.Write(ctx, "large.bin", bytes.NewReader(fullContent), int64(len(fullContent)))
	if err != nil {
		t.Fatalf("large write failed: %v", err)
	}

	var outBuf bytes.Buffer
	err = drv.Stream(ctx, "large.bin", &outBuf)
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	if outBuf.Len() != len(fullContent) {
		t.Fatalf("stream size mismatch: got %d, want %d", outBuf.Len(), len(fullContent))
	}
}
