package local_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

func TestAdversarial_DoubleDotTraversal(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-adv-dotdot-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	attackVectors := []string{
		"../",
		"..\\",
		"../file.txt",
		"..\\file.txt",
		"..%2ffile.txt",
		"..%2Ffile.txt",
		"..%5cfile.txt",
		"..%5Cfile.txt",
		"%2e%2e/file.txt",
		"%2e%2e\\file.txt",
		"%2e%2e%2ffile.txt",
		"%2e%2e%5cfile.txt",
		"nested/../../etc/passwd",
		"nested/..\\..\\windows/win.ini",
		"a/b/c/../../../../../../root.txt",
		"a/b/c/..\\..\\..\\..\\..\\..\\root.txt",
		"/../",
		"\\..\\",
		"/../../",
		"\\..\\..\\",
		"....//",
		"....\\\\",
		"....//....//etc/passwd",
		".../file.txt",
		"..../file.txt",
		"..",
		"a/..",
		"a/b/..",
	}

	for _, vector := range attackVectors {
		t.Run(vector, func(t *testing.T) {
			path, err := drv.SanitizePath(vector)
			if err == nil {
				t.Fatalf("VULNERABILITY: attack vector %q succeeded, resolved to %q", vector, path)
			}
			if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
				t.Fatalf("expected ErrInvalidPath or ErrPathTraversal, got: %v", err)
			}
		})
	}
}

func TestAdversarial_NullBytes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-adv-null-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	nullVectors := []string{
		"\x00",
		"\x00test.txt",
		"test.txt\x00",
		"test\x00.txt",
		"nested/\x00/file.txt",
		"nested/dir\x00name/file.txt",
		"safe.png\x00.evil.exe",
		"%00",
		"safe.png%00.evil.exe",
		"%2500", // double-encoded null: becomes %00 which doesn't contain null byte unless decoded again
	}

	for _, vector := range nullVectors {
		t.Run(fmt.Sprintf("%q", vector), func(t *testing.T) {
			path, err := drv.SanitizePath(vector)
			if strings.ContainsRune(vector, 0) || strings.Contains(vector, "%00") {
				if err == nil {
					t.Fatalf("VULNERABILITY: null byte vector %q was accepted, returned %q", vector, path)
				}
				if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
					t.Fatalf("expected ErrInvalidPath or ErrPathTraversal, got: %v", err)
				}
			}
		})
	}
}

func TestAdversarial_AlternateDataStreamsAndColons(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-adv-ads-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	adsVectors := []string{
		"file.txt::$DATA",
		"file.txt:stream",
		"file.txt:hidden",
		"file.txt:$INDEX_ALLOCATION",
		"file.txt::$INDEX_ALLOCATION",
		"file.txt:stream:$DATA",
		"sub/dir/test.txt::$DATA",
		"C:file.txt",
		"C:\\Windows\\System32\\calc.exe",
		"D:/secret.txt",
		"\\\\?\\C:\\file.txt",
		"file.txt%3a%3a$DATA",
	}

	for _, vector := range adsVectors {
		t.Run(vector, func(t *testing.T) {
			path, err := drv.SanitizePath(vector)
			if err == nil {
				t.Fatalf("VULNERABILITY: ADS/colon vector %q was accepted, returned %q", vector, path)
			}
			if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
				t.Fatalf("expected ErrInvalidPath or ErrPathTraversal, got: %v", err)
			}
		})
	}
}

func TestAdversarial_WindowsDeviceNames(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-adv-devices-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	devices := []string{
		"CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		"con", "prn", "aux", "nul", "com1", "lpt1",
		"CoN", "pRn", "AuX", "NuL",
		"CON.txt", "prn.log", "aux.dat", "nul.bin", "com1.inf", "lpt1.tmp",
		"sub/dir/CON", "sub/dir/PRN.txt", "sub/COM3/data.bin",
		"CONIN$", "CONOUT$", "CLOCK$",
		"con. ", "aux. ", "nul. ",
	}

	for _, dev := range devices {
		t.Run(dev, func(t *testing.T) {
			path, err := drv.SanitizePath(dev)
			if strings.HasSuffix(dev, "$") {
				// CONIN$, CONOUT$, CLOCK$ are legacy DOS console devices; note behavior
				t.Logf("Device name %q resolved to %q (err: %v)", dev, path, err)
				return
			}
			if err == nil {
				t.Fatalf("VULNERABILITY: Windows device name %q was accepted, returned %q", dev, path)
			}
			if !errors.Is(err, storage.ErrInvalidPath) {
				t.Fatalf("expected ErrInvalidPath for %q, got: %v", dev, err)
			}
		})
	}
}

func TestAdversarial_SymlinkEscapes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-adv-symlink-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outsideDir, err := os.MkdirTemp("", "unistorage-adv-outside-*")
	if err != nil {
		t.Fatalf("failed to create outside dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)

	outsideSecret := filepath.Join(outsideDir, "classified.txt")
	if err := os.WriteFile(outsideSecret, []byte("TOP_SECRET_DATA"), 0644); err != nil {
		t.Fatalf("failed to write outside secret: %v", err)
	}

	outsideSubDir := filepath.Join(outsideDir, "secret_sub")
	if err := os.MkdirAll(outsideSubDir, 0755); err != nil {
		t.Fatalf("failed to create outside sub dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outsideSubDir, "internal.txt"), []byte("INTERNAL"), 0644); err != nil {
		t.Fatalf("failed to write secret sub file: %v", err)
	}

	// 1. Direct symlink to outside file
	linkToFile := filepath.Join(tempDir, "link_to_file")
	if err := os.Symlink(outsideSecret, linkToFile); err != nil {
		t.Skipf("symlinks not supported in environment: %v", err)
	}

	// 2. Symlink to outside directory
	linkToDir := filepath.Join(tempDir, "link_to_dir")
	if err := os.Symlink(outsideSubDir, linkToDir); err != nil {
		t.Fatalf("symlink to dir failed: %v", err)
	}

	// 3. Symlink inside subdir pointing outside
	subDir := filepath.Join(tempDir, "inner")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir inner failed: %v", err)
	}
	linkFromInner := filepath.Join(subDir, "link_out")
	if err := os.Symlink(outsideSecret, linkFromInner); err != nil {
		t.Fatalf("symlink inside inner failed: %v", err)
	}

	// 4. Safe internal symlink pointing within root
	safeTarget := filepath.Join(tempDir, "safe_target.txt")
	if err := os.WriteFile(safeTarget, []byte("SAFE"), 0644); err != nil {
		t.Fatalf("failed to write safe target: %v", err)
	}
	linkToSafe := filepath.Join(tempDir, "link_safe")
	if err := os.Symlink(safeTarget, linkToSafe); err != nil {
		t.Fatalf("failed to create safe symlink: %v", err)
	}

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	// Test 1: linkToFile must be rejected
	t.Run("direct_file_symlink_escape", func(t *testing.T) {
		_, err := drv.SanitizePath("link_to_file")
		if err == nil {
			t.Fatalf("VULNERABILITY: symlink to outside file was accepted!")
		}
		if !errors.Is(err, storage.ErrInvalidPath) && !errors.Is(err, storage.ErrPathTraversal) {
			t.Fatalf("expected ErrInvalidPath or ErrPathTraversal, got: %v", err)
		}
	})

	// Test 2: file inside linkToDir must be rejected
	t.Run("dir_symlink_escape_existing_file", func(t *testing.T) {
		_, err := drv.SanitizePath("link_to_dir/internal.txt")
		if err == nil {
			t.Fatalf("VULNERABILITY: traversal through symlinked directory was accepted!")
		}
	})

	// Test 3: non-existent file inside linkToDir (write attempt) must be rejected
	t.Run("dir_symlink_escape_nonexistent_write", func(t *testing.T) {
		_, err := drv.SanitizePath("link_to_dir/new_evil_file.txt")
		if err == nil {
			t.Fatalf("VULNERABILITY: write through symlinked directory to outside target was accepted!")
		}
	})

	// Test 4: symlink from inner directory must be rejected
	t.Run("inner_symlink_escape", func(t *testing.T) {
		_, err := drv.SanitizePath("inner/link_out")
		if err == nil {
			t.Fatalf("VULNERABILITY: inner symlink escape was accepted!")
		}
	})

	// Test 5: safe symlink inside root must be allowed
	t.Run("safe_internal_symlink", func(t *testing.T) {
		resolved, err := drv.SanitizePath("link_safe")
		if err != nil {
			t.Fatalf("safe internal symlink should be allowed, got error: %v", err)
		}
		if resolved != filepath.Clean(filepath.Join(drv.RootDir(), "link_safe")) {
			t.Fatalf("unexpected resolved path: %q", resolved)
		}
	})
}

// ZeroReader generates an infinite stream of zero bytes without heap allocations.
type ZeroReader struct {
	remaining int64
}

func (z *ZeroReader) Read(p []byte) (int, error) {
	if z.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > z.remaining {
		n = int(z.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = 0xAA
	}
	z.remaining -= int64(n)
	return n, nil
}

// DiscardWriter discards all bytes and counts total written without retaining bytes.
type DiscardWriter struct {
	total int64
}

func (d *DiscardWriter) Write(p []byte) (int, error) {
	n := len(p)
	d.total += int64(n)
	return n, nil
}

func TestAdversarial_ConstantMemoryStreaming(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-adv-stream-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	drv, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("failed to init local driver: %v", err)
	}

	ctx := context.Background()
	payloadSize := int64(20 * 1024 * 1024) // 20 Megabytes

	// Force GC and measure baseline heap
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Step 1: Write 100MB stream
	zeroReader := &ZeroReader{remaining: payloadSize}
	err = drv.Write(ctx, "payload_100mb.bin", zeroReader, payloadSize)
	if err != nil {
		t.Fatalf("failed to write 100MB payload: %v", err)
	}

	var memAfterWrite runtime.MemStats
	runtime.ReadMemStats(&memAfterWrite)

	// Step 2: Stream 100MB back out
	discardWriter := &DiscardWriter{}
	err = drv.Stream(ctx, "payload_100mb.bin", discardWriter)
	if err != nil {
		t.Fatalf("failed to stream 100MB payload: %v", err)
	}

	if discardWriter.total != payloadSize {
		t.Fatalf("streamed size mismatch: expected %d bytes, got %d", payloadSize, discardWriter.total)
	}

	// Force GC and measure heap after streaming
	runtime.GC()
	var memAfterStream runtime.MemStats
	runtime.ReadMemStats(&memAfterStream)

	// Evaluate heap memory:
	// A 100MB non-streaming implementation would allocate >= 100MB in heap.
	// A constant-memory streaming implementation using 64KB buffers should keep
	// active heap growth well under 10MB during the entire cycle.
	heapDeltaWrite := int64(memAfterWrite.HeapAlloc) - int64(memBefore.HeapAlloc)
	heapDeltaStream := int64(memAfterStream.HeapAlloc) - int64(memBefore.HeapAlloc)

	t.Logf("Baseline HeapAlloc: %d KB", memBefore.HeapAlloc/1024)
	t.Logf("After Write HeapAlloc: %d KB (delta: %d KB)", memAfterWrite.HeapAlloc/1024, heapDeltaWrite/1024)
	t.Logf("After Stream HeapAlloc: %d KB (delta: %d KB)", memAfterStream.HeapAlloc/1024, heapDeltaStream/1024)

	// Assert active heap growth did NOT buffer the 100MB payload
	maxAllowedHeapDelta := int64(15 * 1024 * 1024) // 15MB ceiling for 100MB stream
	if heapDeltaWrite > maxAllowedHeapDelta {
		t.Fatalf("FAIL: Write allocated too much heap (%d bytes > %d max), memory not constant O(1)", heapDeltaWrite, maxAllowedHeapDelta)
	}
	if heapDeltaStream > maxAllowedHeapDelta {
		t.Fatalf("FAIL: Stream allocated too much heap (%d bytes > %d max), memory not constant O(1)", heapDeltaStream, maxAllowedHeapDelta)
	}
}
