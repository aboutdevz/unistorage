package sync

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

// TestAdversarial_TargetPathDisambiguation tests the exact cases requested in Milestone 2 challenge:
// Complex Windows paths: C:\dir\sub, c:/dir/sub, D:\, D:path, \\server\share
// Remote paths: remote:dir, s3_1:bucket/file, bad:name:path
func TestAdversarial_TargetPathDisambiguation(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectRemote bool
		expectName   string
		expectPath   string
	}{
		{
			name:         "Windows backslash path",
			input:        `C:\dir\sub`,
			expectRemote: false,
			expectPath:   filepath.Clean(`C:\dir\sub`),
		},
		{
			name:         "Windows forward slash path",
			input:        `c:/dir/sub`,
			expectRemote: false,
			expectPath:   filepath.Clean(`c:/dir/sub`),
		},
		{
			name:         "Windows root drive backslash",
			input:        `D:\`,
			expectRemote: false,
			expectPath:   filepath.Clean(`D:\`),
		},
		{
			name:         "Windows drive-relative path D:path",
			input:        `D:path`,
			expectRemote: false,
			expectPath:   filepath.Clean(`D:path`),
		},
		{
			name:         "Windows drive-relative path C:file.txt",
			input:        `C:file.txt`,
			expectRemote: false,
			expectPath:   filepath.Clean(`C:file.txt`),
		},
		{
			name:         "Windows UNC network share",
			input:        `\\server\share`,
			expectRemote: false,
			expectPath:   filepath.Clean(`\\server\share`),
		},
		{
			name:         "Standard remote path",
			input:        `remote:dir`,
			expectRemote: true,
			expectName:   "remote",
			expectPath:   "dir",
		},
		{
			name:         "Remote with underscore and numbers",
			input:        `s3_1:bucket/file`,
			expectRemote: true,
			expectName:   "s3_1",
			expectPath:   "bucket/file",
		},
		{
			name:         "Remote with multiple colons in path",
			input:        `bad:name:path`,
			expectRemote: true,
			expectName:   "bad",
			expectPath:   "name:path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := ParseTarget(tc.input)
			if err != nil {
				t.Fatalf("ParseTarget(%q) returned error: %v", tc.input, err)
			}
			if loc.IsRemote != tc.expectRemote {
				t.Errorf("ParseTarget(%q): expected IsRemote=%v, got %v (loc=%+v)", tc.input, tc.expectRemote, loc.IsRemote, loc)
			}
			if tc.expectRemote {
				if loc.RemoteName != tc.expectName {
					t.Errorf("ParseTarget(%q): expected RemoteName=%q, got %q", tc.input, tc.expectName, loc.RemoteName)
				}
			}
			if loc.Path != tc.expectPath {
				t.Errorf("ParseTarget(%q): expected Path=%q, got %q", tc.input, tc.expectPath, loc.Path)
			}
		})
	}
}

// TestAdversarial_ChangeDetection tests the exact change detection scenarios:
// 1. Same size different content: must trigger sync under --checksum
// 2. Same content different modtime: must trigger sync under default, skip under checksum
// 3. Timestamp within 1s epsilon: must be treated as unchanged in default mode
func TestAdversarial_ChangeDetection(t *testing.T) {
	ctx := context.Background()

	// Scenario 1: Same size, different content
	t.Run("SameSize_DifferentContent", func(t *testing.T) {
		srcDrv := storage.NewMockDriver("src")
		destDrv := storage.NewMockDriver("dest")
		dataA := []byte("hello world 1")
		dataB := []byte("hello world 2")

		_ = srcDrv.Write(ctx, "file.txt", bytes.NewReader(dataA), int64(len(dataA)))
		_ = destDrv.Write(ctx, "file.txt", bytes.NewReader(dataB), int64(len(dataB)))

		// Under --checksum: must detect conflict/difference and trigger sync
		statsChecksum, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{Checksum: true})
		if err != nil {
			t.Fatalf("Sync checksum failed: %v", err)
		}
		if statsChecksum.UpdatedFiles != 1 {
			t.Errorf("expected 1 updated file under --checksum, got %d", statsChecksum.UpdatedFiles)
		}
		if statsChecksum.SkippedFiles != 0 {
			t.Errorf("expected 0 skipped files under --checksum, got %d", statsChecksum.SkippedFiles)
		}

		// Verify dest file has source content now
		rc, _ := destDrv.Read(ctx, "file.txt")
		destContent := make([]byte, len(dataA))
		_, _ = rc.Read(destContent)
		_ = rc.Close()
		if !bytes.Equal(destContent, dataA) {
			t.Errorf("dest file not updated with source content: got %q, want %q", destContent, dataA)
		}
	})

	// Scenario 2: Same content, different modtime
	t.Run("SameContent_DifferentModTime", func(t *testing.T) {
		data := []byte("identical content across both files")
		baseTime := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)

		// 2a. Under default mode: source newer by 5s -> must trigger sync
		cmpDefault := NewComparator(CompareModeSizeModTime)
		srcInfo := &storage.ObjectInfo{Path: "f.txt", Size: int64(len(data)), ModTime: baseTime.Add(5 * time.Second)}
		destInfo := &storage.ObjectInfo{Path: "f.txt", Size: int64(len(data)), ModTime: baseTime}

		statusDefault, err := cmpDefault.Compare(ctx, nil, srcInfo, nil, destInfo)
		if err != nil {
			t.Fatalf("Compare failed: %v", err)
		}
		if statusDefault != DiffStatusModified {
			t.Errorf("expected DiffStatusModified under default mode for different modtime, got %v", statusDefault)
		}

		// 2b. Under --checksum mode: same content -> must skip (DiffStatusIdentical)
		srcDrv := storage.NewMockDriver("src")
		destDrv := storage.NewMockDriver("dest")
		_ = srcDrv.Write(ctx, "f.txt", bytes.NewReader(data), int64(len(data)))
		_ = destDrv.Write(ctx, "f.txt", bytes.NewReader(data), int64(len(data)))

		cmpChecksum := NewComparator(CompareModeChecksum)
		statusChecksum, err := cmpChecksum.Compare(ctx, srcDrv, srcInfo, destDrv, destInfo)
		if err != nil {
			t.Fatalf("Compare failed: %v", err)
		}
		if statusChecksum != DiffStatusIdentical {
			t.Errorf("expected DiffStatusIdentical under checksum mode for identical content, got %v", statusChecksum)
		}
	})

	// Scenario 3: Timestamp within 1s epsilon: treated as unchanged in default mode
	t.Run("Timestamp_Within1sEpsilon", func(t *testing.T) {
		baseTime := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
		cmpDefault := NewComparator(CompareModeSizeModTime)

		testEpsilons := []time.Duration{
			0,
			200 * time.Millisecond,
			500 * time.Millisecond,
			999 * time.Millisecond,
			1000 * time.Millisecond,
			-500 * time.Millisecond,
			-1000 * time.Millisecond,
		}

		for _, eps := range testEpsilons {
			srcInfo := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: baseTime.Add(eps)}
			destInfo := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: baseTime}

			status, err := cmpDefault.Compare(ctx, nil, srcInfo, nil, destInfo)
			if err != nil {
				t.Fatalf("Compare failed for epsilon %v: %v", eps, err)
			}
			if status != DiffStatusIdentical {
				t.Errorf("expected DiffStatusIdentical for epsilon %v, got %v", eps, status)
			}
		}

		// Verify that > 1s is NOT treated as identical
		srcInfoNewer := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: baseTime.Add(1001 * time.Millisecond)}
		destInfo := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: baseTime}
		statusNewer, _ := cmpDefault.Compare(ctx, nil, srcInfoNewer, nil, destInfo)
		if statusNewer == DiffStatusIdentical {
			t.Errorf("expected non-identical status for 1001ms difference, got DiffStatusIdentical")
		}
	})
}

// TestAdversarial_ConflictBackupVerification tests:
// - Displaced files are safely copied to .conflicts/ with timestamp suffix
// - Original source content replaces destination
// - Non-destructive backup: original destination content preserved in .conflicts/
func TestAdversarial_ConflictBackupVerification(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("src")
	destDrv := storage.NewMockDriver("dest")

	srcContent := []byte("brand new source content")
	destOriginalContent := []byte("previous destination content that must not be lost")

	_ = srcDrv.Write(ctx, "important.docx", bytes.NewReader(srcContent), int64(len(srcContent)))
	_ = destDrv.Write(ctx, "important.docx", bytes.NewReader(destOriginalContent), int64(len(destOriginalContent)))

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{})
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// 1. Conflict count
	if stats.ConflictFiles != 1 {
		t.Fatalf("expected 1 conflict file, got %d", stats.ConflictFiles)
	}
	if len(stats.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict in stats.Conflicts, got %d", len(stats.Conflicts))
	}

	backupPath := stats.Conflicts[0]
	// 2. Displaced files safely copied to .conflicts/ with timestamp suffix
	if !strings.HasPrefix(backupPath, ".conflicts/important.docx.") {
		t.Errorf("expected backup path to start with .conflicts/important.docx., got %q", backupPath)
	}
	if !strings.HasSuffix(backupPath, ".conflict") {
		t.Errorf("expected backup path to end with .conflict, got %q", backupPath)
	}

	// 3. Non-destructive backup: verify backup contains destination's original content
	rcBackup, err := destDrv.Read(ctx, backupPath)
	if err != nil {
		t.Fatalf("failed to read conflict backup: %v", err)
	}
	defer rcBackup.Close()
	backupBytes := make([]byte, len(destOriginalContent)*2)
	n, _ := rcBackup.Read(backupBytes)
	if !bytes.Equal(backupBytes[:n], destOriginalContent) {
		t.Errorf("conflict backup content mismatch: got %q, want %q", backupBytes[:n], destOriginalContent)
	}

	// 4. Source content replaces destination
	rcDest, err := destDrv.Read(ctx, "important.docx")
	if err != nil {
		t.Fatalf("failed to read destination after sync: %v", err)
	}
	defer rcDest.Close()
	destBytes := make([]byte, len(srcContent)*2)
	nDest, _ := rcDest.Read(destBytes)
	if !bytes.Equal(destBytes[:nDest], srcContent) {
		t.Errorf("destination content not replaced by source: got %q, want %q", destBytes[:nDest], srcContent)
	}
}

// TestAdversarial_DeleteFlag tests:
// Deleted source files are removed from destination without touching .conflicts/
func TestAdversarial_DeleteFlag(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("src")
	destDrv := storage.NewMockDriver("dest")

	// Source has active.txt
	_ = srcDrv.Write(ctx, "active.txt", bytes.NewReader([]byte("active")), 6)

	// Destination has active.txt, obsolete.txt, and a conflict backup
	_ = destDrv.Write(ctx, "active.txt", bytes.NewReader([]byte("active")), 6)
	_ = destDrv.Write(ctx, "obsolete.txt", bytes.NewReader([]byte("should be deleted")), 17)
	conflictBackupPath := ".conflicts/active.txt.20260904T120000Z.conflict"
	_ = destDrv.Write(ctx, conflictBackupPath, bytes.NewReader([]byte("pre-existing conflict backup")), 28)

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{Delete: true})
	if err != nil {
		t.Fatalf("Sync with Delete failed: %v", err)
	}

	if stats.DeletedFiles != 1 {
		t.Errorf("expected 1 deleted file, got %d", stats.DeletedFiles)
	}

	// Verify active.txt exists
	if _, err := destDrv.Stat(ctx, "active.txt"); err != nil {
		t.Errorf("active.txt should exist on dest: %v", err)
	}

	// Verify obsolete.txt is deleted
	if _, err := destDrv.Stat(ctx, "obsolete.txt"); err == nil {
		t.Errorf("obsolete.txt should have been deleted from destination")
	}

	// Verify conflict backup was NOT touched
	if _, err := destDrv.Stat(ctx, conflictBackupPath); err != nil {
		t.Errorf("conflict backup %q was deleted or corrupted: %v", conflictBackupPath, err)
	}
}

// TestAdversarial_RecursiveSync_SameRootWithPrefix tests if syncing a local driver to itself with a sub-prefix
// is prevented or if it bypasses ErrRecursiveSync.
func TestAdversarial_RecursiveSync_SameRootWithPrefix(t *testing.T) {
	tempDir := t.TempDir()
	srcDir := filepath.Join(tempDir, "data")
	drv, err := local.New(srcDir)
	if err != nil {
		t.Fatalf("failed to create local driver: %v", err)
	}

	// Write a file to the root
	ctx := context.Background()
	_ = drv.Write(ctx, "root.txt", bytes.NewReader([]byte("root")), 4)

	// Sync root to "backup" prefix on the same driver!
	_, err = Sync(ctx, drv, "", drv, "backup", SyncOptions{})
	if err != ErrRecursiveSync {
		t.Errorf("expected ErrRecursiveSync when syncing local driver to itself with subprefix, got: %v", err)
	}
}

