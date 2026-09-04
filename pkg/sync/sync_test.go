package sync

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

func TestSync_InitialCopy_And_Skip(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("mock-src")
	destDrv := storage.NewMockDriver("mock-dest")

	_ = srcDrv.Write(ctx, "file1.txt", bytes.NewReader([]byte("version 1")), 9)
	_ = srcDrv.Write(ctx, "file2.txt", bytes.NewReader([]byte("version 2")), 9)

	// 1. Initial Sync
	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{})
	if err != nil {
		t.Fatalf("Sync initial failed: %v", err)
	}

	if stats.TransferredFiles != 2 {
		t.Errorf("expected 2 transferred files, got %d", stats.TransferredFiles)
	}
	if stats.SkippedFiles != 0 {
		t.Errorf("expected 0 skipped files, got %d", stats.SkippedFiles)
	}

	// Verify destination has files
	if _, err := destDrv.Stat(ctx, "file1.txt"); err != nil {
		t.Errorf("expected dest file1.txt: %v", err)
	}
	if _, err := destDrv.Stat(ctx, "file2.txt"); err != nil {
		t.Errorf("expected dest file2.txt: %v", err)
	}

	// 2. Unchanged Sync (second run should skip both)
	stats2, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{})
	if err != nil {
		t.Fatalf("Sync second run failed: %v", err)
	}

	if stats2.TransferredFiles != 0 {
		t.Errorf("expected 0 transferred files on second run, got %d", stats2.TransferredFiles)
	}
	if stats2.SkippedFiles != 2 {
		t.Errorf("expected 2 skipped files on second run, got %d", stats2.SkippedFiles)
	}
}

func TestSync_Modified_And_ConflictBackup(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("mock-src")
	destDrv := storage.NewMockDriver("mock-dest")

	_ = srcDrv.Write(ctx, "report.pdf", bytes.NewReader([]byte("source version")), 14)
	_ = destDrv.Write(ctx, "report.pdf", bytes.NewReader([]byte("destination divergent version")), 29)

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{})
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if stats.UpdatedFiles != 1 {
		t.Errorf("expected 1 updated file, got %d", stats.UpdatedFiles)
	}
	if stats.ConflictFiles != 1 {
		t.Errorf("expected 1 conflict backup, got %d", stats.ConflictFiles)
	}
	if len(stats.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict recorded in stats, got %d", len(stats.Conflicts))
	}

	// Verify conflict file content
	conflictFile := stats.Conflicts[0]
	rc, err := destDrv.Read(ctx, conflictFile)
	if err != nil {
		t.Fatalf("failed to read conflict backup %q: %v", conflictFile, err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "destination divergent version" {
		t.Errorf("conflict content mismatch: got %q", string(data))
	}

	// Verify dest has the new source content
	rc2, err := destDrv.Read(ctx, "report.pdf")
	if err != nil {
		t.Fatalf("failed to read updated dest: %v", err)
	}
	defer rc2.Close()
	data2, _ := io.ReadAll(rc2)
	if string(data2) != "source version" {
		t.Errorf("dest file content mismatch: got %q", string(data2))
	}
}

func TestSync_NoConflictBackupFlag(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("mock-src")
	destDrv := storage.NewMockDriver("mock-dest")

	_ = srcDrv.Write(ctx, "f.txt", bytes.NewReader([]byte("new content")), 11)
	_ = destDrv.Write(ctx, "f.txt", bytes.NewReader([]byte("old content long")), 16)

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{NoConflictBackup: true})
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if stats.ConflictFiles != 0 {
		t.Errorf("expected 0 conflict backups with NoConflictBackup=true, got %d", stats.ConflictFiles)
	}
	if stats.UpdatedFiles != 1 {
		t.Errorf("expected 1 updated file, got %d", stats.UpdatedFiles)
	}
}

func TestSync_DeleteFlag(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("mock-src")
	destDrv := storage.NewMockDriver("mock-dest")

	_ = srcDrv.Write(ctx, "keep.txt", bytes.NewReader([]byte("keep")), 4)
	_ = destDrv.Write(ctx, "keep.txt", bytes.NewReader([]byte("keep")), 4)
	_ = destDrv.Write(ctx, "extra.txt", bytes.NewReader([]byte("extra to delete")), 15)

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{Delete: true})
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if stats.DeletedFiles != 1 {
		t.Errorf("expected 1 deleted file, got %d", stats.DeletedFiles)
	}

	// Verify extra.txt is gone
	if _, err := destDrv.Stat(ctx, "extra.txt"); err == nil {
		t.Errorf("expected extra.txt to be deleted from destination")
	}
}

func TestSync_DryRun(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("mock-src")
	destDrv := storage.NewMockDriver("mock-dest")

	_ = srcDrv.Write(ctx, "file.txt", bytes.NewReader([]byte("dry run content")), 15)
	_ = destDrv.Write(ctx, "extra.txt", bytes.NewReader([]byte("extra")), 5)

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{
		DryRun: true,
		Delete: true,
	})
	if err != nil {
		t.Fatalf("Sync dry run failed: %v", err)
	}

	if stats.TransferredFiles != 1 {
		t.Errorf("expected 1 simulated transfer, got %d", stats.TransferredFiles)
	}
	if stats.DeletedFiles != 1 {
		t.Errorf("expected 1 simulated delete, got %d", stats.DeletedFiles)
	}

	// Destination should NOT have file.txt and should STILL have extra.txt
	if _, err := destDrv.Stat(ctx, "file.txt"); err == nil {
		t.Errorf("file.txt should not be written during dry run")
	}
	if _, err := destDrv.Stat(ctx, "extra.txt"); err != nil {
		t.Errorf("extra.txt should not be deleted during dry run")
	}
}

func TestSync_ChecksumMode(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("mock-src")
	destDrv := storage.NewMockDriver("mock-dest")

	// Same size, different content
	_ = srcDrv.Write(ctx, "diff.txt", bytes.NewReader([]byte("AAAA")), 4)
	_ = destDrv.Write(ctx, "diff.txt", bytes.NewReader([]byte("BBBB")), 4)

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{Checksum: true})
	if err != nil {
		t.Fatalf("Sync checksum failed: %v", err)
	}

	if stats.UpdatedFiles != 1 {
		t.Errorf("expected 1 updated file under checksum mode, got %d", stats.UpdatedFiles)
	}
	if stats.ConflictFiles != 1 {
		t.Errorf("expected 1 conflict file under checksum mode, got %d", stats.ConflictFiles)
	}
}

func TestSync_RecursiveGuard(t *testing.T) {
	tempDir := t.TempDir()
	srcDir := filepath.Join(tempDir, "source")
	destDir := filepath.Join(srcDir, "backup") // inside source!

	srcDrv, err := local.New(srcDir)
	if err != nil {
		t.Fatalf("failed to create src driver: %v", err)
	}
	destDrv, err := local.New(destDir)
	if err != nil {
		t.Fatalf("failed to create dest driver: %v", err)
	}

	_, err = Sync(context.Background(), srcDrv, "", destDrv, "", SyncOptions{})
	if err != ErrRecursiveSync {
		t.Errorf("expected ErrRecursiveSync, got %v", err)
	}
}

func TestSync_Concurrency(t *testing.T) {
	ctx := context.Background()
	srcDrv := storage.NewMockDriver("mock-src")
	destDrv := storage.NewMockDriver("mock-dest")

	const numFiles = 20
	for i := 0; i < numFiles; i++ {
		name := fmt.Sprintf("chunk_%d.dat", i)
		content := []byte(fmt.Sprintf("content for file %d", i))
		_ = srcDrv.Write(ctx, name, bytes.NewReader(content), int64(len(content)))
	}

	stats, err := Sync(ctx, srcDrv, "", destDrv, "", SyncOptions{Workers: 4})
	if err != nil {
		t.Fatalf("concurrent sync failed: %v", err)
	}

	if stats.TransferredFiles != numFiles {
		t.Errorf("expected %d transferred files, got %d", numFiles, stats.TransferredFiles)
	}

	for i := 0; i < numFiles; i++ {
		name := fmt.Sprintf("chunk_%d.dat", i)
		if _, err := destDrv.Stat(ctx, name); err != nil {
			t.Errorf("file %s not found in dest: %v", name, err)
		}
	}
}
