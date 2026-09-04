package sync

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

func TestConflictBackup_DefaultDir(t *testing.T) {
	ctx := context.Background()
	drv := storage.NewMockDriver("mock-dest")

	content := []byte("original divergent destination content")
	err := drv.Write(ctx, "docs/report.pdf", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("failed to write original: %v", err)
	}

	conflictPath, err := BackupConflict(ctx, drv, "docs/report.pdf", "")
	if err != nil {
		t.Fatalf("BackupConflict failed: %v", err)
	}

	// Verify path structure: .conflicts/docs/report.pdf.<timestamp>.conflict
	if !strings.HasPrefix(conflictPath, ".conflicts/docs/report.pdf.") {
		t.Errorf("expected path to start with .conflicts/docs/report.pdf., got %q", conflictPath)
	}
	if !strings.HasSuffix(conflictPath, ".conflict") {
		t.Errorf("expected path to end with .conflict, got %q", conflictPath)
	}

	// Verify timestamp format
	trimmed := strings.TrimPrefix(conflictPath, ".conflicts/docs/report.pdf.")
	timestamp := strings.TrimSuffix(trimmed, ".conflict")
	if _, err := time.Parse("20060102T150405Z", timestamp); err != nil {
		t.Errorf("invalid timestamp in conflict path %q: %v", timestamp, err)
	}

	// Verify backup content matches original
	rc, err := drv.Read(ctx, conflictPath)
	if err != nil {
		t.Fatalf("failed to read backup: %v", err)
	}
	defer rc.Close()
	backupData, _ := io.ReadAll(rc)
	if !bytes.Equal(backupData, content) {
		t.Errorf("backup content mismatch: expected %s, got %s", content, backupData)
	}
}

func TestConflictBackup_CustomRelativeDir(t *testing.T) {
	ctx := context.Background()
	drv := storage.NewMockDriver("mock-dest")

	content := []byte("data")
	_ = drv.Write(ctx, "file.txt", bytes.NewReader(content), int64(len(content)))

	conflictPath, err := BackupConflict(ctx, drv, "file.txt", "my_backup_conflicts")
	if err != nil {
		t.Fatalf("BackupConflict error: %v", err)
	}

	if !strings.HasPrefix(conflictPath, "my_backup_conflicts/file.txt.") {
		t.Errorf("expected custom conflict prefix, got %q", conflictPath)
	}
}

func TestConflictBackup_CustomAbsoluteDir(t *testing.T) {
	ctx := context.Background()
	drv := storage.NewMockDriver("mock-dest")
	tmpDir := t.TempDir()

	content := []byte("content to backup to absolute dir")
	_ = drv.Write(ctx, "nested/file.txt", bytes.NewReader(content), int64(len(content)))

	conflictFile, err := BackupConflict(ctx, drv, "nested/file.txt", tmpDir)
	if err != nil {
		t.Fatalf("BackupConflict error: %v", err)
	}

	if !filepath.IsAbs(conflictFile) {
		t.Errorf("expected absolute path, got %q", conflictFile)
	}

	data, err := os.ReadFile(conflictFile)
	if err != nil {
		t.Fatalf("failed to read backup file from disk: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("content mismatch in disk backup: expected %s, got %s", content, data)
	}
}
