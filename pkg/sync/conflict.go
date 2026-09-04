package sync

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

// DefaultConflictDir is the standard sub-directory where displaced destination files are backed up.
const DefaultConflictDir = ".conflicts"

// BackupConflict safely copies an existing divergent destination file to
// <conflictDir>/<path>.<timestamp>.conflict before it is overwritten.
// If conflictDir is empty, DefaultConflictDir (".conflicts") is used.
// If conflictDir is an absolute filesystem path, the backup is saved directly to that directory.
// Otherwise, it is written via the destination storage driver relative to its root.
func BackupConflict(ctx context.Context, destDriver storage.Driver, relPath string, conflictDir string) (string, error) {
	if conflictDir == "" {
		conflictDir = DefaultConflictDir
	}

	normalized := strings.TrimPrefix(strings.ReplaceAll(relPath, "\\", "/"), "/")
	timestamp := time.Now().UTC().Format("20060102T150405Z")

	// Stat original file on destination to ensure it exists and get size
	info, err := destDriver.Stat(ctx, relPath)
	if err != nil {
		return "", fmt.Errorf("conflict backup aborted: cannot stat existing dest file %q: %w", relPath, err)
	}

	// Open destination file stream
	rc, err := destDriver.Read(ctx, relPath)
	if err != nil {
		return "", fmt.Errorf("conflict backup aborted: cannot read existing dest file %q: %w", relPath, err)
	}
	defer rc.Close()

	// Handle case where conflictDir is an absolute local filesystem path
	if filepath.IsAbs(conflictDir) {
		destFile := filepath.Join(conflictDir, filepath.FromSlash(normalized)+"."+timestamp+".conflict")
		if err := os.MkdirAll(filepath.Dir(destFile), 0750); err != nil {
			return "", fmt.Errorf("conflict backup aborted: cannot create conflict directory %q: %w", filepath.Dir(destFile), err)
		}
		// #nosec G302, G304 -- conflict file written to isolated directory with restricted permissions
		f, err := os.OpenFile(destFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return "", fmt.Errorf("conflict backup aborted: cannot create conflict backup file %q: %w", destFile, err)
		}
		defer f.Close()

		bufPtr := storage.BufferPool.Get().(*[]byte)
		defer storage.BufferPool.Put(bufPtr)
		if _, err := io.CopyBuffer(f, rc, *bufPtr); err != nil {
			return "", fmt.Errorf("conflict backup aborted: stream copy error for %q: %w", destFile, err)
		}
		return destFile, nil
	}

	// Relative conflict path on destination driver
	cleanConflictDir := strings.Trim(strings.ReplaceAll(conflictDir, "\\", "/"), "/")
	conflictPath := fmt.Sprintf("%s/%s.%s.conflict", cleanConflictDir, normalized, timestamp)

	if err := destDriver.Write(ctx, conflictPath, rc, info.Size); err != nil {
		return "", fmt.Errorf("conflict backup aborted: failed to write backup %q: %w", conflictPath, err)
	}

	return conflictPath, nil
}
