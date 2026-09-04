package local

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

// Driver implements storage.Driver and storage.AdvancedDriver backed by the local filesystem.
type Driver struct {
	sanitizer *PathSanitizer
	rootDir   string
}

// New creates a new local filesystem driver rooted at rootDir.
func New(rootDir string) (*Driver, error) {
	sanitizer, err := NewPathSanitizer(rootDir)
	if err != nil {
		return nil, fmt.Errorf("local driver init failed: %w", err)
	}

	// Ensure root directory exists
	if err := os.MkdirAll(sanitizer.CanonicalRoot(), 0755); err != nil {
		return nil, fmt.Errorf("failed to create root dir %q: %w", sanitizer.CanonicalRoot(), err)
	}

	return &Driver{
		sanitizer: sanitizer,
		rootDir:   sanitizer.CanonicalRoot(),
	}, nil
}

// Name returns "local".
func (d *Driver) Name() string {
	return "local"
}

// RootDir returns the canonical root directory of this driver.
func (d *Driver) RootDir() string {
	return d.rootDir
}

// SanitizePath checks and translates userPath to a safe host filesystem path.
func (d *Driver) SanitizePath(userPath string) (string, error) {
	return d.sanitizer.Sanitize(userPath)
}

// Read opens a file for reading.
func (d *Driver) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fullPath, err := d.SanitizePath(path)
	if err != nil {
		return nil, &storage.StorageError{Op: "read", Driver: "local", Path: path, Err: err}
	}

	f, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &storage.StorageError{Op: "read", Driver: "local", Path: path, Err: storage.ErrNotFound}
		}
		if os.IsPermission(err) {
			return nil, &storage.StorageError{Op: "read", Driver: "local", Path: path, Err: storage.ErrPermissionDenied}
		}
		return nil, &storage.StorageError{Op: "read", Driver: "local", Path: path, Err: err}
	}

	return f, nil
}

// Write writes data from r into destination file using atomic replacement.
func (d *Driver) Write(ctx context.Context, path string, r io.Reader, size int64) error {
	return d.WriteWithOptions(ctx, path, r, size)
}

// WriteWithOptions writes data with custom options using atomic replacement.
func (d *Driver) WriteWithOptions(ctx context.Context, path string, r io.Reader, size int64, opts ...storage.WriteOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	fullPath, err := d.SanitizePath(path)
	if err != nil {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: err}
	}

	options := storage.DefaultWriteOptions()
	for _, opt := range opts {
		opt(&options)
	}

	// Check if already exists when Overwrite is false
	if !options.Overwrite {
		if _, err := os.Stat(fullPath); err == nil {
			return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: storage.ErrAlreadyExists}
		}
	}

	// 1. Ensure parent directory exists
	parentDir := filepath.Dir(fullPath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("failed to create parent dir: %w", err)}
	}

	// 2. Generate random sibling temp file name
	var randBytes [8]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("failed to generate random suffix: %w", err)}
	}
	tmpPath := fmt.Sprintf("%s.tmp.%s", fullPath, hex.EncodeToString(randBytes[:]))

	// 3. Create temp file
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("failed to create temp file: %w", err)}
	}

	// Ensure cleanup on failure
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// 4. Stream data using pooled 64KB buffer
	hasher := sha256.New()
	multiWriter := io.MultiWriter(tmpFile, hasher)

	var written int64
	if size >= 0 {
		written, err = storage.StreamCopy(multiWriter, io.LimitReader(r, size))
	} else {
		written, err = storage.StreamCopy(multiWriter, r)
	}
	if err != nil {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("streaming write failed: %w", err)}
	}

	if size >= 0 && written < size {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("unexpected EOF: wrote %d of %d bytes", written, size)}
	}

	// 5. Commit disk cache to physical storage
	if err := tmpFile.Sync(); err != nil {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("failed to sync temp file: %w", err)}
	}

	// 6. Close before rename
	if err := tmpFile.Close(); err != nil {
		return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("failed to close temp file: %w", err)}
	}

	// 7. Atomic rename
	if err := os.Rename(tmpPath, fullPath); err != nil {
		// On Windows, if destination exists, rename might fail unless removed first
		_ = os.Remove(fullPath)
		if retryErr := os.Rename(tmpPath, fullPath); retryErr != nil {
			return &storage.StorageError{Op: "write", Driver: "local", Path: path, Err: fmt.Errorf("atomic rename failed: %w", retryErr)}
		}
	}

	cleanup = false
	return nil
}

// List enumerates files matching the prefix.
func (d *Driver) List(ctx context.Context, prefix string) ([]storage.ObjectInfo, error) {
	res, err := d.ListWithOptions(ctx, storage.ListOptions{Prefix: prefix, Recursive: true})
	if err != nil {
		return nil, err
	}
	return res.Objects, nil
}

// ListWithOptions lists files with pagination and filtering options.
func (d *Driver) ListWithOptions(ctx context.Context, opts storage.ListOptions) (*storage.ListResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cleanPrefix := strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+opts.Prefix)), "/")
	if cleanPrefix == "." {
		cleanPrefix = ""
	}

	var results []storage.ObjectInfo
	err := filepath.WalkDir(d.rootDir, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		// Calculate relative path from rootDir
		rel, err := filepath.Rel(d.rootDir, filePath)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		relSlash := filepath.ToSlash(rel)

		// Prefix filtering
		if cleanPrefix != "" && !strings.HasPrefix(relSlash, cleanPrefix) && !strings.HasPrefix(cleanPrefix, relSlash) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return nil
		}

		// If not recursive, skip subdirectories unless directly in prefix
		if !opts.Recursive && entry.IsDir() && relSlash != cleanPrefix {
			return filepath.SkipDir
		}

		if cleanPrefix == "" || strings.HasPrefix(relSlash, cleanPrefix) {
			modTime := info.ModTime().UTC()
			obj := storage.ObjectInfo{
				Key:     relSlash,
				Path:    relSlash,
				Size:    info.Size(),
				ModTime: modTime,
				IsDir:   entry.IsDir(),
			}
			results = append(results, obj)
		}

		return nil
	})

	if err != nil {
		return nil, &storage.StorageError{Op: "list", Driver: "local", Path: opts.Prefix, Err: err}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Key < results[j].Key
	})

	// Pagination
	startIdx := 0
	if opts.ContinuationToken != "" {
		for i, obj := range results {
			if obj.Key > opts.ContinuationToken {
				startIdx = i
				break
			}
			if i == len(results)-1 {
				startIdx = len(results)
			}
		}
	}

	maxKeys := opts.MaxKeys
	if maxKeys <= 0 {
		maxKeys = len(results)
	}

	endIdx := startIdx + maxKeys
	var nextToken string
	truncated := false
	if endIdx < len(results) {
		truncated = true
		nextToken = results[endIdx-1].Key
	} else {
		endIdx = len(results)
	}

	var pagedObjects []storage.ObjectInfo
	if startIdx < len(results) {
		pagedObjects = results[startIdx:endIdx]
	}

	return &storage.ListResult{
		Objects:               pagedObjects,
		NextContinuationToken: nextToken,
		IsTruncated:           truncated,
	}, nil
}

// Delete removes the specified object. Idempotent: returns nil if object does not exist.
func (d *Driver) Delete(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	fullPath, err := d.SanitizePath(path)
	if err != nil {
		return &storage.StorageError{Op: "delete", Driver: "local", Path: path, Err: err}
	}

	err = os.Remove(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Idempotent deletion
		}
		return &storage.StorageError{Op: "delete", Driver: "local", Path: path, Err: err}
	}
	return nil
}

// Stat retrieves metadata for the specified path without reading content.
func (d *Driver) Stat(ctx context.Context, path string) (*storage.ObjectInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	fullPath, err := d.SanitizePath(path)
	if err != nil {
		return nil, &storage.StorageError{Op: "stat", Driver: "local", Path: path, Err: err}
	}

	fi, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &storage.StorageError{Op: "stat", Driver: "local", Path: path, Err: storage.ErrNotFound}
		}
		if os.IsPermission(err) {
			return nil, &storage.StorageError{Op: "stat", Driver: "local", Path: path, Err: storage.ErrPermissionDenied}
		}
		return nil, &storage.StorageError{Op: "stat", Driver: "local", Path: path, Err: err}
	}

	rel, _ := filepath.Rel(d.rootDir, fullPath)
	relSlash := filepath.ToSlash(rel)

	return &storage.ObjectInfo{
		Key:     relSlash,
		Path:    relSlash,
		Size:    fi.Size(),
		ModTime: fi.ModTime().UTC(),
		IsDir:   fi.IsDir(),
	}, nil
}

// Stream reads the object directly into w using constant memory O(1).
func (d *Driver) Stream(ctx context.Context, path string, w io.Writer) error {
	rc, err := d.Read(ctx, path)
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = storage.StreamCopy(w, rc)
	return err
}

// Verify interface implementations at compile time.
var _ storage.Driver = (*Driver)(nil)
var _ storage.AdvancedDriver = (*Driver)(nil)
