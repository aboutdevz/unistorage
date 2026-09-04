package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

var (
	ErrNotFound           = errors.New("storage: object not found")
	ErrAlreadyExists      = errors.New("storage: object already exists")
	ErrPathTraversal      = errors.New("storage: path traversal detected")
	ErrInvalidPath        = errors.New("storage: invalid path")
	ErrPermissionDenied   = errors.New("storage: permission denied")
	ErrStorageUnavailable = errors.New("storage: backend unavailable")
	ErrPreconditionFailed = errors.New("storage: precondition failed")
	ErrInvalidRange       = errors.New("storage: invalid byte range")
)

// ObjectInfo holds metadata for a stored object or directory entry.
type ObjectInfo struct {
	Key         string            `json:"key"`
	Path        string            `json:"path"`
	Size        int64             `json:"size"`
	ModTime     time.Time         `json:"mod_time"`
	IsDir       bool              `json:"is_dir"`
	ETag        string            `json:"etag,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// WriteOptions provides optional configuration for write operations.
type WriteOptions struct {
	ContentType string            `json:"content_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Overwrite   bool              `json:"overwrite"`
}

// WriteOption configures a WriteOptions instance.
type WriteOption func(*WriteOptions)

// WithContentType sets the content type on write.
func WithContentType(ct string) WriteOption {
	return func(o *WriteOptions) { o.ContentType = ct }
}

// WithMetadata sets custom metadata on write.
func WithMetadata(meta map[string]string) WriteOption {
	return func(o *WriteOptions) { o.Metadata = meta }
}

// WithNoOverwrite disables overwriting existing objects.
func WithNoOverwrite() WriteOption {
	return func(o *WriteOptions) { o.Overwrite = false }
}

// DefaultWriteOptions returns standard write options allowing overwrite.
func DefaultWriteOptions() WriteOptions {
	return WriteOptions{
		Overwrite: true,
	}
}

// ListOptions specifies parameters for directory or object listing.
type ListOptions struct {
	Prefix            string `json:"prefix"`
	Recursive         bool   `json:"recursive"`
	MaxKeys           int    `json:"max_keys"`
	ContinuationToken string `json:"continuation_token"`
	Delimiter         string `json:"delimiter"`
}

// ListResult holds a page of listing results.
type ListResult struct {
	Objects               []ObjectInfo `json:"objects"`
	NextContinuationToken string       `json:"next_continuation_token,omitempty"`
	IsTruncated           bool         `json:"is_truncated"`
}

// StorageError provides structured diagnostic context for storage operations.
type StorageError struct {
	Op     string // e.g. "read", "write", "list", "delete", "stat", "stream"
	Driver string // e.g. "local", "s3", "mock"
	Path   string
	Err    error
}

func (e *StorageError) Error() string {
	return fmt.Sprintf("storage %s %s [%s]: %v", e.Driver, e.Op, e.Path, e.Err)
}

func (e *StorageError) Unwrap() error {
	return e.Err
}

// Driver is the core unified storage interface for heterogeneous backends.
// Implementations must be thread-safe.
type Driver interface {
	Name() string
	Read(ctx context.Context, path string) (io.ReadCloser, error)
	Write(ctx context.Context, path string, r io.Reader, size int64) error
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
	Delete(ctx context.Context, path string) error
	Stat(ctx context.Context, path string) (*ObjectInfo, error)
	Stream(ctx context.Context, path string, w io.Writer) error
}

// AdvancedDriver extends Driver with options-based methods.
type AdvancedDriver interface {
	Driver
	WriteWithOptions(ctx context.Context, path string, r io.Reader, size int64, opts ...WriteOption) error
	ListWithOptions(ctx context.Context, opts ListOptions) (*ListResult, error)
}

// BufferPool manages reusable 64KB buffers for constant-memory streaming.
var BufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

// StreamCopy copies from src to dst using a pooled 64KB buffer for constant O(1) memory usage.
func StreamCopy(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := BufferPool.Get().(*[]byte)
	defer BufferPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}
