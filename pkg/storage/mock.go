package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// MockDriver is an in-memory, thread-safe implementation of Driver and AdvancedDriver for testing.
type MockDriver struct {
	mu      sync.RWMutex
	name    string
	objects map[string][]byte
	info    map[string]ObjectInfo
}

// NewMockDriver creates an initialized MockDriver.
func NewMockDriver(name ...string) *MockDriver {
	driverName := "mock"
	if len(name) > 0 && name[0] != "" {
		driverName = name[0]
	}
	return &MockDriver{
		name:    driverName,
		objects: make(map[string][]byte),
		info:    make(map[string]ObjectInfo),
	}
}

func (m *MockDriver) normalizeKey(k string) string {
	cleaned := path.Clean("/" + strings.ReplaceAll(k, "\\", "/"))
	return strings.TrimPrefix(cleaned, "/")
}

// Name returns the driver identifier.
func (m *MockDriver) Name() string {
	return m.name
}

// Read returns an io.ReadCloser for the object data.
func (m *MockDriver) Read(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k := m.normalizeKey(key)

	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.objects[k]
	if !ok {
		return nil, &StorageError{Op: "read", Driver: m.name, Path: key, Err: ErrNotFound}
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Write streams data from r into the in-memory object store.
func (m *MockDriver) Write(ctx context.Context, key string, r io.Reader, size int64) error {
	return m.WriteWithOptions(ctx, key, r, size)
}

// WriteWithOptions stores an object with custom options.
func (m *MockDriver) WriteWithOptions(ctx context.Context, key string, r io.Reader, size int64, opts ...WriteOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k := m.normalizeKey(key)
	if k == "" {
		return &StorageError{Op: "write", Driver: m.name, Path: key, Err: ErrInvalidPath}
	}

	options := DefaultWriteOptions()
	for _, opt := range opts {
		opt(&options)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if !options.Overwrite {
		if _, exists := m.objects[k]; exists {
			return &StorageError{Op: "write", Driver: m.name, Path: key, Err: ErrAlreadyExists}
		}
	}

	var buf bytes.Buffer
	if _, err := StreamCopy(&buf, r); err != nil {
		return &StorageError{Op: "write", Driver: m.name, Path: key, Err: err}
	}
	data := buf.Bytes()

	hash := sha256.Sum256(data)
	etag := hex.EncodeToString(hash[:])

	contentType := options.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	metaCopy := make(map[string]string)
	for k, v := range options.Metadata {
		metaCopy[k] = v
	}

	m.objects[k] = data
	m.info[k] = ObjectInfo{
		Key:         k,
		Path:        k,
		Size:        int64(len(data)),
		ModTime:     time.Now().UTC(),
		IsDir:       false,
		ETag:        etag,
		ContentType: contentType,
		Metadata:    metaCopy,
	}

	return nil
}

// List returns all objects matching the prefix.
func (m *MockDriver) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	res, err := m.ListWithOptions(ctx, ListOptions{Prefix: prefix, Recursive: true})
	if err != nil {
		return nil, err
	}
	return res.Objects, nil
}

// ListWithOptions returns paginated listing results.
func (m *MockDriver) ListWithOptions(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cleanPrefix := m.normalizeKey(opts.Prefix)

	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []ObjectInfo
	for k, info := range m.info {
		if cleanPrefix == "" || strings.HasPrefix(k, cleanPrefix) {
			matched = append(matched, info)
		}
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Key < matched[j].Key
	})

	startIdx := 0
	if opts.ContinuationToken != "" {
		for i, obj := range matched {
			if obj.Key > opts.ContinuationToken {
				startIdx = i
				break
			}
			if i == len(matched)-1 {
				startIdx = len(matched)
			}
		}
	}

	maxKeys := opts.MaxKeys
	if maxKeys <= 0 {
		maxKeys = len(matched)
	}

	endIdx := startIdx + maxKeys
	var nextToken string
	truncated := false
	if endIdx < len(matched) {
		truncated = true
		nextToken = matched[endIdx-1].Key
	} else {
		endIdx = len(matched)
	}

	var resultObjects []ObjectInfo
	if startIdx < len(matched) {
		resultObjects = matched[startIdx:endIdx]
	}

	return &ListResult{
		Objects:               resultObjects,
		NextContinuationToken: nextToken,
		IsTruncated:           truncated,
	}, nil
}

// Delete removes the specified object. Idempotent per spec.
func (m *MockDriver) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k := m.normalizeKey(key)

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.objects, k)
	delete(m.info, k)
	return nil
}

// Stat retrieves metadata for an object without returning its content.
func (m *MockDriver) Stat(ctx context.Context, key string) (*ObjectInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k := m.normalizeKey(key)

	m.mu.RLock()
	defer m.mu.RUnlock()

	info, ok := m.info[k]
	if !ok {
		return nil, &StorageError{Op: "stat", Driver: m.name, Path: key, Err: ErrNotFound}
	}
	res := info
	return &res, nil
}

// Stream writes object content directly into w using pooled constant memory.
func (m *MockDriver) Stream(ctx context.Context, key string, w io.Writer) error {
	rc, err := m.Read(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = StreamCopy(w, rc)
	return err
}

// Verify interface implementations at compile time.
var _ Driver = (*MockDriver)(nil)
var _ AdvancedDriver = (*MockDriver)(nil)
