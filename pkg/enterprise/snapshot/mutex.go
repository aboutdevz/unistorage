package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

var (
	ErrJobAlreadyRunning = errors.New("snapshot job already in progress")
	ErrLockAcquisition   = errors.New("failed to acquire job lock")
)

const LockFileName = ".job.lock"

// JobMutexRegistry provides in-memory non-blocking mutual exclusion per job_id.
type JobMutexRegistry struct {
	mu    sync.Mutex
	locks map[string]bool
}

// NewJobMutexRegistry constructs an empty job mutex registry.
func NewJobMutexRegistry() *JobMutexRegistry {
	return &JobMutexRegistry{
		locks: make(map[string]bool),
	}
}

// TryLock attempts to acquire the lock for jobID without blocking.
// Returns true if acquired, false if already held.
func (r *JobMutexRegistry) TryLock(jobID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.locks[jobID] {
		return false
	}
	r.locks[jobID] = true
	return true
}

// Unlock releases the in-memory lock for jobID.
func (r *JobMutexRegistry) Unlock(jobID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.locks, jobID)
}

// LockInfo records ownership and timing of a storage-level lock.
type LockInfo struct {
	PID      int       `json:"pid"`
	Hostname string    `json:"hostname"`
	LockedAt time.Time `json:"locked_at"`
}

// StorageLock handles storage-level lock files with stale lock reclamation.
type StorageLock struct {
	driver   storage.Driver
	lockPath string
	info     LockInfo
}

// AcquireStorageLock creates or reclaims a `.job.lock` file on the destination storage.
func AcquireStorageLock(ctx context.Context, d storage.Driver, destDir string, timeoutMinutes int) (*StorageLock, error) {
	cleanDir := strings.Trim(destDir, "/")
	lockPath := path.Join(cleanDir, LockFileName)

	// Check if existing lock file exists
	existingInfo, err := readLockInfo(ctx, d, lockPath)
	if err == nil && existingInfo != nil {
		timeout := time.Duration(timeoutMinutes) * time.Minute
		if timeout <= 0 {
			timeout = 60 * time.Minute
		}

		age := time.Since(existingInfo.LockedAt)
		if age < timeout {
			// Lock is active and not stale
			return nil, fmt.Errorf("%w: held by PID %d on %s (locked %s ago)",
				ErrJobAlreadyRunning, existingInfo.PID, existingInfo.Hostname, age.Round(time.Second))
		}
		// Stale lock detected -> reclaim lock
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}

	info := LockInfo{
		PID:      os.Getpid(),
		Hostname: hostname,
		LockedAt: time.Now().UTC(),
	}

	data, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal lock info: %w", err)
	}

	if err := d.Write(ctx, lockPath, bytes.NewReader(data), int64(len(data))); err != nil {
		return nil, fmt.Errorf("%w: cannot write lock file: %v", ErrLockAcquisition, err)
	}

	return &StorageLock{
		driver:   d,
		lockPath: lockPath,
		info:     info,
	}, nil
}

// Release deletes the storage-level lock file.
func (sl *StorageLock) Release(ctx context.Context) error {
	if sl == nil || sl.driver == nil {
		return nil
	}
	return sl.driver.Delete(ctx, sl.lockPath)
}

func readLockInfo(ctx context.Context, d storage.Driver, lockPath string) (*LockInfo, error) {
	rc, err := d.Read(ctx, lockPath)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	var info LockInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}
