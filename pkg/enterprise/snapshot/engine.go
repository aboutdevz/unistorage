package snapshot

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/license"
	"github.com/aboutdevz/unistorage/pkg/storage"
)

// SnapshotRunResult contains execution details of a completed backup.
type SnapshotRunResult struct {
	SnapshotID    string       `json:"snapshot_id"`
	JobID         string       `json:"job_id"`
	SnapshotDir   string       `json:"snapshot_dir"`
	Manifest      *Manifest    `json:"manifest"`
	PruneResult   *PruneResult `json:"prune_result,omitempty"`
	Duration      time.Duration
	SkippedDueToLock bool      `json:"skipped_due_to_lock"`
}

// Engine orchestrates snapshot backups, locking, manifests, and retention pruning.
type Engine struct {
	mutexRegistry *JobMutexRegistry
	license       license.EntitlementChecker
}

// NewEngine constructs a snapshot backup engine.
func NewEngine(mutexRegistry *JobMutexRegistry, checker license.EntitlementChecker) *Engine {
	if mutexRegistry == nil {
		mutexRegistry = NewJobMutexRegistry()
	}
	if checker == nil {
		checker = license.NewCommunityChecker()
	}
	return &Engine{
		mutexRegistry: mutexRegistry,
		license:       checker,
	}
}

// ExecuteBackup runs a complete snapshot cycle for the specified job policy.
func (e *Engine) ExecuteBackup(ctx context.Context, job JobConfig, srcDriver, destDriver storage.Driver) (*SnapshotRunResult, error) {
	startTime := time.Now().UTC()

	// Step 1: Entitlement enforcement
	if err := e.license.Require(ctx, license.FeatureSnapshotBackup); err != nil {
		return nil, fmt.Errorf("license entitlement check failed: %w", err)
	}
	if job.RetentionLimit > 0 {
		if err := e.license.Require(ctx, license.FeatureRetentionPrune); err != nil {
			return nil, fmt.Errorf("retention pruning not licensed: %w", err)
		}
	}

	// Step 2: In-memory non-blocking mutual exclusion
	if !e.mutexRegistry.TryLock(job.JobID) {
		return &SnapshotRunResult{
			JobID:            job.JobID,
			SkippedDueToLock: true,
		}, ErrJobAlreadyRunning
	}
	defer e.mutexRegistry.Unlock(job.JobID)

	// Step 3: Storage-level lock acquisition & stale reclamation
	storageLock, err := AcquireStorageLock(ctx, destDriver, job.DestPath, job.TimeoutMinutes)
	if err != nil {
		return &SnapshotRunResult{
			JobID:            job.JobID,
			SkippedDueToLock: true,
		}, err
	}
	defer func() {
		_ = storageLock.Release(context.Background())
	}()

	// Step 4: Prepare snapshot directory
	timestampStr := startTime.Format("2006-01-02T15-04-05Z")
	snapshotID := fmt.Sprintf("snap-%s-%s", job.JobID, timestampStr)
	cleanDestPath := strings.Trim(job.DestPath, "/")
	snapshotDir := path.Join(cleanDestPath, "snapshots", timestampStr)

	// Step 5: Enumerate source objects
	cleanSrcPath := strings.Trim(job.SourcePath, "/")
	srcObjects, err := srcDriver.List(ctx, cleanSrcPath)
	if err != nil {
		return nil, fmt.Errorf("failed listing source path %s: %w", cleanSrcPath, err)
	}

	var snapshotFiles []SnapshotFile
	var totalBytes int64

	// Step 6: Transfer objects and compute SHA256
	for _, obj := range srcObjects {
		if obj.IsDir {
			continue
		}

		relPath := strings.TrimPrefix(strings.Trim(obj.Path, "/"), cleanSrcPath)
		relPath = strings.Trim(relPath, "/")
		if relPath == "" {
			relPath = path.Base(obj.Path)
		}

		targetObjPath := path.Join(snapshotDir, relPath)

		rc, err := srcDriver.Read(ctx, obj.Path)
		if err != nil {
			return nil, fmt.Errorf("failed reading source object %s: %w", obj.Path, err)
		}

		hasher := sha256.New()
		tee := ioTeeReader(rc, hasher)

		err = destDriver.Write(ctx, targetObjPath, tee, obj.Size)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("failed writing snapshot object %s: %w", targetObjPath, err)
		}

		hashStr := fmt.Sprintf("%x", hasher.Sum(nil))
		snapshotFiles = append(snapshotFiles, SnapshotFile{
			Path:    relPath,
			Size:    obj.Size,
			SHA256:  hashStr,
			ModTime: obj.ModTime,
			Mode:    "-rw-r--r--",
		})
		totalBytes += obj.Size
	}

	duration := time.Since(startTime)

	// Step 7: Build and write manifest
	manifest := &Manifest{
		ManifestVersion: ManifestVersionCurrent,
		SnapshotID:      snapshotID,
		JobID:           job.JobID,
		Timestamp:       startTime,
		SourceRemote:    job.SourceRemote,
		SourcePath:      job.SourcePath,
		DestRemote:      job.DestRemote,
		DestPath:        snapshotDir,
		Stats: SnapshotStats{
			TotalFiles:      len(snapshotFiles),
			TotalBytes:      totalBytes,
			DurationSeconds: duration.Seconds(),
			Status:          StatusSuccess,
		},
		Files: snapshotFiles,
	}

	if err := WriteManifest(ctx, destDriver, snapshotDir, manifest); err != nil {
		return nil, fmt.Errorf("failed writing snapshot manifest: %w", err)
	}

	// Step 8: Retention pruning
	var pruneResult *PruneResult
	if job.RetentionLimit > 0 {
		pruner := NewPruner(destDriver)
		pRes, err := pruner.Prune(ctx, job.DestPath, job.RetentionLimit)
		if err != nil {
			// Log and continue, do not abort completed backup
			pruneResult = pRes
		} else {
			pruneResult = pRes
		}
	}

	return &SnapshotRunResult{
		SnapshotID:  snapshotID,
		JobID:       job.JobID,
		SnapshotDir: snapshotDir,
		Manifest:    manifest,
		PruneResult: pruneResult,
		Duration:    duration,
	}, nil
}

type teeReadCloser struct {
	r io.Reader
}

func (t *teeReadCloser) Read(p []byte) (n int, err error) {
	return t.r.Read(p)
}

func ioTeeReader(r io.Reader, w io.Writer) io.Reader {
	return &teeReadCloser{r: &teeReaderHelper{r: r, w: w}}
}

type teeReaderHelper struct {
	r io.Reader
	w io.Writer
}

func (t *teeReaderHelper) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		if nw, ew := t.w.Write(p[:n]); ew != nil {
			return nw, ew
		}
	}
	return n, err
}
