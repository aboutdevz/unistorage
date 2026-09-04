package snapshot

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

// PruneResult records statistics from a retention pruning run.
type PruneResult struct {
	TotalSnapshots  int      `json:"total_snapshots"`
	ValidSnapshots  int      `json:"valid_snapshots"`
	PrunedSnapshots int      `json:"pruned_snapshots"`
	PruneErrors     int      `json:"prune_errors"`
	PrunedDirs      []string `json:"pruned_dirs"`
	Errors          []error  `json:"-"`
}

type snapshotEntry struct {
	dirPath   string
	timestamp time.Time
	manifest  *Manifest
}

// Pruner purges expired snapshots beyond the retention limit.
type Pruner struct {
	driver storage.Driver
}

// NewPruner constructs a retention pruner for a given destination driver.
func NewPruner(d storage.Driver) *Pruner {
	return &Pruner{driver: d}
}

// Prune inspects snapshots under destPath/snapshots, keeps the newest retentionLimit valid snapshots,
// and removes older ones. Tolerates individual deletion failures without aborting the batch.
func (p *Pruner) Prune(ctx context.Context, destPath string, retentionLimit int) (*PruneResult, error) {
	result := &PruneResult{
		PrunedDirs: make([]string, 0),
		Errors:     make([]error, 0),
	}

	if retentionLimit <= 0 {
		// Retention limit <= 0 means keep all snapshots
		return result, nil
	}

	cleanDest := strings.Trim(destPath, "/")
	var snapshotsPrefix string
	if cleanDest == "" {
		snapshotsPrefix = "snapshots"
	} else {
		snapshotsPrefix = path.Join(cleanDest, "snapshots")
	}

	items, err := p.driver.List(ctx, snapshotsPrefix)
	if err != nil {
		return result, fmt.Errorf("failed listing snapshots under %s: %w", snapshotsPrefix, err)
	}

	// Identify unique snapshot directories under snapshotsPrefix
	snapshotDirs := make(map[string]bool)
	for _, it := range items {
		cleanItemPath := strings.Trim(it.Path, "/")
		rel := strings.TrimPrefix(cleanItemPath, snapshotsPrefix)
		rel = strings.Trim(rel, "/")
		if rel == "" {
			continue
		}
		parts := strings.Split(rel, "/")
		if len(parts) > 0 && parts[0] != "" {
			snapshotDir := path.Join(snapshotsPrefix, parts[0])
			snapshotDirs[snapshotDir] = true
		}
	}

	result.TotalSnapshots = len(snapshotDirs)

	var validSnapshots []snapshotEntry
	for dir := range snapshotDirs {
		manifestPath := path.Join(dir, ManifestFileName)
		manifest, err := ReadManifest(ctx, p.driver, manifestPath)
		if err != nil {
			// Incomplete or corrupted snapshot, ignore from valid retention list
			continue
		}
		if manifest.Stats.Status != StatusSuccess {
			continue
		}

		ts := manifest.Timestamp
		if ts.IsZero() {
			ts = time.Unix(0, 0)
		}

		validSnapshots = append(validSnapshots, snapshotEntry{
			dirPath:   dir,
			timestamp: ts,
			manifest:  manifest,
		})
	}

	result.ValidSnapshots = len(validSnapshots)
	if len(validSnapshots) <= retentionLimit {
		return result, nil
	}

	// Sort valid snapshots descending (newest first)
	sort.Slice(validSnapshots, func(i, j int) bool {
		return validSnapshots[i].timestamp.After(validSnapshots[j].timestamp)
	})

	// Snapshots from index retentionLimit to end are expired
	expired := validSnapshots[retentionLimit:]

	for _, snap := range expired {
		if err := p.deleteSnapshotDir(ctx, snap.dirPath); err != nil {
			result.PruneErrors++
			result.Errors = append(result.Errors, fmt.Errorf("failed deleting snapshot %s: %w", snap.dirPath, err))
			// Continue pruning next expired snapshot (fault tolerant)
			continue
		}
		result.PrunedSnapshots++
		result.PrunedDirs = append(result.PrunedDirs, snap.dirPath)
	}

	return result, nil
}

func (p *Pruner) deleteSnapshotDir(ctx context.Context, snapshotDir string) error {
	// List all files in snapshotDir
	objects, err := p.driver.List(ctx, snapshotDir)
	if err != nil {
		return err
	}

	var lastErr error
	for _, obj := range objects {
		if obj.IsDir {
			continue
		}
		if err := p.driver.Delete(ctx, obj.Path); err != nil {
			lastErr = err
		}
	}

	// Ensure manifest and lock files are explicitly deleted
	_ = p.driver.Delete(ctx, path.Join(snapshotDir, ManifestFileName))
	_ = p.driver.Delete(ctx, path.Join(snapshotDir, ManifestTempFileName))
	// Delete directory root if driver supports it
	_ = p.driver.Delete(ctx, snapshotDir)

	return lastErr
}
