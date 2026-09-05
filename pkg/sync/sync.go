package sync

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

var (
	// ErrRecursiveSync is returned when the destination directory resides inside the source directory.
	ErrRecursiveSync = errors.New("sync: recursive loop detected: destination directory is inside source directory")
)

// SyncOptions configures synchronization behavior.
type SyncOptions struct {
	Checksum         bool     `json:"checksum"`
	Delete           bool     `json:"delete"`
	DryRun           bool     `json:"dry_run"`
	ConflictDir      string   `json:"conflict_dir"`
	NoConflictBackup bool     `json:"no_conflict_backup"`
	ExcludePatterns  []string `json:"exclude_patterns"`
	IncludePatterns  []string `json:"include_patterns"`
	Workers          int      `json:"workers"`
}

// SyncStats records metrics and results of a synchronization execution.
type SyncStats struct {
	Source           string        `json:"source"`
	Destination      string        `json:"destination"`
	TransferredFiles int64         `json:"transferred_files"`
	TransferredBytes int64         `json:"transferred_bytes"`
	UpdatedFiles     int64         `json:"updated_files"`
	UpdatedBytes     int64         `json:"updated_bytes"`
	ConflictFiles    int64         `json:"conflict_files"`
	DeletedFiles     int64         `json:"deleted_files"`
	SkippedFiles     int64         `json:"skipped_files"`
	Duration         time.Duration `json:"duration"`
	Conflicts        []string      `json:"conflicts,omitempty"`
}

// SummaryString returns the formatted summary report.
func (s *SyncStats) SummaryString() string {
	return fmt.Sprintf(
		"Sync Summary:\n"+
			"  Source:       %s\n"+
			"  Destination:  %s\n"+
			"  Transferred:  %d files (%s)\n"+
			"  Updated:      %d files (%s)\n"+
			"  Conflicts:    %d files moved to %s\n"+
			"  Deleted:      %d files\n"+
			"  Skipped:      %d files (identical)\n"+
			"  Duration:     %s\n",
		s.Source,
		s.Destination,
		s.TransferredFiles, FormatBytes(s.TransferredBytes),
		s.UpdatedFiles, FormatBytes(s.UpdatedBytes),
		s.ConflictFiles, DefaultConflictDir,
		s.DeletedFiles,
		s.SkippedFiles,
		s.Duration.Round(time.Millisecond),
	)
}

// FormatBytes formats byte counts into human-readable strings.
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Sync performs unidirectional synchronization from srcDriver to destDriver.
func Sync(ctx context.Context, srcDriver storage.Driver, srcPrefix string, destDriver storage.Driver, destPrefix string, opts SyncOptions) (*SyncStats, error) {
	startTime := time.Now()

	cleanSrcPrefix := strings.Trim(strings.ReplaceAll(srcPrefix, "\\", "/"), "/")
	cleanDestPrefix := strings.Trim(strings.ReplaceAll(destPrefix, "\\", "/"), "/")

	// 1. Guard against recursive sync loop when both drivers are local or same driver
	if srcLocal, ok := srcDriver.(*local.Driver); ok {
		if destLocal, ok := destDriver.(*local.Driver); ok {
			effSrc := filepath.Clean(filepath.Join(srcLocal.RootDir(), filepath.FromSlash(cleanSrcPrefix)))
			effDest := filepath.Clean(filepath.Join(destLocal.RootDir(), filepath.FromSlash(cleanDestPrefix)))
			rel, err := filepath.Rel(effSrc, effDest)
			if err == nil && !strings.HasPrefix(rel, "..") {
				return nil, ErrRecursiveSync
			}
		}
	} else if srcDriver == destDriver {
		if cleanDestPrefix == cleanSrcPrefix || (cleanDestPrefix != "" && (cleanSrcPrefix == "" || strings.HasPrefix(cleanDestPrefix, cleanSrcPrefix+"/"))) {
			return nil, ErrRecursiveSync
		}
	}

	if opts.Workers <= 0 {
		opts.Workers = 4
	}

	mode := CompareModeSizeModTime
	if opts.Checksum {
		mode = CompareModeChecksum
	}
	comparator := NewComparator(mode)

	// 2. Walk source driver
	srcObjects, err := srcDriver.List(ctx, srcPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list source objects: %w", err)
	}

	// 3. Walk destination driver
	destObjects, err := destDriver.List(ctx, destPrefix)
	if err != nil {
		// Non-fatal if destination prefix is empty or not yet created
		destObjects = nil
	}

	// Map destination objects by relative normalized path
	cleanConflictDir := strings.Trim(strings.ReplaceAll(opts.ConflictDir, "\\", "/"), "/")
	if cleanConflictDir == "" {
		cleanConflictDir = DefaultConflictDir
	}

	destMap := make(map[string]storage.ObjectInfo)
	for _, obj := range destObjects {
		if obj.IsDir {
			continue
		}
		rel := obj.Path
		if cleanDestPrefix != "" && strings.HasPrefix(rel, cleanDestPrefix) {
			rel = strings.TrimPrefix(rel, cleanDestPrefix)
			rel = strings.TrimPrefix(rel, "/")
		}
		// Ignore conflict directory files on destination
		if strings.HasPrefix(rel, DefaultConflictDir) || strings.HasPrefix(rel, cleanConflictDir) {
			continue
		}
		destMap[rel] = obj
	}

	stats := &SyncStats{
		Source:      srcDriver.Name() + ":" + srcPrefix,
		Destination: destDriver.Name() + ":" + destPrefix,
	}

	var mu sync.Mutex

	// Source map to track for --delete
	srcMap := make(map[string]bool)

	type syncTask struct {
		srcObj   storage.ObjectInfo
		relPath  string
		destPath string
	}

	tasks := make([]syncTask, 0, len(srcObjects))
	for _, obj := range srcObjects {
		if obj.IsDir {
			continue
		}
		rel := obj.Path
		if cleanSrcPrefix != "" && strings.HasPrefix(rel, cleanSrcPrefix) {
			rel = strings.TrimPrefix(rel, cleanSrcPrefix)
			rel = strings.TrimPrefix(rel, "/")
		}
		// Skip files inside conflict directory
		if strings.HasPrefix(rel, DefaultConflictDir) || strings.HasPrefix(rel, cleanConflictDir) {
			continue
		}

		srcMap[rel] = true

		destPath := rel
		if cleanDestPrefix != "" {
			destPath = cleanDestPrefix + "/" + rel
		}

		tasks = append(tasks, syncTask{
			srcObj:   obj,
			relPath:  rel,
			destPath: destPath,
		})
	}

	// 4. Process transfer tasks
	taskChan := make(chan syncTask, len(tasks))
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)

	var wg sync.WaitGroup
	var taskErr error
	var errOnce sync.Once

	workerCount := opts.Workers
	if workerCount > len(tasks) {
		workerCount = len(tasks)
	}
	if workerCount <= 0 {
		workerCount = 1
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				if ctx.Err() != nil {
					return
				}

				destObj, exists := destMap[task.relPath]
				var destPtr *storage.ObjectInfo
				if exists {
					destPtr = &destObj
				}

				diffStatus, cmpErr := comparator.Compare(ctx, srcDriver, &task.srcObj, destDriver, destPtr)
				if cmpErr != nil {
					errOnce.Do(func() { taskErr = cmpErr })
					return
				}

				if diffStatus == DiffStatusIdentical {
					atomic.AddInt64(&stats.SkippedFiles, 1)
					continue
				}

				// If destination exists and differs, perform conflict safety backup
				if exists && (diffStatus == DiffStatusConflict || diffStatus == DiffStatusModified) {
					if !opts.NoConflictBackup {
						if !opts.DryRun {
							backupPath, bErr := BackupConflict(ctx, destDriver, task.destPath, opts.ConflictDir)
							if bErr != nil {
								errOnce.Do(func() { taskErr = bErr })
								return
							}
							mu.Lock()
							stats.Conflicts = append(stats.Conflicts, backupPath)
							mu.Unlock()
						}
						atomic.AddInt64(&stats.ConflictFiles, 1)
					}
				}

				// Transfer file if not in dry-run mode
				if !opts.DryRun {
					rc, rErr := srcDriver.Read(ctx, task.srcObj.Path)
					if rErr != nil {
						errOnce.Do(func() { taskErr = fmt.Errorf("failed to read source object %q: %w", task.srcObj.Path, rErr) })
						return
					}

					wErr := destDriver.Write(ctx, task.destPath, rc, task.srcObj.Size)
					_ = rc.Close()
					if wErr != nil {
						errOnce.Do(func() { taskErr = fmt.Errorf("failed to write destination object %q: %w", task.destPath, wErr) })
						return
					}
				}

				if exists {
					atomic.AddInt64(&stats.UpdatedFiles, 1)
					atomic.AddInt64(&stats.UpdatedBytes, task.srcObj.Size)
				} else {
					atomic.AddInt64(&stats.TransferredFiles, 1)
					atomic.AddInt64(&stats.TransferredBytes, task.srcObj.Size)
				}
			}
		}()
	}

	wg.Wait()

	if taskErr != nil {
		return nil, taskErr
	}

	// 5. Handle --delete flag: remove extraneous destination files
	if opts.Delete {
		for rel, destObj := range destMap {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if !srcMap[rel] {
				if !opts.DryRun {
					if err := destDriver.Delete(ctx, destObj.Path); err != nil {
						return nil, fmt.Errorf("failed to delete extraneous file %q: %w", destObj.Path, err)
					}
				}
				atomic.AddInt64(&stats.DeletedFiles, 1)
			}
		}
	}

	stats.Duration = time.Since(startTime)
	return stats, nil
}
