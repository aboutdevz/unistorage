package snapshot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/license"
	"github.com/aboutdevz/unistorage/pkg/enterprise/snapshot"
	"github.com/aboutdevz/unistorage/pkg/enterprise/telemetry"
	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

// TestAdversarial_AntiDoubleRun_ConcurrentRace simulates heavy concurrency on JobMutexRegistry
// and Engine.ExecuteBackup, verifying TryLock mutual exclusion and overlap counters.
func TestAdversarial_AntiDoubleRun_ConcurrentRace(t *testing.T) {
	// Part 1: Mutex Registry concurrent stress
	t.Run("JobMutexRegistry_100_Concurrent_Goroutines", func(t *testing.T) {
		registry := snapshot.NewJobMutexRegistry()
		jobID := "heavy-concurrent-job"

		const totalGoroutines = 100
		var startBarrier sync.WaitGroup
		startBarrier.Add(1)

		var doneWg sync.WaitGroup
		var successCount int64
		var rejectedCount int64

		for i := 0; i < totalGoroutines; i++ {
			doneWg.Add(1)
			go func() {
				defer doneWg.Done()
				startBarrier.Wait() // maximize collision probability

				if registry.TryLock(jobID) {
					atomic.AddInt64(&successCount, 1)
					// Simulate critical section work
					time.Sleep(10 * time.Millisecond)
				} else {
					atomic.AddInt64(&rejectedCount, 1)
				}
			}()
		}

		startBarrier.Done() // release all goroutines simultaneously
		doneWg.Wait()

		if successCount != 1 {
			t.Fatalf("expected exactly 1 successful lock acquisition, got %d", successCount)
		}
		if rejectedCount != totalGoroutines-1 {
			t.Fatalf("expected %d rejected acquisitions, got %d", totalGoroutines-1, rejectedCount)
		}

		// Unlock and verify subsequent acquisition succeeds
		registry.Unlock(jobID)
		if !registry.TryLock(jobID) {
			t.Fatalf("expected successful acquisition after Unlock")
		}
		registry.Unlock(jobID)
	})

	t.Run("JobMutexRegistry_Distinct_Jobs_Independent", func(t *testing.T) {
		registry := snapshot.NewJobMutexRegistry()
		jobIDs := []string{"job-alpha", "job-beta", "job-gamma", "job-delta"}

		var wg sync.WaitGroup
		errCh := make(chan error, len(jobIDs))

		for _, jID := range jobIDs {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				if !registry.TryLock(id) {
					errCh <- fmt.Errorf("failed acquiring lock for independent job %s", id)
					return
				}
				time.Sleep(5 * time.Millisecond)
				registry.Unlock(id)
			}(jID)
		}

		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatalf("independent mutex error: %v", err)
		}
	})

	t.Run("Engine_ExecuteBackup_Concurrent_Overlap_And_Metrics", func(t *testing.T) {
		srcDir, err := os.MkdirTemp("", "adv-race-src-*")
		if err != nil {
			t.Fatalf("MkdirTemp failed: %v", err)
		}
		defer os.RemoveAll(srcDir)

		destDir, err := os.MkdirTemp("", "adv-race-dest-*")
		if err != nil {
			t.Fatalf("MkdirTemp failed: %v", err)
		}
		defer os.RemoveAll(destDir)

		_ = os.WriteFile(filepath.Join(srcDir, "payload.bin"), []byte("concurrent payload"), 0644)

		srcDriver, _ := local.New(srcDir)
		destDriver, _ := local.New(destDir)

		// Create Enterprise Checker
		pub, priv, _ := license.GenerateKeyPair()
		lk := &license.LicenseKey{
			CustomerID: "cust-race",
			ExpiresAt:  time.Now().Add(24 * time.Hour),
			Features:   []license.Feature{license.FeatureSnapshotBackup, license.FeatureRetentionPrune},
			Tier:       license.TierEnterprise,
		}
		token, _ := license.SignLicense(priv, lk)
		checker, _ := license.NewEnterpriseChecker(pub, token)

		engine := snapshot.NewEngine(nil, checker)

		job := snapshot.JobConfig{
			JobID:          "race-job-1",
			Schedule:       "@daily",
			SourcePath:     "",
			DestPath:       "snapshots-vault",
			TimeoutMinutes: 5,
			Enabled:        true,
		}

		metricsReg := telemetry.NewMetricsRegistry()

		const concurrentRuns = 15
		var startBarrier sync.WaitGroup
		startBarrier.Add(1)

		var wg sync.WaitGroup
		var successfulRuns int64
		var skippedDueToLockRuns int64

		for i := 0; i < concurrentRuns; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				startBarrier.Wait()

				res, runErr := engine.ExecuteBackup(context.Background(), job, srcDriver, destDriver)
				if runErr != nil {
					if errors.Is(runErr, snapshot.ErrJobAlreadyRunning) {
						atomic.AddInt64(&skippedDueToLockRuns, 1)
						metricsReg.IncBackupSkippedOverlap(job.JobID)
						if res == nil || !res.SkippedDueToLock {
							t.Errorf("expected res.SkippedDueToLock to be true on lock rejection")
						}
						return
					}
					t.Errorf("unexpected execution error: %v", runErr)
					return
				}

				if res != nil && res.Manifest != nil {
					atomic.AddInt64(&successfulRuns, 1)
				}
			}()
		}

		startBarrier.Done()
		wg.Wait()

		if successfulRuns != 1 {
			t.Fatalf("expected exactly 1 successful execution, got %d", successfulRuns)
		}
		if skippedDueToLockRuns != concurrentRuns-1 {
			t.Fatalf("expected %d runs skipped due to lock, got %d", concurrentRuns-1, skippedDueToLockRuns)
		}

		// Verify overlap counter in telemetry metrics
		rendered := metricsReg.Format()
		expectedMetric := fmt.Sprintf("unistorage_backup_skipped_overlap_total{job=\"race-job-1\"} %d", skippedDueToLockRuns)
		if !bytes.Contains([]byte(rendered), []byte(expectedMetric)) {
			t.Fatalf("expected metrics to contain '%s', got:\n%s", expectedMetric, rendered)
		}
	})
}

// TestAdversarial_StorageLock_StaleReclamation verifies storage-level .job.lock semantics:
// active lock blocking, expired lock reclamation, corrupt lock recovery, and zero/negative timeouts.
func TestAdversarial_StorageLock_StaleReclamation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv-lock-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	d, _ := local.New(tempDir)
	ctx := context.Background()

	t.Run("Active_Lock_Blocks_Acquisition", func(t *testing.T) {
		destDir := "active-target"
		lockPath := path.Join(destDir, snapshot.LockFileName)

		// Simulate lock held 5 minutes ago with 30m timeout
		info := snapshot.LockInfo{
			PID:      1234,
			Hostname: "worker-node-1",
			LockedAt: time.Now().UTC().Add(-5 * time.Minute),
		}
		data, _ := json.Marshal(info)
		_ = d.Write(ctx, lockPath, bytes.NewReader(data), int64(len(data)))

		_, err := snapshot.AcquireStorageLock(ctx, d, destDir, 30)
		if err == nil {
			t.Fatalf("expected active lock to block acquisition, got nil")
		}
		if !errors.Is(err, snapshot.ErrJobAlreadyRunning) {
			t.Fatalf("expected ErrJobAlreadyRunning, got %v", err)
		}
	})

	t.Run("Expired_Lock_Is_Reclaimed", func(t *testing.T) {
		destDir := "expired-target"
		lockPath := path.Join(destDir, snapshot.LockFileName)

		// Simulate lock held 45 minutes ago with 30m timeout
		info := snapshot.LockInfo{
			PID:      5678,
			Hostname: "crashed-worker-node",
			LockedAt: time.Now().UTC().Add(-45 * time.Minute),
		}
		data, _ := json.Marshal(info)
		_ = d.Write(ctx, lockPath, bytes.NewReader(data), int64(len(data)))

		lock, err := snapshot.AcquireStorageLock(ctx, d, destDir, 30)
		if err != nil {
			t.Fatalf("expected expired lock to be reclaimed, got error: %v", err)
		}
		defer lock.Release(ctx)

		// Verify lock file now reflects current process
		rc, err := d.Read(ctx, lockPath)
		if err != nil {
			t.Fatalf("failed reading reclaimed lock file: %v", err)
		}
		defer rc.Close()
		var newInfo snapshot.LockInfo
		_ = json.NewDecoder(rc).Decode(&newInfo)

		if newInfo.PID != os.Getpid() {
			t.Fatalf("expected PID %d, got %d", os.Getpid(), newInfo.PID)
		}
	})

	t.Run("Corrupted_Lock_File_Reclaimed_Cleanly", func(t *testing.T) {
		destDir := "corrupt-target"
		lockPath := path.Join(destDir, snapshot.LockFileName)

		// Zero bytes or corrupted JSON
		corruptBytes := []byte("{corrupt-json-truncated-")
		_ = d.Write(ctx, lockPath, bytes.NewReader(corruptBytes), int64(len(corruptBytes)))

		lock, err := snapshot.AcquireStorageLock(ctx, d, destDir, 10)
		if err != nil {
			t.Fatalf("expected corrupt lock file to be overwritten, got error: %v", err)
		}
		defer lock.Release(ctx)
	})

	t.Run("Default_Timeout_When_Zero_Or_Negative", func(t *testing.T) {
		destDir := "default-timeout-target"
		lockPath := path.Join(destDir, snapshot.LockFileName)

		// Default timeout is 60m.
		// 1) 30 min old lock should be active
		activeInfo := snapshot.LockInfo{
			PID:      9999,
			Hostname: "active-node",
			LockedAt: time.Now().UTC().Add(-30 * time.Minute),
		}
		data, _ := json.Marshal(activeInfo)
		_ = d.Write(ctx, lockPath, bytes.NewReader(data), int64(len(data)))

		_, err := snapshot.AcquireStorageLock(ctx, d, destDir, 0)
		if err == nil {
			t.Fatalf("expected 30m lock to be active with default 60m timeout")
		}

		// 2) 75 min old lock should be expired and reclaimed
		expiredInfo := snapshot.LockInfo{
			PID:      9999,
			Hostname: "dead-node",
			LockedAt: time.Now().UTC().Add(-75 * time.Minute),
		}
		data, _ = json.Marshal(expiredInfo)
		_ = d.Write(ctx, lockPath, bytes.NewReader(data), int64(len(data)))

		lock, err := snapshot.AcquireStorageLock(ctx, d, destDir, -5)
		if err != nil {
			t.Fatalf("expected 75m lock to be reclaimed with negative timeout, got: %v", err)
		}
		defer lock.Release(ctx)
	})

	t.Run("Release_Idempotency", func(t *testing.T) {
		destDir := "release-target"
		lock, err := snapshot.AcquireStorageLock(ctx, d, destDir, 10)
		if err != nil {
			t.Fatalf("AcquireStorageLock failed: %v", err)
		}

		// First release
		if err := lock.Release(ctx); err != nil {
			t.Fatalf("first Release failed: %v", err)
		}

		// Second release should be idempotent and return nil
		if err := lock.Release(ctx); err != nil {
			t.Fatalf("second Release failed: %v", err)
		}

		// Nil receiver should not panic
		var nilLock *snapshot.StorageLock
		if err := nilLock.Release(ctx); err != nil {
			t.Fatalf("nil lock Release returned error: %v", err)
		}
	})
}

// TestAdversarial_RetentionPruner_EdgeCases tests pruning boundary conditions (N=0, N=1, exact N, N+5),
// corrupt manifests, non-snapshot directories, and non-snapshot file safety.
func TestAdversarial_RetentionPruner_EdgeCases(t *testing.T) {
	createSnapshot := func(t *testing.T, d storage.Driver, rootDir, snapID string, ts time.Time, status string, payload []byte) {
		snapDir := path.Join(rootDir, "snapshots", snapID)
		if payload != nil {
			fPath := path.Join(snapDir, "data.bin")
			_ = d.Write(context.Background(), fPath, bytes.NewReader(payload), int64(len(payload)))
		}
		m := &snapshot.Manifest{
			ManifestVersion: snapshot.ManifestVersionCurrent,
			SnapshotID:      snapID,
			Timestamp:       ts,
			Stats: snapshot.SnapshotStats{
				TotalFiles: 1,
				TotalBytes: int64(len(payload)),
				Status:     status,
			},
			Files: []snapshot.SnapshotFile{
				{Path: "data.bin", Size: int64(len(payload))},
			},
		}
		if err := snapshot.WriteManifest(context.Background(), d, snapDir, m); err != nil {
			t.Fatalf("WriteManifest failed: %v", err)
		}
	}

	t.Run("Boundary_N_Zero_Keeps_All", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv-prune-n0-*")
		defer os.RemoveAll(tempDir)
		d, _ := local.New(tempDir)

		base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 5; i++ {
			createSnapshot(t, d, "vault", fmt.Sprintf("snap-%02d", i), base.Add(time.Duration(i)*time.Hour), snapshot.StatusSuccess, []byte("ok"))
		}

		pruner := snapshot.NewPruner(d)
		res, err := pruner.Prune(context.Background(), "vault", 0)
		if err != nil {
			t.Fatalf("Prune failed: %v", err)
		}
		if res.PrunedSnapshots != 0 {
			t.Fatalf("expected 0 pruned for N=0, got %d", res.PrunedSnapshots)
		}
	})

	t.Run("Boundary_N_One_Keeps_Only_Newest", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv-prune-n1-*")
		defer os.RemoveAll(tempDir)
		d, _ := local.New(tempDir)

		base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 5; i++ {
			createSnapshot(t, d, "vault", fmt.Sprintf("snap-%02d", i), base.Add(time.Duration(i)*time.Hour), snapshot.StatusSuccess, []byte("ok"))
		}

		pruner := snapshot.NewPruner(d)
		res, err := pruner.Prune(context.Background(), "vault", 1)
		if err != nil {
			t.Fatalf("Prune failed: %v", err)
		}
		if res.PrunedSnapshots != 4 {
			t.Fatalf("expected 4 pruned for N=1, got %d", res.PrunedSnapshots)
		}

		// Only snap-05 should exist
		for i := 1; i <= 4; i++ {
			p := path.Join("vault", "snapshots", fmt.Sprintf("snap-%02d", i), snapshot.ManifestFileName)
			if _, err := d.Stat(context.Background(), p); err == nil {
				t.Fatalf("expected %s to be deleted", p)
			}
		}
		p5 := path.Join("vault", "snapshots", "snap-05", snapshot.ManifestFileName)
		if _, err := d.Stat(context.Background(), p5); err != nil {
			t.Fatalf("expected newest snapshot snap-05 to exist: %v", err)
		}
	})

	t.Run("Boundary_Exact_N_Prunes_Zero", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv-prune-exact-*")
		defer os.RemoveAll(tempDir)
		d, _ := local.New(tempDir)

		base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 5; i++ {
			createSnapshot(t, d, "vault", fmt.Sprintf("snap-%02d", i), base.Add(time.Duration(i)*time.Hour), snapshot.StatusSuccess, []byte("ok"))
		}

		pruner := snapshot.NewPruner(d)
		res, err := pruner.Prune(context.Background(), "vault", 5)
		if err != nil {
			t.Fatalf("Prune failed: %v", err)
		}
		if res.PrunedSnapshots != 0 {
			t.Fatalf("expected 0 pruned for exact N=5, got %d", res.PrunedSnapshots)
		}
	})

	t.Run("Boundary_N_Plus_5_Prunes_Exactly_5", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv-prune-nplus5-*")
		defer os.RemoveAll(tempDir)
		d, _ := local.New(tempDir)

		base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 10; i++ {
			createSnapshot(t, d, "vault", fmt.Sprintf("snap-%02d", i), base.Add(time.Duration(i)*time.Hour), snapshot.StatusSuccess, []byte("ok"))
		}

		pruner := snapshot.NewPruner(d)
		res, err := pruner.Prune(context.Background(), "vault", 5)
		if err != nil {
			t.Fatalf("Prune failed: %v", err)
		}
		if res.PrunedSnapshots != 5 {
			t.Fatalf("expected 5 pruned for 10 snapshots with N=5, got %d", res.PrunedSnapshots)
		}

		// Verify snap-01..05 pruned, snap-06..10 remain
		for i := 1; i <= 5; i++ {
			p := path.Join("vault", "snapshots", fmt.Sprintf("snap-%02d", i), snapshot.ManifestFileName)
			if _, err := d.Stat(context.Background(), p); err == nil {
				t.Fatalf("expected %s to be deleted", p)
			}
		}
		for i := 6; i <= 10; i++ {
			p := path.Join("vault", "snapshots", fmt.Sprintf("snap-%02d", i), snapshot.ManifestFileName)
			if _, err := d.Stat(context.Background(), p); err != nil {
				t.Fatalf("expected %s to remain: %v", p, err)
			}
		}
	})

	t.Run("Non_Snapshot_Files_And_Dirs_Are_Never_Touched", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv-prune-safety-*")
		defer os.RemoveAll(tempDir)
		d, _ := local.New(tempDir)
		ctx := context.Background()

		// 1. Root level files and directories
		_ = d.Write(ctx, "vault/.job.lock", bytes.NewReader([]byte("active")), 6)
		_ = d.Write(ctx, "vault/archive.tar.gz", bytes.NewReader([]byte("tar-archive")), 11)
		_ = d.Write(ctx, "vault/config/settings.json", bytes.NewReader([]byte("{}")), 2)

		// 2. Non-snapshot files directly under snapshots/
		_ = d.Write(ctx, "vault/snapshots/readme.txt", bytes.NewReader([]byte("readme")), 6)
		_ = d.Write(ctx, "vault/snapshots/external_tool/tool.bin", bytes.NewReader([]byte("bin")), 3)

		// 3. Create 5 valid snapshots
		base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		for i := 1; i <= 5; i++ {
			createSnapshot(t, d, "vault", fmt.Sprintf("snap-%02d", i), base.Add(time.Duration(i)*time.Hour), snapshot.StatusSuccess, []byte("ok"))
		}

		// Prune with N=2
		pruner := snapshot.NewPruner(d)
		res, err := pruner.Prune(ctx, "vault", 2)
		if err != nil {
			t.Fatalf("Prune failed: %v", err)
		}
		if res.PrunedSnapshots != 3 {
			t.Fatalf("expected 3 pruned, got %d", res.PrunedSnapshots)
		}

		// Verify non-snapshot files still exist untouched
		safetyFiles := []string{
			"vault/.job.lock",
			"vault/archive.tar.gz",
			"vault/config/settings.json",
			"vault/snapshots/readme.txt",
			"vault/snapshots/external_tool/tool.bin",
		}
		for _, f := range safetyFiles {
			if _, err := d.Stat(ctx, f); err != nil {
				t.Fatalf("CRITICAL: non-snapshot file %s was deleted or damaged: %v", f, err)
			}
		}
	})

	t.Run("Corrupted_And_Incomplete_Manifests_Tolerated", func(t *testing.T) {
		tempDir, _ := os.MkdirTemp("", "adv-prune-corrupt-*")
		defer os.RemoveAll(tempDir)
		d, _ := local.New(tempDir)
		ctx := context.Background()

		// 1. Snapshot with corrupted manifest JSON
		_ = d.Write(ctx, "vault/snapshots/snap-corrupt/manifest.json", bytes.NewReader([]byte("{invalid-json")), 13)

		// 2. Snapshot with FAILED status
		createSnapshot(t, d, "vault", "snap-failed", time.Now().UTC().Add(-10*time.Hour), snapshot.StatusFailed, []byte("fail"))

		// 3. Snapshot with missing manifest file
		_ = d.Write(ctx, "vault/snapshots/snap-no-manifest/data.bin", bytes.NewReader([]byte("data")), 4)

		// 4. Two valid snapshots
		base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		createSnapshot(t, d, "vault", "snap-valid-1", base.Add(1*time.Hour), snapshot.StatusSuccess, []byte("v1"))
		createSnapshot(t, d, "vault", "snap-valid-2", base.Add(2*time.Hour), snapshot.StatusSuccess, []byte("v2"))

		// Prune with N=1
		pruner := snapshot.NewPruner(d)
		res, err := pruner.Prune(ctx, "vault", 1)
		if err != nil {
			t.Fatalf("Prune failed with error: %v", err)
		}

		if res.ValidSnapshots != 2 {
			t.Fatalf("expected exactly 2 valid snapshots detected, got %d", res.ValidSnapshots)
		}
		if res.PrunedSnapshots != 1 {
			t.Fatalf("expected 1 valid snapshot pruned, got %d", res.PrunedSnapshots)
		}

		// snap-valid-1 should be pruned (oldest valid)
		if _, err := d.Stat(ctx, "vault/snapshots/snap-valid-1/manifest.json"); err == nil {
			t.Fatalf("expected snap-valid-1 to be pruned")
		}
		// snap-valid-2 should remain (newest valid)
		if _, err := d.Stat(ctx, "vault/snapshots/snap-valid-2/manifest.json"); err != nil {
			t.Fatalf("expected snap-valid-2 to remain: %v", err)
		}
	})
}

// TestAdversarial_CronSchedule_ParsingAndMatching performs exhaustive tests on cron boundary strings,
// range/step parsing, macro expansion, and invalid syntax rejection.
func TestAdversarial_CronSchedule_ParsingAndMatching(t *testing.T) {
	t.Run("Boundary_Values_And_Step_Ranges", func(t *testing.T) {
		tests := []struct {
			expr      string
			matchTime time.Time
			noMatch   time.Time
		}{
			{
				expr:      "0 * * * *", // minute 0
				matchTime: time.Date(2026, 9, 4, 15, 0, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 4, 15, 1, 0, 0, time.UTC),
			},
			{
				expr:      "59 * * * *", // minute 59
				matchTime: time.Date(2026, 9, 4, 15, 59, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 4, 15, 58, 0, 0, time.UTC),
			},
			{
				expr:      "* 0 * * *", // hour 0
				matchTime: time.Date(2026, 9, 4, 0, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 4, 1, 10, 0, 0, time.UTC),
			},
			{
				expr:      "* 23 * * *", // hour 23
				matchTime: time.Date(2026, 9, 4, 23, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 4, 22, 10, 0, 0, time.UTC),
			},
			{
				expr:      "* * 1 * *", // DOM 1
				matchTime: time.Date(2026, 9, 1, 10, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 2, 10, 10, 0, 0, time.UTC),
			},
			{
				expr:      "* * 31 * *", // DOM 31
				matchTime: time.Date(2026, 8, 31, 10, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 8, 30, 10, 10, 0, 0, time.UTC),
			},
			{
				expr:      "* * * 1 *", // Month 1 (Jan)
				matchTime: time.Date(2026, 1, 15, 10, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 2, 15, 10, 10, 0, 0, time.UTC),
			},
			{
				expr:      "* * * 12 *", // Month 12 (Dec)
				matchTime: time.Date(2026, 12, 15, 10, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 11, 15, 10, 10, 0, 0, time.UTC),
			},
			{
				expr:      "* * * * 0", // DOW 0 (Sunday)
				matchTime: time.Date(2026, 9, 6, 10, 10, 0, 0, time.UTC), // 2026-09-06 is Sunday
				noMatch:   time.Date(2026, 9, 7, 10, 10, 0, 0, time.UTC), // Monday
			},
			{
				expr:      "* * * * 7", // DOW 7 (also Sunday)
				matchTime: time.Date(2026, 9, 6, 10, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 7, 10, 10, 0, 0, time.UTC),
			},
			{
				expr:      "10-30/5 * * * *", // Steps within range: 10, 15, 20, 25, 30
				matchTime: time.Date(2026, 9, 4, 12, 25, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 4, 12, 26, 0, 0, time.UTC),
			},
			{
				expr:      "*/15 * * * *", // Step: 0, 15, 30, 45
				matchTime: time.Date(2026, 9, 4, 12, 45, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 4, 12, 46, 0, 0, time.UTC),
			},
			{
				expr:      "5,10,15 * * * *", // List
				matchTime: time.Date(2026, 9, 4, 12, 10, 0, 0, time.UTC),
				noMatch:   time.Date(2026, 9, 4, 12, 12, 0, 0, time.UTC),
			},
		}

		for _, tc := range tests {
			cs, err := snapshot.ParseCron(tc.expr)
			if err != nil {
				t.Fatalf("ParseCron(%s) failed: %v", tc.expr, err)
			}
			if !cs.Matches(tc.matchTime) {
				t.Errorf("expr %s: expected match at %v", tc.expr, tc.matchTime)
			}
			if cs.Matches(tc.noMatch) {
				t.Errorf("expr %s: expected NO match at %v", tc.expr, tc.noMatch)
			}
		}
	})

	t.Run("Macro_Expansions", func(t *testing.T) {
		macros := []struct {
			macro string
			testT time.Time
			match bool
		}{
			{"@hourly", time.Date(2026, 9, 4, 14, 0, 0, 0, time.UTC), true},
			{"@hourly", time.Date(2026, 9, 4, 14, 1, 0, 0, time.UTC), false},
			{"@daily", time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC), true},
			{"@daily", time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC), false},
			{"@weekly", time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC), true}, // Sunday midnight
			{"@weekly", time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC), false},
			{"@monthly", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), true},
			{"@monthly", time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC), false},
			{"@yearly", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), true},
			{"@yearly", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), false},
			{"@annually", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), true},
		}

		for _, m := range macros {
			cs, err := snapshot.ParseCron(m.macro)
			if err != nil {
				t.Fatalf("ParseCron(%s) failed: %v", m.macro, err)
			}
			if cs.Matches(m.testT) != m.match {
				t.Errorf("macro %s at %v: expected match=%v, got %v", m.macro, m.testT, m.match, cs.Matches(m.testT))
			}
		}
	})

	t.Run("Invalid_Syntax_Rejections", func(t *testing.T) {
		invalidExprs := []string{
			"",
			"   ",
			"*",
			"* *",
			"* * *",
			"* * * *",       // 4 fields
			"* * * * * *",   // 6 fields
			"-1 * * * *",     // negative min
			"60 * * * *",     // min >= 60
			"* -1 * * *",     // negative hour
			"* 24 * * *",     // hour >= 24
			"* * 0 * *",      // dom < 1
			"* * 32 * *",     // dom > 31
			"* * * 0 *",      // month < 1
			"* * * 13 *",     // month > 12
			"* * * * -1",     // dow < 0
			"* * * * 8",      // dow > 7
			"*/0 * * * *",    // step = 0
			"*/-1 * * * *",   // negative step
			"20-10 * * * *",  // reversed range
			"1/2/3 * * * *",  // multiple slashes
			"abc * * * *",    // alpha in minute
			"* * foo * *",    // alpha in dom
			"1,,2 * * * *",   // empty comma entry
			",1 * * * *",     // leading comma
			"1, * * * *",     // trailing comma
			"*/ * * * *",     // missing step
			"/5 * * * *",     // missing range
		}

		for _, bad := range invalidExprs {
			_, err := snapshot.ParseCron(bad)
			if err == nil {
				t.Errorf("expected error for invalid cron expr '%s', got nil", bad)
			}
		}
	})

	t.Run("Next_Schedule_Calculation", func(t *testing.T) {
		cs, err := snapshot.ParseCron("30 4 * * *")
		if err != nil {
			t.Fatalf("ParseCron failed: %v", err)
		}

		// From 2026-09-04 04:00 UTC -> next is 2026-09-04 04:30 UTC
		from := time.Date(2026, 9, 4, 4, 0, 0, 0, time.UTC)
		next := cs.Next(from)
		expected := time.Date(2026, 9, 4, 4, 30, 0, 0, time.UTC)
		if !next.Equal(expected) {
			t.Fatalf("expected next %v, got %v", expected, next)
		}

		// From 2026-09-04 04:30 UTC -> next is 2026-09-05 04:30 UTC
		from2 := time.Date(2026, 9, 4, 4, 30, 0, 0, time.UTC)
		next2 := cs.Next(from2)
		expected2 := time.Date(2026, 9, 5, 4, 30, 0, 0, time.UTC)
		if !next2.Equal(expected2) {
			t.Fatalf("expected next %v, got %v", expected2, next2)
		}
	})
}

// TestAdversarial_AtomicManifestWrite verifies that manifest writes never leave half-written
// manifests, cleanly clean up temporary files, and survive simulated pre-existing garbage.
func TestAdversarial_AtomicManifestWrite(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "adv-manifest-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	d, _ := local.New(tempDir)
	ctx := context.Background()
	snapDir := "snap-atomic-test"

	manifest := &snapshot.Manifest{
		ManifestVersion: snapshot.ManifestVersionCurrent,
		SnapshotID:      "snap-atomic-1",
		JobID:           "job-atomic",
		Timestamp:       time.Now().UTC().Truncate(time.Millisecond),
		Stats: snapshot.SnapshotStats{
			TotalFiles:      3,
			TotalBytes:      4096,
			DurationSeconds: 0.85,
			Status:          snapshot.StatusSuccess,
		},
		Files: []snapshot.SnapshotFile{
			{Path: "f1.txt", Size: 1024, SHA256: "hash1", ModTime: time.Now().UTC(), Mode: "-rw-r--r--"},
			{Path: "f2.txt", Size: 2048, SHA256: "hash2", ModTime: time.Now().UTC(), Mode: "-rw-r--r--"},
			{Path: "f3.txt", Size: 1024, SHA256: "hash3", ModTime: time.Now().UTC(), Mode: "-rw-r--r--"},
		},
	}

	t.Run("Clean_Write_And_Temp_Cleanup", func(t *testing.T) {
		if err := snapshot.WriteManifest(ctx, d, snapDir, manifest); err != nil {
			t.Fatalf("WriteManifest failed: %v", err)
		}

		// 1. Verify manifest.json exists and is valid
		finalPath := path.Join(snapDir, snapshot.ManifestFileName)
		readM, err := snapshot.ReadManifest(ctx, d, finalPath)
		if err != nil {
			t.Fatalf("ReadManifest failed: %v", err)
		}
		if readM.SnapshotID != "snap-atomic-1" {
			t.Fatalf("expected SnapshotID snap-atomic-1, got %s", readM.SnapshotID)
		}
		if len(readM.Files) != 3 {
			t.Fatalf("expected 3 files in manifest, got %d", len(readM.Files))
		}

		// 2. Verify manifest.json.tmp does NOT exist
		tmpPath := path.Join(snapDir, snapshot.ManifestTempFileName)
		if _, err := d.Stat(ctx, tmpPath); err == nil {
			t.Fatalf("expected manifest.json.tmp to be cleaned up, but it still exists")
		}
	})

	t.Run("PreExisting_Temp_File_Overwritten_Cleanly", func(t *testing.T) {
		// Simulate leftover garbage temp file from a previous aborted write
		tmpPath := path.Join(snapDir, snapshot.ManifestTempFileName)
		garbage := []byte("half-written-garbage-payload")
		_ = d.Write(ctx, tmpPath, bytes.NewReader(garbage), int64(len(garbage)))

		// Update manifest ID and write again
		manifest.SnapshotID = "snap-atomic-2"
		if err := snapshot.WriteManifest(ctx, d, snapDir, manifest); err != nil {
			t.Fatalf("WriteManifest failed with pre-existing temp file: %v", err)
		}

		// Verify temp file is cleaned up
		if _, err := d.Stat(ctx, tmpPath); err == nil {
			t.Fatalf("temp file was not deleted after write")
		}

		// Verify final manifest has new ID
		finalPath := path.Join(snapDir, snapshot.ManifestFileName)
		readM, err := snapshot.ReadManifest(ctx, d, finalPath)
		if err != nil {
			t.Fatalf("ReadManifest failed: %v", err)
		}
		if readM.SnapshotID != "snap-atomic-2" {
			t.Fatalf("expected SnapshotID snap-atomic-2, got %s", readM.SnapshotID)
		}
	})

	t.Run("Simulated_Crash_Only_Temp_File_Does_Not_Poison_Read", func(t *testing.T) {
		crashDir := "snap-crash-dir"
		tmpPath := path.Join(crashDir, snapshot.ManifestTempFileName)
		data, _ := json.Marshal(manifest)
		// Only tmp file is written, process crashes before committing final manifest
		_ = d.Write(ctx, tmpPath, bytes.NewReader(data), int64(len(data)))

		// Reading manifest.json should fail because atomic commit never occurred
		finalPath := path.Join(crashDir, snapshot.ManifestFileName)
		_, err := snapshot.ReadManifest(ctx, d, finalPath)
		if err == nil {
			t.Fatalf("expected ReadManifest to fail when manifest.json does not exist")
		}
	})
}
