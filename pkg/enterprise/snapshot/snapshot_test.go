package snapshot_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/enterprise/license"
	"github.com/aboutdevz/unistorage/pkg/enterprise/snapshot"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
)

func TestCronParser(t *testing.T) {
	// Standard 5-field cron
	cron, err := snapshot.ParseCron("30 4 1,15 * 1-5")
	if err != nil {
		t.Fatalf("ParseCron failed: %v", err)
	}

	// 2026-09-01 is Tuesday (weekday 2), matches 1-5, day 1, hour 4, min 30
	matchTime := time.Date(2026, 9, 1, 4, 30, 0, 0, time.UTC)
	if !cron.Matches(matchTime) {
		t.Fatalf("expected match for %v", matchTime)
	}

	// Minute mismatch
	noMatchMin := time.Date(2026, 9, 1, 4, 31, 0, 0, time.UTC)
	if cron.Matches(noMatchMin) {
		t.Fatalf("expected no match for %v", noMatchMin)
	}

	// Macro testing
	hourly, err := snapshot.ParseCron("@hourly")
	if err != nil {
		t.Fatalf("ParseCron(@hourly) failed: %v", err)
	}
	if !hourly.Matches(time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("expected @hourly match on top of hour")
	}

	daily, err := snapshot.ParseCron("@daily")
	if err != nil {
		t.Fatalf("ParseCron(@daily) failed: %v", err)
	}
	if !daily.Matches(time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("expected @daily match at midnight")
	}

	// Invalid expressions
	for _, bad := range []string{
		"invalid",
		"* * * *",       // 4 fields
		"* * * * * *",   // 6 fields
		"60 * * * *",     // minute out of range
		"* 25 * * *",     // hour out of range
		"* * 32 * *",     // dom out of range
		"* * * 13 *",     // month out of range
		"* * * * 8",      // dow out of range
		"*/0 * * * *",    // step 0
	} {
		_, err := snapshot.ParseCron(bad)
		if err == nil {
			t.Fatalf("expected error parsing invalid cron '%s'", bad)
		}
	}
}

func TestScheduler(t *testing.T) {
	var triggeredJob string
	runner := func(ctx context.Context, job snapshot.JobConfig) error {
		triggeredJob = job.JobID
		return nil
	}

	sched := snapshot.NewScheduler(runner)
	job := snapshot.JobConfig{
		JobID:          "test-daily",
		Schedule:       "@daily",
		SourcePath:     "/src",
		DestPath:       "/dest",
		TimeoutMinutes: 10,
		Enabled:        true,
	}

	if err := sched.AddJob(job); err != nil {
		t.Fatalf("AddJob failed: %v", err)
	}

	jobs := sched.ListJobs()
	if len(jobs) != 1 || jobs[0].JobID != "test-daily" {
		t.Fatalf("unexpected jobs list: %v", jobs)
	}

	// Trigger manually
	ctx := context.Background()
	if err := sched.TriggerJob(ctx, "test-daily"); err != nil {
		t.Fatalf("TriggerJob failed: %v", err)
	}
	if triggeredJob != "test-daily" {
		t.Fatalf("expected triggered job test-daily, got %s", triggeredJob)
	}

	// Remove job
	sched.RemoveJob("test-daily")
	if _, ok := sched.GetJob("test-daily"); ok {
		t.Fatalf("expected test-daily to be removed")
	}
}

func TestManifestAtomicWriteAndRead(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-manifest-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	d, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("NewDriver failed: %v", err)
	}

	ctx := context.Background()
	snapDir := "snap-2026-09-04T00-00-00Z"

	manifest := &snapshot.Manifest{
		ManifestVersion: snapshot.ManifestVersionCurrent,
		SnapshotID:      "snap-123",
		JobID:           "job-db",
		Timestamp:       time.Now().UTC().Truncate(time.Second),
		Stats: snapshot.SnapshotStats{
			TotalFiles:      2,
			TotalBytes:      1024,
			DurationSeconds: 1.25,
			Status:          snapshot.StatusSuccess,
		},
		Files: []snapshot.SnapshotFile{
			{Path: "data1.bin", Size: 512, SHA256: "aaa", ModTime: time.Now().UTC()},
			{Path: "data2.bin", Size: 512, SHA256: "bbb", ModTime: time.Now().UTC()},
		},
	}

	if err := snapshot.WriteManifest(ctx, d, snapDir, manifest); err != nil {
		t.Fatalf("WriteManifest failed: %v", err)
	}

	// Verify temporary manifest is removed
	tmpPath := path.Join(snapDir, snapshot.ManifestTempFileName)
	if _, err := d.Stat(ctx, tmpPath); err == nil {
		t.Fatalf("temporary manifest %s was not cleaned up", tmpPath)
	}

	// Read manifest
	finalPath := path.Join(snapDir, snapshot.ManifestFileName)
	readManifest, err := snapshot.ReadManifest(ctx, d, finalPath)
	if err != nil {
		t.Fatalf("ReadManifest failed: %v", err)
	}

	if readManifest.SnapshotID != "snap-123" {
		t.Fatalf("expected snapshot_id snap-123, got %s", readManifest.SnapshotID)
	}
	if len(readManifest.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(readManifest.Files))
	}
}

func TestJobMutexRegistry(t *testing.T) {
	registry := snapshot.NewJobMutexRegistry()
	jobID := "backup-postgres"

	if !registry.TryLock(jobID) {
		t.Fatalf("first TryLock should succeed")
	}

	// Second acquisition should fail
	if registry.TryLock(jobID) {
		t.Fatalf("concurrent TryLock should fail")
	}

	registry.Unlock(jobID)

	// After unlock, acquisition should succeed again
	if !registry.TryLock(jobID) {
		t.Fatalf("TryLock after Unlock should succeed")
	}
	registry.Unlock(jobID)
}

func TestStorageLevelLockAndStaleReclamation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-lock-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	d, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("NewDriver failed: %v", err)
	}

	ctx := context.Background()

	// 1. Initial lock acquisition
	lock, err := snapshot.AcquireStorageLock(ctx, d, "backup-target", 60)
	if err != nil {
		t.Fatalf("AcquireStorageLock failed: %v", err)
	}

	// 2. Active lock prevents double acquisition
	_, err = snapshot.AcquireStorageLock(ctx, d, "backup-target", 60)
	if err == nil {
		t.Fatalf("expected error acquiring active lock, got nil")
	}

	// Release lock
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("lock.Release failed: %v", err)
	}

	// 3. Stale lock simulation: write lock file dated 2 hours ago with 60 min timeout
	staleInfo := snapshot.LockInfo{
		PID:      99999,
		Hostname: "crashed-worker",
		LockedAt: time.Now().UTC().Add(-2 * time.Hour),
	}
	staleBytes, _ := json.Marshal(staleInfo)
	lockFilePath := path.Join("backup-target", snapshot.LockFileName)
	_ = d.Write(ctx, lockFilePath, bytes.NewReader(staleBytes), int64(len(staleBytes)))

	// Stale lock should be reclaimed cleanly
	reclaimedLock, err := snapshot.AcquireStorageLock(ctx, d, "backup-target", 60)
	if err != nil {
		t.Fatalf("failed to reclaim stale lock: %v", err)
	}
	if err := reclaimedLock.Release(ctx); err != nil {
		t.Fatalf("reclaimedLock.Release failed: %v", err)
	}
}

func TestRetentionPruner(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-pruner-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	d, err := local.New(tempDir)
	if err != nil {
		t.Fatalf("NewDriver failed: %v", err)
	}

	ctx := context.Background()
	destPath := "backups"

	// Create 5 snapshots with different timestamps
	baseTime := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		ts := baseTime.Add(time.Duration(i) * 24 * time.Hour)
		snapName := fmt.Sprintf("snap-%02d", i)
		snapDir := path.Join(destPath, "snapshots", snapName)

		// Create payload file
		dataFile := path.Join(snapDir, "payload.txt")
		content := []byte(fmt.Sprintf("snapshot %d data", i))
		_ = d.Write(ctx, dataFile, bytes.NewReader(content), int64(len(content)))

		// Create manifest
		m := &snapshot.Manifest{
			ManifestVersion: snapshot.ManifestVersionCurrent,
			SnapshotID:      snapName,
			Timestamp:       ts,
			Stats: snapshot.StatsSuccess(1, int64(len(content)), 0.5),
			Files: []snapshot.SnapshotFile{
				{Path: "payload.txt", Size: int64(len(content))},
			},
		}
		_ = snapshot.WriteManifest(ctx, d, snapDir, m)
	}

	// Prune keeping retention_limit = 3
	pruner := snapshot.NewPruner(d)
	result, err := pruner.Prune(ctx, destPath, 3)
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}

	if result.TotalSnapshots != 5 {
		t.Fatalf("expected 5 total snapshots, got %d", result.TotalSnapshots)
	}
	if result.ValidSnapshots != 5 {
		t.Fatalf("expected 5 valid snapshots, got %d", result.ValidSnapshots)
	}
	if result.PrunedSnapshots != 2 {
		t.Fatalf("expected 2 pruned snapshots, got %d", result.PrunedSnapshots)
	}

	// Verify oldest snapshots (snap-01 and snap-02) were deleted
	for _, snapName := range []string{"snap-01", "snap-02"} {
		snapDir := path.Join(destPath, "snapshots", snapName)
		manifestPath := path.Join(snapDir, snapshot.ManifestFileName)
		if _, err := d.Stat(ctx, manifestPath); err == nil {
			t.Fatalf("expected manifest %s to be deleted", manifestPath)
		}
	}

	// Verify newest snapshots (snap-03, snap-04, snap-05) remain
	for _, snapName := range []string{"snap-03", "snap-04", "snap-05"} {
		snapDir := path.Join(destPath, "snapshots", snapName)
		manifestPath := path.Join(snapDir, snapshot.ManifestFileName)
		if _, err := d.Stat(ctx, manifestPath); err != nil {
			t.Fatalf("expected manifest %s to still exist: %v", manifestPath, err)
		}
	}
}

func TestSnapshotEngine_ExecutionWorkflow(t *testing.T) {
	srcDir, err := os.MkdirTemp("", "unistorage-src-*")
	if err != nil {
		t.Fatalf("src tempDir failed: %v", err)
	}
	defer os.RemoveAll(srcDir)

	destDir, err := os.MkdirTemp("", "unistorage-dest-*")
	if err != nil {
		t.Fatalf("dest tempDir failed: %v", err)
	}
	defer os.RemoveAll(destDir)

	// Populate test data in src
	f1Data := []byte("Postgres DB Dump chunk 1")
	f2Data := []byte("Configuration file contents")
	if err := os.WriteFile(filepath.Join(srcDir, "dump.sql"), f1Data, 0644); err != nil {
		t.Fatalf("failed writing dump.sql: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "config.yaml"), f2Data, 0644); err != nil {
		t.Fatalf("failed writing config.yaml: %v", err)
	}

	srcDriver, _ := local.New(srcDir)
	destDriver, _ := local.New(destDir)

	ctx := context.Background()
	job := snapshot.JobConfig{
		JobID:          "daily-backup",
		Schedule:       "@daily",
		SourcePath:     "",
		DestPath:       "backup-vault",
		RetentionLimit: 2,
		TimeoutMinutes: 30,
		Enabled:        true,
	}

	// 1. Community edition license check: should fail
	commEngine := snapshot.NewEngine(nil, license.NewCommunityChecker())
	_, err = commEngine.ExecuteBackup(ctx, job, srcDriver, destDriver)
	if err == nil {
		t.Fatalf("expected community checker to deny enterprise snapshot execution")
	}

	// 2. Enterprise licensed execution
	pub, priv, _ := license.GenerateKeyPair()
	lk := &license.LicenseKey{
		CustomerID: "enterprise-cust",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Features: []license.Feature{
			license.FeatureSnapshotBackup,
			license.FeatureRetentionPrune,
		},
		Tier: license.TierEnterprise,
	}
	token, _ := license.SignLicense(priv, lk)
	checker, err := license.NewEnterpriseChecker(pub, token)
	if err != nil {
		t.Fatalf("NewEnterpriseChecker failed: %v", err)
	}

	engine := snapshot.NewEngine(nil, checker)
	res, err := engine.ExecuteBackup(ctx, job, srcDriver, destDriver)
	if err != nil {
		t.Fatalf("ExecuteBackup failed: %v", err)
	}

	if res.Manifest == nil {
		t.Fatalf("expected Manifest in run result")
	}
	if res.Manifest.Stats.TotalFiles != 2 {
		t.Fatalf("expected 2 files in manifest, got %d", res.Manifest.Stats.TotalFiles)
	}

	// Verify SHA-256 calculation
	h := sha256.Sum256(f1Data)
	expectedHash := fmt.Sprintf("%x", h)
	var foundDump bool
	for _, f := range res.Manifest.Files {
		if f.Path == "dump.sql" {
			foundDump = true
			if f.SHA256 != expectedHash {
				t.Fatalf("expected sha256 %s, got %s", expectedHash, f.SHA256)
			}
		}
	}
	if !foundDump {
		t.Fatalf("dump.sql not found in snapshot files")
	}
}
