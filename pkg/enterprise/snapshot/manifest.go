package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

const (
	ManifestVersionCurrent = "1.0"
	StatusSuccess          = "SUCCESS"
	StatusFailed           = "FAILED"
	StatusPartial          = "PARTIAL"
	ManifestFileName       = "manifest.json"
	ManifestTempFileName   = "manifest.json.tmp"
)

// SnapshotStats contains aggregate metrics for a snapshot backup execution.
type SnapshotStats struct {
	TotalFiles      int     `json:"total_files"`
	TotalBytes      int64   `json:"total_bytes"`
	DurationSeconds float64 `json:"duration_seconds"`
	Status          string  `json:"status"`
}

// StatsSuccess constructs a SnapshotStats with StatusSuccess.
func StatsSuccess(totalFiles int, totalBytes int64, durationSeconds float64) SnapshotStats {
	return SnapshotStats{
		TotalFiles:      totalFiles,
		TotalBytes:      totalBytes,
		DurationSeconds: durationSeconds,
		Status:          StatusSuccess,
	}
}

// SnapshotFile records metadata and checksum of an individual snapshot file.
type SnapshotFile struct {
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	SHA256  string    `json:"sha256"`
	ModTime time.Time `json:"mod_time"`
	Mode    string    `json:"mode,omitempty"`
}

// Manifest represents the authoritative snapshot metadata tree.
type Manifest struct {
	ManifestVersion string         `json:"manifest_version"`
	SnapshotID      string         `json:"snapshot_id"`
	JobID           string         `json:"job_id"`
	Timestamp       time.Time      `json:"timestamp"`
	SourceRemote    string         `json:"source_remote,omitempty"`
	SourcePath      string         `json:"source_path,omitempty"`
	DestRemote      string         `json:"dest_remote,omitempty"`
	DestPath        string         `json:"dest_path,omitempty"`
	Stats           SnapshotStats  `json:"stats"`
	Files           []SnapshotFile `json:"files"`
}

// WriteManifest atomically persists the manifest into the snapshot directory.
// It writes manifest.json.tmp first, then manifest.json, and cleans up .tmp.
func WriteManifest(ctx context.Context, d storage.Driver, snapshotDir string, m *Manifest) error {
	if m.ManifestVersion == "" {
		m.ManifestVersion = ManifestVersionCurrent
	}
	if m.Files == nil {
		m.Files = make([]SnapshotFile, 0)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot manifest: %w", err)
	}

	cleanDir := strings.Trim(snapshotDir, "/")
	tmpPath := path.Join(cleanDir, ManifestTempFileName)
	finalPath := path.Join(cleanDir, ManifestFileName)

	// Step 1: Write to temporary manifest file
	if err := d.Write(ctx, tmpPath, bytes.NewReader(data), int64(len(data))); err != nil {
		return fmt.Errorf("failed writing temporary manifest %s: %w", tmpPath, err)
	}

	// Step 2: Write to final manifest file (atomic commit)
	if err := d.Write(ctx, finalPath, bytes.NewReader(data), int64(len(data))); err != nil {
		return fmt.Errorf("failed writing manifest %s: %w", finalPath, err)
	}

	// Step 3: Remove temporary manifest file
	_ = d.Delete(ctx, tmpPath)

	return nil
}

// ReadManifest fetches and decodes a manifest from storage.
func ReadManifest(ctx context.Context, d storage.Driver, manifestPath string) (*Manifest, error) {
	rc, err := d.Read(ctx, manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest at %s: %w", manifestPath, err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest payload: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to decode manifest JSON: %w", err)
	}

	return &m, nil
}
