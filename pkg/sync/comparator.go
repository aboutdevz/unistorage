package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

// ModTimeEpsilon defines the tolerance threshold (1.0 second) for filesystem timestamp comparison.
const ModTimeEpsilon = 1 * time.Second

// CompareMode specifies how files are compared.
type CompareMode int

const (
	CompareModeSizeModTime CompareMode = iota
	CompareModeChecksum
)

// DiffStatus indicates the change detection result between source and destination.
type DiffStatus int

const (
	DiffStatusIdentical DiffStatus = iota // No changes needed
	DiffStatusNew                         // Dest does not exist; new file
	DiffStatusModified                    // Source size or modtime indicates update
	DiffStatusConflict                    // Dest exists and is divergent
)

// String returns a human-readable description of DiffStatus.
func (s DiffStatus) String() string {
	switch s {
	case DiffStatusIdentical:
		return "IDENTICAL"
	case DiffStatusNew:
		return "NEW"
	case DiffStatusModified:
		return "MODIFIED"
	case DiffStatusConflict:
		return "CONFLICT"
	default:
		return "UNKNOWN"
	}
}

// Comparator coordinates change detection between source and destination objects.
type Comparator struct {
	Mode CompareMode
}

// NewComparator creates a comparator with the given mode.
func NewComparator(mode CompareMode) *Comparator {
	return &Comparator{Mode: mode}
}

// ComputeSHA256 calculates the hex-encoded SHA-256 hash of an object in constant memory using storage.BufferPool.
func ComputeSHA256(ctx context.Context, driver storage.Driver, path string) (string, error) {
	rc, err := driver.Read(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to open object for hashing %q: %w", path, err)
	}
	defer rc.Close()

	hasher := sha256.New()
	bufPtr := storage.BufferPool.Get().(*[]byte)
	defer storage.BufferPool.Put(bufPtr)

	if _, err := io.CopyBuffer(hasher, rc, *bufPtr); err != nil {
		return "", fmt.Errorf("hashing stream error for %q: %w", path, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Compare determines the DiffStatus between a source object and destination object.
// If dest is nil, it returns DiffStatusNew.
// In default mode:
// - If sizes differ: DiffStatusConflict (destination file will be displaced)
// - If sizes match and ModTime difference <= 1.0s: DiffStatusIdentical
// - If source ModTime is newer by > 1.0s: DiffStatusModified
// - If destination ModTime is newer by > 1.0s: DiffStatusConflict
// In checksum mode:
// - If SHA-256 hashes match: DiffStatusIdentical
// - If SHA-256 hashes differ: DiffStatusConflict
func (c *Comparator) Compare(ctx context.Context, srcDriver storage.Driver, srcInfo *storage.ObjectInfo, destDriver storage.Driver, destInfo *storage.ObjectInfo) (DiffStatus, error) {
	if destInfo == nil {
		return DiffStatusNew, nil
	}

	if c.Mode == CompareModeChecksum {
		srcHash, err := ComputeSHA256(ctx, srcDriver, srcInfo.Path)
		if err != nil {
			return DiffStatusModified, fmt.Errorf("failed to hash source %q: %w", srcInfo.Path, err)
		}
		destHash, err := ComputeSHA256(ctx, destDriver, destInfo.Path)
		if err != nil {
			return DiffStatusModified, fmt.Errorf("failed to hash destination %q: %w", destInfo.Path, err)
		}
		if srcHash == destHash {
			return DiffStatusIdentical, nil
		}
		return DiffStatusConflict, nil
	}

	// Default Mode: Size + ModTime with 1-second epsilon
	if srcInfo.Size != destInfo.Size {
		return DiffStatusConflict, nil
	}

	diff := srcInfo.ModTime.Sub(destInfo.ModTime)
	absDiff := time.Duration(math.Abs(float64(diff)))
	if absDiff <= ModTimeEpsilon {
		return DiffStatusIdentical, nil
	}

	if diff > ModTimeEpsilon {
		return DiffStatusModified, nil
	}

	// Destination is strictly newer (out-of-band edit)
	return DiffStatusConflict, nil
}
