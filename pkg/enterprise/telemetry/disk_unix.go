//go:build !windows

package telemetry

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// GetDiskUsage inspects filesystem capacity using Statfs syscall on Unix/Linux/macOS.
func GetDiskUsage(path string) (*DiskUsage, error) {
	if path == "" {
		path = "."
	}

	var stat unix.Statfs_t
	err := unix.Statfs(path, &stat)
	if err != nil {
		return nil, fmt.Errorf("statfs failed for %s: %w", path, err)
	}

	bsize := uint64(stat.Bsize)
	total := uint64(stat.Blocks) * bsize
	free := uint64(stat.Bfree) * bsize
	avail := uint64(stat.Bavail) * bsize

	var used uint64
	if total >= free {
		used = total - free
	}

	var pct float64
	if total > 0 {
		pct = (float64(used) / float64(total)) * 100.0
	}

	return &DiskUsage{
		Path:        path,
		TotalBytes:  total,
		FreeBytes:   free,
		AvailBytes:  avail,
		UsedBytes:   used,
		UsedPercent: pct,
	}, nil
}
