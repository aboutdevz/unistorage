//go:build windows

package telemetry

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// GetDiskUsage retrieves filesystem capacity and usage using direct Windows kernel syscalls.
func GetDiskUsage(path string) (*DiskUsage, error) {
	if path == "" {
		path = "."
	}

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path string: %w", err)
	}

	var freeAvail, total, totalFree uint64
	err = windows.GetDiskFreeSpaceEx(pathPtr, &freeAvail, &total, &totalFree)
	if err != nil {
		return nil, fmt.Errorf("GetDiskFreeSpaceEx failed for %s: %w", path, err)
	}

	var used uint64
	if total >= totalFree {
		used = total - totalFree
	}

	var pct float64
	if total > 0 {
		pct = (float64(used) / float64(total)) * 100.0
	}

	return &DiskUsage{
		Path:        path,
		TotalBytes:  total,
		FreeBytes:   totalFree,
		AvailBytes:  freeAvail,
		UsedBytes:   used,
		UsedPercent: pct,
	}, nil
}
