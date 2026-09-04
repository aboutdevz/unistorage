package sync

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// winDriveRegex matches Windows drive roots and absolute drive paths such as C:, C:\..., D:/...
var winDriveRegex = regexp.MustCompile(`^[a-zA-Z]:([\\/].*)?$`)

// TargetLocation represents a resolved local or remote storage endpoint.
type TargetLocation struct {
	IsRemote   bool   `json:"is_remote"`
	RemoteName string `json:"remote_name,omitempty"`
	Path       string `json:"path"`
	Original   string `json:"original"`
}

// String returns the canonical string representation of the target location.
func (t *TargetLocation) String() string {
	if t.IsRemote {
		if t.Path == "" {
			return t.RemoteName + ":"
		}
		return t.RemoteName + ":" + t.Path
	}
	return t.Path
}

// ParseTarget parses a target path string and safely disambiguates Windows drive letters
// (e.g. C:\folder\file.txt, D:/path) from remote specs (e.g. s3-backup:bucket/prefix).
func ParseTarget(target string) (*TargetLocation, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil, fmt.Errorf("target path cannot be empty")
	}

	// 1. Disambiguate Windows drive paths: ^[a-zA-Z]:([\\/].*)?$
	if winDriveRegex.MatchString(trimmed) {
		return &TargetLocation{
			IsRemote:   false,
			RemoteName: "",
			Path:       filepath.Clean(trimmed),
			Original:   trimmed,
		}, nil
	}

	// 2. Remote path specification with ':'
	idx := strings.Index(trimmed, ":")
	if idx != -1 {
		remote := trimmed[:idx]
		relPath := trimmed[idx+1:]
		if remote == "" {
			return nil, fmt.Errorf("invalid target: missing remote name before colon in %q", trimmed)
		}
		// Remote paths normalize to forward slashes without leading slash
		cleanPath := strings.TrimPrefix(strings.ReplaceAll(relPath, "\\", "/"), "/")
		return &TargetLocation{
			IsRemote:   true,
			RemoteName: remote,
			Path:       cleanPath,
			Original:   trimmed,
		}, nil
	}

	// 3. Standard local relative or absolute filesystem path
	return &TargetLocation{
		IsRemote:   false,
		RemoteName: "",
		Path:       filepath.Clean(trimmed),
		Original:   trimmed,
	}, nil
}
