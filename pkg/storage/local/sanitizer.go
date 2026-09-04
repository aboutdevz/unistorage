package local

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

// winDeviceRegex matches Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
// with optional extensions (e.g. CON.txt, NUL.dat).
var winDeviceRegex = regexp.MustCompile(`^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$`)

// PathSanitizer validates and confines relative paths inside a designated root directory.
type PathSanitizer struct {
	canonicalRoot string
}

// NewPathSanitizer creates a PathSanitizer with an evaluated, absolute canonical root.
func NewPathSanitizer(rootDir string) (*PathSanitizer, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute root path: %w", err)
	}

	canonicalRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		// If root doesn't exist yet, clean the absRoot
		canonicalRoot = filepath.Clean(absRoot)
	} else {
		canonicalRoot = filepath.Clean(canonicalRoot)
	}

	return &PathSanitizer{canonicalRoot: canonicalRoot}, nil
}

// CanonicalRoot returns the absolute, symlink-evaluated root path.
func (p *PathSanitizer) CanonicalRoot() string {
	return p.canonicalRoot
}

// Sanitize resolves userPath safely inside the canonical root directory.
// Rejects path traversal, null bytes, URL encoded escapes, Windows device names,
// alternate data streams, and external symlinks.
func (p *PathSanitizer) Sanitize(userPath string) (string, error) {
	// 1. Check for null bytes
	if strings.ContainsRune(userPath, 0) {
		return "", fmt.Errorf("%w: path contains null byte: %w", storage.ErrInvalidPath, storage.ErrPathTraversal)
	}

	// 2. URL decode detection: if path contains '%', decode and check for traversal
	if strings.Contains(userPath, "%") {
		decoded, err := url.PathUnescape(userPath)
		if err != nil {
			return "", fmt.Errorf("%w: invalid url encoding in path", storage.ErrInvalidPath)
		}
		if strings.ContainsRune(decoded, 0) {
			return "", fmt.Errorf("%w: path contains url-encoded null byte: %w", storage.ErrInvalidPath, storage.ErrPathTraversal)
		}
		if strings.Contains(decoded, "..") {
			return "", fmt.Errorf("%w: path contains url-encoded traversal: %w", storage.ErrInvalidPath, storage.ErrPathTraversal)
		}
		userPath = decoded
	}

	// 3. Normalize slashes
	normalized := strings.ReplaceAll(userPath, "\\", "/")

	// 4. Reject Windows drive letters, colons, and Alternate Data Streams (::$DATA)
	if strings.Contains(normalized, ":") {
		return "", fmt.Errorf("%w: colon or alternate data stream forbidden: %w", storage.ErrInvalidPath, storage.ErrPathTraversal)
	}

	// 5. Check segments before lexical cleaning for directory traversal and reserved names
	rawSegments := strings.Split(normalized, "/")
	for _, seg := range rawSegments {
		// Reject multi-dot traversal patterns like "..", "...", "...."
		trimmedDots := strings.Trim(seg, ".")
		if trimmedDots == "" && len(seg) >= 2 {
			return "", fmt.Errorf("%w: traversal segment %q: %w", storage.ErrInvalidPath, seg, storage.ErrPathTraversal)
		}
		if seg == ".." || strings.Contains(seg, "..") {
			return "", fmt.Errorf("%w: traversal segment %q: %w", storage.ErrInvalidPath, seg, storage.ErrPathTraversal)
		}
		// Check for Windows reserved device names in each path segment
		if winDeviceRegex.MatchString(seg) {
			return "", fmt.Errorf("%w: reserved device name %q", storage.ErrInvalidPath, seg)
		}
	}

	// 6. Clean path lexically using forward slashes
	cleanRel := path.Clean("/" + normalized)
	cleanRel = strings.TrimPrefix(cleanRel, "/")
	if cleanRel == "." {
		cleanRel = ""
	}

	// Check for escaping leading parent references
	if cleanRel == ".." || strings.HasPrefix(cleanRel, "../") || strings.Contains(cleanRel, "/../") {
		return "", fmt.Errorf("%w: path traverses outside root: %w", storage.ErrInvalidPath, storage.ErrPathTraversal)
	}

	// 7. Join with absolute canonical root directory
	fullPath := filepath.Join(p.canonicalRoot, filepath.FromSlash(cleanRel))
	fullPath = filepath.Clean(fullPath)

	// 8. Lexical boundary verification
	rel, err := filepath.Rel(p.canonicalRoot, fullPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: resolved path escapes root boundary: %w", storage.ErrInvalidPath, storage.ErrPathTraversal)
	}

	// 9. Symlink verification:
	// If path exists or any ancestor exists and is a symlink, verify it doesn't escape root
	if err := p.verifySymlinkConfinement(fullPath); err != nil {
		return "", err
	}

	return fullPath, nil
}

// verifySymlinkConfinement checks that any existing symlink in the path stays within root.
func (p *PathSanitizer) verifySymlinkConfinement(targetPath string) error {
	curr := targetPath
	for {
		var fi os.FileInfo
		var err error
		for attempt := 0; attempt < 5; attempt++ {
			fi, err = os.Lstat(curr)
			if err == nil || errors.Is(err, os.ErrNotExist) {
				break
			}
			time.Sleep(time.Duration(5*(attempt+1)) * time.Millisecond)
		}
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				resolved, err := filepath.EvalSymlinks(curr)
				if err != nil {
					return fmt.Errorf("%w: failed to evaluate symlink %q: %w", storage.ErrInvalidPath, curr, storage.ErrPathTraversal)
				}
				resolved = filepath.Clean(resolved)
				rel, err := filepath.Rel(p.canonicalRoot, resolved)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return fmt.Errorf("%w: symlink targets location outside root: %w", storage.ErrInvalidPath, storage.ErrPathTraversal)
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: failed to stat path %q: %v", storage.ErrInvalidPath, curr, err)
		}

		parent := filepath.Dir(curr)
		if parent == curr || len(parent) < len(p.canonicalRoot) {
			break
		}
		curr = parent
	}
	return nil
}
