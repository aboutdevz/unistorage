package sync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

func TestComparator_DefaultMode_SizeDiff(t *testing.T) {
	cmp := NewComparator(CompareModeSizeModTime)
	now := time.Now()

	src := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: now}
	dest := &storage.ObjectInfo{Path: "f.txt", Size: 200, ModTime: now}

	status, err := cmp.Compare(context.Background(), nil, src, nil, dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != DiffStatusConflict {
		t.Errorf("expected DiffStatusConflict for different sizes, got %v", status)
	}
}

func TestComparator_DefaultMode_ModTimeEpsilon(t *testing.T) {
	cmp := NewComparator(CompareModeSizeModTime)
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)

	// Subtest 1: Exactly equal mod times
	t.Run("ExactModTime", func(t *testing.T) {
		src := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base}
		dest := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base}
		status, err := cmp.Compare(context.Background(), nil, src, nil, dest)
		if err != nil || status != DiffStatusIdentical {
			t.Errorf("expected DiffStatusIdentical, got %v (err=%v)", status, err)
		}
	})

	// Subtest 2: Within 1-second epsilon (500ms difference)
	t.Run("WithinEpsilon_500ms", func(t *testing.T) {
		src := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base.Add(500 * time.Millisecond)}
		dest := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base}
		status, err := cmp.Compare(context.Background(), nil, src, nil, dest)
		if err != nil || status != DiffStatusIdentical {
			t.Errorf("expected DiffStatusIdentical for within epsilon, got %v (err=%v)", status, err)
		}
	})

	// Subtest 3: Source is newer by > 1s (1500ms)
	t.Run("SourceNewer_1500ms", func(t *testing.T) {
		src := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base.Add(1500 * time.Millisecond)}
		dest := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base}
		status, err := cmp.Compare(context.Background(), nil, src, nil, dest)
		if err != nil || status != DiffStatusModified {
			t.Errorf("expected DiffStatusModified for newer source, got %v (err=%v)", status, err)
		}
	})

	// Subtest 4: Destination is newer by > 1s (out-of-band edit)
	t.Run("DestNewer_1500ms", func(t *testing.T) {
		src := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base}
		dest := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base.Add(1500 * time.Millisecond)}
		status, err := cmp.Compare(context.Background(), nil, src, nil, dest)
		if err != nil || status != DiffStatusConflict {
			t.Errorf("expected DiffStatusConflict for newer destination, got %v (err=%v)", status, err)
		}
	})

	// Subtest 5: New destination file
	t.Run("NewFile_DestNil", func(t *testing.T) {
		src := &storage.ObjectInfo{Path: "f.txt", Size: 100, ModTime: base}
		status, err := cmp.Compare(context.Background(), nil, src, nil, nil)
		if err != nil || status != DiffStatusNew {
			t.Errorf("expected DiffStatusNew for nil dest, got %v (err=%v)", status, err)
		}
	})
}

func TestComparator_ChecksumMode(t *testing.T) {
	ctx := context.Background()
	cmp := NewComparator(CompareModeChecksum)

	// Use storage.NewMockDriver for source and dest
	srcDrv := storage.NewMockDriver("src-mock")
	destDrv := storage.NewMockDriver("dest-mock")

	t.Run("Identical_Content", func(t *testing.T) {
		content := []byte("consistent content across drivers")
		_ = srcDrv.Write(ctx, "ident.txt", bytes.NewReader(content), int64(len(content)))
		_ = destDrv.Write(ctx, "ident.txt", bytes.NewReader(content), int64(len(content)))

		srcInfo, _ := srcDrv.Stat(ctx, "ident.txt")
		destInfo, _ := destDrv.Stat(ctx, "ident.txt")

		status, err := cmp.Compare(ctx, srcDrv, srcInfo, destDrv, destInfo)
		if err != nil || status != DiffStatusIdentical {
			t.Errorf("expected DiffStatusIdentical, got %v (err=%v)", status, err)
		}
	})

	t.Run("SameSize_DifferentContent", func(t *testing.T) {
		contentA := []byte("AAAA_same_length_data")
		contentB := []byte("BBBB_same_length_data")
		_ = srcDrv.Write(ctx, "diff.txt", bytes.NewReader(contentA), int64(len(contentA)))
		_ = destDrv.Write(ctx, "diff.txt", bytes.NewReader(contentB), int64(len(contentB)))

		srcInfo, _ := srcDrv.Stat(ctx, "diff.txt")
		destInfo, _ := destDrv.Stat(ctx, "diff.txt")

		status, err := cmp.Compare(ctx, srcDrv, srcInfo, destDrv, destInfo)
		if err != nil || status != DiffStatusConflict {
			t.Errorf("expected DiffStatusConflict for different content, got %v (err=%v)", status, err)
		}
	})

	t.Run("Empty_Files", func(t *testing.T) {
		_ = srcDrv.Write(ctx, "empty.txt", bytes.NewReader([]byte{}), 0)
		_ = destDrv.Write(ctx, "empty.txt", bytes.NewReader([]byte{}), 0)

		srcInfo, _ := srcDrv.Stat(ctx, "empty.txt")
		destInfo, _ := destDrv.Stat(ctx, "empty.txt")

		status, err := cmp.Compare(ctx, srcDrv, srcInfo, destDrv, destInfo)
		if err != nil || status != DiffStatusIdentical {
			t.Errorf("expected DiffStatusIdentical for empty files, got %v (err=%v)", status, err)
		}

		hash, err := ComputeSHA256(ctx, srcDrv, "empty.txt")
		if err != nil {
			t.Fatalf("ComputeSHA256 error: %v", err)
		}
		expectedEmptyHash := hex.EncodeToString(sha256.New().Sum(nil))
		if hash != expectedEmptyHash {
			t.Errorf("expected %s, got %s", expectedEmptyHash, hash)
		}
	})

	t.Run("Binary_Files", func(t *testing.T) {
		binA := []byte{0x00, 0xFF, 0xFE, 0x01, 0xAA, 0xBB}
		binB := []byte{0x00, 0xFF, 0xFE, 0x01, 0xAA, 0xCC}
		_ = srcDrv.Write(ctx, "bin_a.dat", bytes.NewReader(binA), int64(len(binA)))
		_ = destDrv.Write(ctx, "bin_a.dat", bytes.NewReader(binB), int64(len(binB)))

		srcInfo, _ := srcDrv.Stat(ctx, "bin_a.dat")
		destInfo, _ := destDrv.Stat(ctx, "bin_a.dat")

		status, err := cmp.Compare(ctx, srcDrv, srcInfo, destDrv, destInfo)
		if err != nil || status != DiffStatusConflict {
			t.Errorf("expected DiffStatusConflict for differing binary, got %v (err=%v)", status, err)
		}
	})
}
