package storage_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/storage"
)

func TestMockDriverCRUD(t *testing.T) {
	ctx := context.Background()
	driver := storage.NewMockDriver("test-mock")

	if driver.Name() != "test-mock" {
		t.Fatalf("expected driver name 'test-mock', got %q", driver.Name())
	}

	// 1. Stat non-existent
	_, err := driver.Stat(ctx, "nonexistent.txt")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// 2. Write object
	content := []byte("hello unistorage mock")
	err = driver.Write(ctx, "documents/test.txt", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// 3. Stat existing
	info, err := driver.Stat(ctx, "documents/test.txt")
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), info.Size)
	}
	if info.Key != "documents/test.txt" {
		t.Errorf("expected key 'documents/test.txt', got %q", info.Key)
	}

	// 4. Read object
	rc, err := driver.Read(ctx, "documents/test.txt")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	defer rc.Close()
	readBytes, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read all failed: %v", err)
	}
	if !bytes.Equal(readBytes, content) {
		t.Fatalf("content mismatch: got %q, want %q", string(readBytes), string(content))
	}

	// 5. Stream object
	var streamBuf bytes.Buffer
	err = driver.Stream(ctx, "documents/test.txt", &streamBuf)
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	if !bytes.Equal(streamBuf.Bytes(), content) {
		t.Fatalf("streamed content mismatch: got %q, want %q", streamBuf.String(), string(content))
	}

	// 6. Overwrite policy
	err = driver.WriteWithOptions(ctx, "documents/test.txt", bytes.NewReader([]byte("new")), 3, storage.WithNoOverwrite())
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists on no-overwrite, got %v", err)
	}

	// 7. Delete object
	err = driver.Delete(ctx, "documents/test.txt")
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// 8. Delete is idempotent
	err = driver.Delete(ctx, "documents/test.txt")
	if err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}

	// 9. Read deleted returns ErrNotFound
	_, err = driver.Read(ctx, "documents/test.txt")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after deletion, got %v", err)
	}
}

func TestMockDriverListAndPagination(t *testing.T) {
	ctx := context.Background()
	driver := storage.NewMockDriver()

	// Populate 10 items
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("items/item-%02d.dat", i)
		data := []byte(fmt.Sprintf("data-%d", i))
		if err := driver.Write(ctx, key, bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatalf("write item failed: %v", err)
		}
	}

	// Write item outside prefix
	if err := driver.Write(ctx, "other/foo.txt", bytes.NewReader([]byte("foo")), 3); err != nil {
		t.Fatalf("write other item failed: %v", err)
	}

	// List prefix "items"
	list, err := driver.List(ctx, "items")
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(list) != 10 {
		t.Fatalf("expected 10 items, got %d", len(list))
	}

	// List with pagination: 4 items per page
	res1, err := driver.ListWithOptions(ctx, storage.ListOptions{
		Prefix:  "items",
		MaxKeys: 4,
	})
	if err != nil {
		t.Fatalf("page 1 failed: %v", err)
	}
	if len(res1.Objects) != 4 || !res1.IsTruncated || res1.NextContinuationToken == "" {
		t.Fatalf("unexpected page 1 result: %+v", res1)
	}

	// Page 2
	res2, err := driver.ListWithOptions(ctx, storage.ListOptions{
		Prefix:            "items",
		MaxKeys:           4,
		ContinuationToken: res1.NextContinuationToken,
	})
	if err != nil {
		t.Fatalf("page 2 failed: %v", err)
	}
	if len(res2.Objects) != 4 || !res2.IsTruncated {
		t.Fatalf("unexpected page 2 result: %+v", res2)
	}

	// Page 3 (remaining 2 items)
	res3, err := driver.ListWithOptions(ctx, storage.ListOptions{
		Prefix:            "items",
		MaxKeys:           4,
		ContinuationToken: res2.NextContinuationToken,
	})
	if err != nil {
		t.Fatalf("page 3 failed: %v", err)
	}
	if len(res3.Objects) != 2 || res3.IsTruncated {
		t.Fatalf("unexpected page 3 result: %+v", res3)
	}
}

func TestMockDriverConcurrency(t *testing.T) {
	ctx := context.Background()
	driver := storage.NewMockDriver()

	var wg sync.WaitGroup
	numWorkers := 20
	numOps := 50

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				key := fmt.Sprintf("worker-%d/file-%d.txt", workerID, j)
				data := []byte(fmt.Sprintf("content-%d-%d", workerID, j))

				_ = driver.Write(ctx, key, bytes.NewReader(data), int64(len(data)))
				_, _ = driver.Stat(ctx, key)
				rc, err := driver.Read(ctx, key)
				if err == nil {
					_, _ = io.ReadAll(rc)
					_ = rc.Close()
				}
				_ = driver.Delete(ctx, key)
			}
		}(i)
	}

	wg.Wait()
}
