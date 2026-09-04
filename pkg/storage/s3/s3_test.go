package s3_test

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
	unistorage_s3 "github.com/aboutdevz/unistorage/pkg/storage/s3"
	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

// mockS3Server provides an embedded HTTP server simulating S3 REST API.
type mockS3Server struct {
	mu           sync.RWMutex
	objects      map[string][]byte
	multipart    map[string]map[int][]byte // uploadID -> partNumber -> data
	nextUploadID int
	failCount    int32 // for simulating transient errors
}

func newMockS3Server() *mockS3Server {
	return &mockS3Server{
		objects:   make(map[string][]byte),
		multipart: make(map[string]map[int][]byte),
	}
}

func (m *mockS3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Simulate transient 503 SlowDown errors if failCount > 0
	if atomic.LoadInt32(&m.failCount) > 0 {
		atomic.AddInt32(&m.failCount, -1)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>`))
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucket := parts[0]
	key := ""
	if len(parts) > 1 {
		key = parts[1]
	}

	query := r.URL.Query()

	// 1. ListObjectsV2
	if r.Method == http.MethodGet && (key == "" || query.Has("list-type")) {
		prefix := query.Get("prefix")
		var contentsXML []string
		for k, data := range m.objects {
			if prefix == "" || strings.HasPrefix(k, prefix) {
				contentsXML = append(contentsXML, fmt.Sprintf(
					`<Contents><Key>%s</Key><Size>%d</Size><ETag>"mock-etag"</ETag><LastModified>%s</LastModified></Contents>`,
					k, len(data), time.Now().UTC().Format(time.RFC3339),
				))
			}
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(
			`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><IsTruncated>false</IsTruncated>%s</ListBucketResult>`,
			bucket, strings.Join(contentsXML, ""),
		)))
		return
	}

	// 2. Initiate Multipart Upload
	if r.Method == http.MethodPost && query.Has("uploads") {
		m.nextUploadID++
		uploadID := fmt.Sprintf("upload-%d", m.nextUploadID)
		m.multipart[uploadID] = make(map[int][]byte)

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(
			`<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>`,
			bucket, key, uploadID,
		)))
		return
	}

	// 3. Upload Part
	if r.Method == http.MethodPut && query.Has("uploadId") && query.Has("partNumber") {
		uploadID := query.Get("uploadId")
		var partNum int
		_, _ = fmt.Sscanf(query.Get("partNumber"), "%d", &partNum)

		bodyBytes, _ := io.ReadAll(r.Body)
		if partsMap, ok := m.multipart[uploadID]; ok {
			partsMap[partNum] = bodyBytes
		}

		w.Header().Set("ETag", fmt.Sprintf(`"part-etag-%d"`, partNum))
		w.WriteHeader(http.StatusOK)
		return
	}

	// 4. Complete Multipart Upload
	if r.Method == http.MethodPost && query.Has("uploadId") {
		uploadID := query.Get("uploadId")
		partsMap, ok := m.multipart[uploadID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var fullData []byte
		for i := 1; i <= len(partsMap); i++ {
			fullData = append(fullData, partsMap[i]...)
		}
		m.objects[key] = fullData
		delete(m.multipart, uploadID)

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(
			`<CompleteMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><ETag>"complete-etag"</ETag></CompleteMultipartUploadResult>`,
			bucket, key,
		)))
		return
	}

	// 5. Abort Multipart Upload
	if r.Method == http.MethodDelete && query.Has("uploadId") {
		uploadID := query.Get("uploadId")
		delete(m.multipart, uploadID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// 6. PutObject
	if r.Method == http.MethodPut {
		bodyBytes, _ := io.ReadAll(r.Body)
		m.objects[key] = bodyBytes
		w.Header().Set("ETag", `"mock-single-etag"`)
		w.WriteHeader(http.StatusOK)
		return
	}

	// 7. GetObject
	if r.Method == http.MethodGet {
		data, ok := m.objects[key]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`))
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Set("ETag", `"mock-etag"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	// 8. HeadObject
	if r.Method == http.MethodHead {
		data, ok := m.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Set("ETag", `"mock-etag"`)
		w.WriteHeader(http.StatusOK)
		return
	}

	// 9. DeleteObject
	if r.Method == http.MethodDelete {
		delete(m.objects, key)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.NotFound(w, r)
}

func setupTestS3Client(ts *httptest.Server, bucket string) (*awss3.Client, *unistorage_s3.Driver) {
	client := awss3.New(awss3.Options{
		BaseEndpoint: aws.String(ts.URL),
		Region:       "us-east-1",
		UsePathStyle: true,
	})
	driver := unistorage_s3.NewWithClient(client, bucket)
	return client, driver
}

func TestS3Driver_SinglePutAndGet(t *testing.T) {
	mockS3 := newMockS3Server()
	ts := httptest.NewServer(mockS3)
	defer ts.Close()

	ctx := context.Background()
	_, driver := setupTestS3Client(ts, "test-bucket")

	if driver.Name() != "s3" {
		t.Fatalf("expected name 's3', got %q", driver.Name())
	}

	// 1. Write small file (<= 16MB)
	data := []byte("hello S3 compatible storage")
	err := driver.Write(ctx, "notes/doc.txt", bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// 2. Stat
	info, err := driver.Stat(ctx, "notes/doc.txt")
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Size != int64(len(data)) {
		t.Errorf("expected size %d, got %d", len(data), info.Size)
	}

	// 3. Read
	rc, err := driver.Read(ctx, "notes/doc.txt")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	defer rc.Close()
	readBytes, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(readBytes, data) {
		t.Fatalf("content mismatch: got %q, want %q", string(readBytes), string(data))
	}

	// 4. Stream
	var streamBuf bytes.Buffer
	err = driver.Stream(ctx, "notes/doc.txt", &streamBuf)
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	if !bytes.Equal(streamBuf.Bytes(), data) {
		t.Fatalf("streamed mismatch: got %q, want %q", streamBuf.String(), string(data))
	}

	// 5. Delete
	err = driver.Delete(ctx, "notes/doc.txt")
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// 6. Stat after delete returns ErrNotFound
	_, err = driver.Stat(ctx, "notes/doc.txt")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestS3Driver_MultipartUpload(t *testing.T) {
	mockS3 := newMockS3Server()
	ts := httptest.NewServer(mockS3)
	defer ts.Close()

	ctx := context.Background()
	_, driver := setupTestS3Client(ts, "test-bucket")

	// Size > 16MB: 17MB
	size17MB := int64(17 * 1024 * 1024)
	chunk := bytes.Repeat([]byte("X"), 1024*1024) // 1MB chunk

	// MultiReader producing 17MB
	readers := make([]io.Reader, 17)
	for i := 0; i < 17; i++ {
		readers[i] = bytes.NewReader(chunk)
	}
	combined := io.MultiReader(readers...)

	err := driver.Write(ctx, "large-file.dat", combined, size17MB)
	if err != nil {
		t.Fatalf("multipart upload failed: %v", err)
	}

	// Verify object exists in mock S3
	mockS3.mu.RLock()
	stored, exists := mockS3.objects["large-file.dat"]
	mockS3.mu.RUnlock()

	if !exists {
		t.Fatalf("expected object to exist in mock S3 store")
	}
	if int64(len(stored)) != size17MB {
		t.Fatalf("expected stored length %d, got %d", size17MB, len(stored))
	}
}

func TestS3Driver_DynamicStreamMultipart(t *testing.T) {
	mockS3 := newMockS3Server()
	ts := httptest.NewServer(mockS3)
	defer ts.Close()

	ctx := context.Background()
	_, driver := setupTestS3Client(ts, "test-bucket")

	// Unknown size (size = -1) with 18MB
	size18MB := int64(18 * 1024 * 1024)
	chunk := bytes.Repeat([]byte("Y"), 1024*1024)
	readers := make([]io.Reader, 18)
	for i := 0; i < 18; i++ {
		readers[i] = bytes.NewReader(chunk)
	}
	combined := io.MultiReader(readers...)

	err := driver.Write(ctx, "stream-large.dat", combined, -1)
	if err != nil {
		t.Fatalf("dynamic stream multipart upload failed: %v", err)
	}

	mockS3.mu.RLock()
	stored, exists := mockS3.objects["stream-large.dat"]
	mockS3.mu.RUnlock()

	if !exists || int64(len(stored)) != size18MB {
		t.Fatalf("dynamic multipart upload content missing or incomplete")
	}
}

func TestS3Driver_RetryTransientErrors(t *testing.T) {
	mockS3 := newMockS3Server()
	ts := httptest.NewServer(mockS3)
	defer ts.Close()

	ctx := context.Background()
	client := awss3.New(awss3.Options{
		BaseEndpoint: aws.String(ts.URL),
		Region:       "us-east-1",
		UsePathStyle: true,
	})
	retryCfg := unistorage_s3.RetryConfig{
		MaxRetries: 3,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   50 * time.Millisecond,
	}
	driver := unistorage_s3.NewWithClient(client, "test-bucket", retryCfg)

	// Simulate 2 transient 503 SlowDown failures, then success
	atomic.StoreInt32(&mockS3.failCount, 2)

	data := []byte("retry test data")
	err := driver.Write(ctx, "retry.txt", bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("expected retry to succeed after transient errors, got: %v", err)
	}

	// Verify failCount reached 0
	if atomic.LoadInt32(&mockS3.failCount) != 0 {
		t.Fatalf("expected failCount to be 0, got %d", atomic.LoadInt32(&mockS3.failCount))
	}
}

// Ensure xml import is used
var _ = xml.Header
