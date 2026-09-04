package harness

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- mock S3 server calculates standard RFC-compliant S3 MD5 ETags
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// S3MockServer simulates an S3-compatible object storage server (AWS S3, MinIO) for zero-cost E2E tests.
type S3MockServer struct {
	server           *httptest.Server
	mu               sync.RWMutex
	buckets          map[string]map[string][]byte
	multipartUploads map[string]map[int][]byte // uploadId -> partNum -> data
	nextUploadID     uint64

	// Failure simulation
	failNextNRequests int32
	simulateLatency   time.Duration
}

// NewS3MockServer starts an in-process HTTP mock server simulating S3 REST API.
func NewS3MockServer() *S3MockServer {
	s := &S3MockServer{
		buckets:          make(map[string]map[string][]byte),
		multipartUploads: make(map[string]map[int][]byte),
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handler))
	return s
}

// URL returns the base URL of the mock S3 server.
func (s *S3MockServer) URL() string {
	return s.server.URL
}

// Close terminates the mock server.
func (s *S3MockServer) Close() {
	s.server.Close()
}

// CreateBucket provisions a bucket in memory.
func (s *S3MockServer) CreateBucket(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.buckets[name]; !ok {
		s.buckets[name] = make(map[string][]byte)
	}
}

// SimulateTransientFailures causes next N requests to return HTTP 503 SlowDown / ServiceUnavailable.
func (s *S3MockServer) SimulateTransientFailures(n int32) {
	atomic.StoreInt32(&s.failNextNRequests, n)
}

// SetLatency sets an artificial delay for each S3 request.
func (s *S3MockServer) SetLatency(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.simulateLatency = d
}

// GetObjectData inspects bucket contents directly for test assertions.
func (s *S3MockServer) GetObjectData(bucket, key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.buckets[bucket]
	if !ok {
		return nil, false
	}
	data, ok := b[key]
	return data, ok
}

func (s *S3MockServer) handler(w http.ResponseWriter, r *http.Request) {
	// Latency injection
	s.mu.RLock()
	lat := s.simulateLatency
	s.mu.RUnlock()
	if lat > 0 {
		time.Sleep(lat)
	}

	// Transient failure injection
	if rem := atomic.AddInt32(&s.failNextNRequests, -1); rem >= 0 {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>`))
		return
	}

	// Path parsing: /{bucket}/{key...}
	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	bucket := parts[0]
	key := ""
	if len(parts) > 1 {
		key = parts[1]
	}

	s.mu.Lock()
	if _, ok := s.buckets[bucket]; !ok {
		s.buckets[bucket] = make(map[string][]byte)
	}
	s.mu.Unlock()

	query := r.URL.Query()

	// 1. Multipart initiation / completion
	if query.Has("uploads") && r.Method == http.MethodPost {
		s.handleInitiateMultipart(w, r, bucket, key)
		return
	}
	if query.Has("uploadId") && query.Has("partNumber") && r.Method == http.MethodPut {
		s.handleUploadPart(w, r, query.Get("uploadId"), query.Get("partNumber"))
		return
	}
	if query.Has("uploadId") && r.Method == http.MethodPost {
		s.handleCompleteMultipart(w, r, bucket, key, query.Get("uploadId"))
		return
	}
	if query.Has("uploadId") && r.Method == http.MethodDelete {
		s.handleAbortMultipart(w, query.Get("uploadId"))
		return
	}

	// 2. Standard S3 Operations
	switch r.Method {
	case http.MethodPut:
		s.handlePutObject(w, r, bucket, key)
	case http.MethodGet:
		if key == "" || query.Has("list-type") {
			s.handleListObjects(w, r, bucket)
		} else {
			s.handleGetObject(w, bucket, key)
		}
	case http.MethodHead:
		s.handleHeadObject(w, bucket, key)
	case http.MethodDelete:
		s.handleDeleteObject(w, bucket, key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *S3MockServer) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// #nosec G401 -- mock S3 server requires standard MD5 for ETag
	hash := md5.Sum(data)
	etag := hex.EncodeToString(hash[:])

	s.mu.Lock()
	s.buckets[bucket][key] = data
	s.mu.Unlock()

	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(http.StatusOK)
}

func (s *S3MockServer) handleGetObject(w http.ResponseWriter, bucket, key string) {
	s.mu.RLock()
	data, ok := s.buckets[bucket][key]
	s.mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`))
		return
	}

	// #nosec G401 -- mock S3 server requires standard MD5 for ETag
	hash := md5.Sum(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *S3MockServer) handleHeadObject(w http.ResponseWriter, bucket, key string) {
	s.mu.RLock()
	data, ok := s.buckets[bucket][key]
	s.mu.RUnlock()

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// #nosec G401 -- mock S3 server requires standard MD5 for ETag
	hash := md5.Sum(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
}

func (s *S3MockServer) handleDeleteObject(w http.ResponseWriter, bucket, key string) {
	s.mu.Lock()
	delete(s.buckets[bucket], key)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

type ListBucketResult struct {
	XMLName     xml.Name   `xml:"ListBucketResult"`
	Name        string     `xml:"Name"`
	Prefix      string     `xml:"Prefix"`
	KeyCount    int        `xml:"KeyCount"`
	MaxKeys     int        `xml:"MaxKeys"`
	IsTruncated bool       `xml:"IsTruncated"`
	Contents    []S3Object `xml:"Contents"`
}

type S3Object struct {
	Key          string    `xml:"Key"`
	LastModified time.Time `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	StorageClass string    `xml:"StorageClass"`
}

func (s *S3MockServer) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")

	s.mu.RLock()
	var objects []S3Object
	if b, ok := s.buckets[bucket]; ok {
		for k, v := range b {
			if strings.HasPrefix(k, prefix) {
				// #nosec G401 -- mock S3 server requires standard MD5 for ETag
				hash := md5.Sum(v)
				objects = append(objects, S3Object{
					Key:          k,
					LastModified: time.Now().UTC(),
					ETag:         `"` + hex.EncodeToString(hash[:]) + `"`,
					Size:         int64(len(v)),
					StorageClass: "STANDARD",
				})
			}
		}
	}
	s.mu.RUnlock()

	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Key < objects[j].Key
	})

	res := ListBucketResult{
		Name:        bucket,
		Prefix:      prefix,
		KeyCount:    len(objects),
		MaxKeys:     1000,
		IsTruncated: false,
		Contents:    objects,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(res)
}

func (s *S3MockServer) handleInitiateMultipart(w http.ResponseWriter, r *http.Request, bucket, key string) {
	uid := atomic.AddUint64(&s.nextUploadID, 1)
	uploadID := fmt.Sprintf("upload-%d", uid)

	s.mu.Lock()
	s.multipartUploads[uploadID] = make(map[int][]byte)
	s.mu.Unlock()

	type InitiateResult struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadId string   `xml:"UploadId"`
	}
	res := InitiateResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(res)
}

func (s *S3MockServer) handleUploadPart(w http.ResponseWriter, r *http.Request, uploadID, partNumStr string) {
	partNum, err := strconv.Atoi(partNumStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	parts, ok := s.multipartUploads[uploadID]
	if !ok {
		s.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		return
	}
	parts[partNum] = data
	s.mu.Unlock()

	// #nosec G401 -- mock S3 server requires standard MD5 for ETag
	hash := md5.Sum(data)
	w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
	w.WriteHeader(http.StatusOK)
}

func (s *S3MockServer) handleCompleteMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	s.mu.Lock()
	parts, ok := s.multipartUploads[uploadID]
	if !ok {
		s.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var partNums []int
	for num := range parts {
		partNums = append(partNums, num)
	}
	sort.Ints(partNums)

	var assembled bytes.Buffer
	for _, num := range partNums {
		assembled.Write(parts[num])
	}
	delete(s.multipartUploads, uploadID)
	data := assembled.Bytes()
	s.buckets[bucket][key] = data
	s.mu.Unlock()

	// #nosec G401 -- mock S3 server requires standard MD5 for ETag
	hash := md5.Sum(data)
	etag := hex.EncodeToString(hash[:])

	type CompleteResult struct {
		XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
		Bucket  string   `xml:"Bucket"`
		Key     string   `xml:"Key"`
		ETag    string   `xml:"ETag"`
	}
	res := CompleteResult{
		Bucket: bucket,
		Key:    key,
		ETag:   `"` + etag + `"`,
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(res)
}

func (s *S3MockServer) handleAbortMultipart(w http.ResponseWriter, uploadID string) {
	s.mu.Lock()
	delete(s.multipartUploads, uploadID)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
