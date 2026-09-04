package daemon_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aboutdevz/unistorage/internal/daemon"
	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/vault"
)

func setupTestDaemon(t *testing.T) (*daemon.Server, http.Handler, string, func()) {
	tempDir, err := os.MkdirTemp("", "unistorage-daemon-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	tokenFile := filepath.Join(tempDir, "daemon.token")
	vaultPath := filepath.Join(tempDir, "vault.enc")

	cfg := daemon.Config{
		Addr:            "127.0.0.1:8080",
		TokenFile:       tokenFile,
		VaultPath:       vaultPath,
		VaultPassphrase: "test-passphrase",
	}

	srv, err := daemon.New(cfg)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	return srv, srv.Handler(), srv.Token(), cleanup
}

func newReq(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Host = "127.0.0.1:8080"
	return req
}

func TestDaemon_Health(t *testing.T) {
	_, handler, _, cleanup := setupTestDaemon(t)
	defer cleanup()

	// 1. /healthz without auth
	req := newReq(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	// 2. /api/v1/health without auth
	req2 := newReq(http.MethodGet, "/api/v1/health", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w2.Code)
	}

	var payload map[string]string
	if err := json.Unmarshal(w2.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode health payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Errorf("expected status ok, got %q", payload["status"])
	}
	if payload["version"] == "" {
		t.Errorf("expected non-empty version in health payload")
	}

	// 3. Health with configured version
	customSrv, err := daemon.New(daemon.Config{
		StaticToken: "test-custom-token",
		Version:     "v1.2.3",
	})
	if err != nil {
		t.Fatalf("failed to create custom daemon: %v", err)
	}
	w3 := httptest.NewRecorder()
	customSrv.Handler().ServeHTTP(w3, newReq(http.MethodGet, "/api/v1/health", nil))
	var customPayload map[string]string
	if err := json.Unmarshal(w3.Body.Bytes(), &customPayload); err != nil {
		t.Fatalf("failed to decode custom health payload: %v", err)
	}
	if customPayload["version"] != "v1.2.3" {
		t.Errorf("expected custom version 'v1.2.3', got %q", customPayload["version"])
	}
}

func TestDaemon_Auth(t *testing.T) {
	_, handler, validToken, cleanup := setupTestDaemon(t)
	defer cleanup()

	// 1. Missing auth
	req := newReq(http.MethodGet, "/api/v1/remotes", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
	}

	// 2. Wrong token
	req2 := newReq(http.MethodGet, "/api/v1/remotes", nil)
	req2.Header.Set("Authorization", "Bearer invalid-token-value")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid token, got %d", w2.Code)
	}

	// 3. Valid token
	req3 := newReq(http.MethodGet, "/api/v1/remotes", nil)
	req3.Header.Set("Authorization", "Bearer "+validToken)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid token, got %d", w3.Code)
	}
}

func TestDaemon_DNSRebindingAndCORS(t *testing.T) {
	_, handler, validToken, cleanup := setupTestDaemon(t)
	defer cleanup()

	// 1. Attacker Host Header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/remotes", nil)
	req.Host = "rebind.attacker.evil:8080"
	req.Header.Set("Authorization", "Bearer "+validToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for external host header, got %d", w.Code)
	}

	// 2. Cross-Origin Request
	req2 := newReq(http.MethodGet, "/api/v1/remotes", nil)
	req2.Header.Set("Origin", "https://attacker.site")
	req2.Header.Set("Authorization", "Bearer "+validToken)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-origin request, got %d", w2.Code)
	}
}

func TestDaemon_RemotesManagement(t *testing.T) {
	_, handler, token, cleanup := setupTestDaemon(t)
	defer cleanup()

	// 1. Create Remote
	newProfile := vault.RemoteProfile{
		Name:      "test-remote-s3",
		Type:      "s3",
		Bucket:    "my-test-bucket",
		AccessKey: "test-access",
		SecretKey: "test-secret",
	}
	body, _ := json.Marshal(newProfile)

	req := newReq(http.MethodPost, "/api/v1/remotes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d (body: %s)", w.Code, w.Body.String())
	}

	// 2. Get Remote
	reqGet := newReq(http.MethodGet, "/api/v1/remotes/test-remote-s3", nil)
	reqGet.Header.Set("Authorization", "Bearer "+token)
	wGet := httptest.NewRecorder()
	handler.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wGet.Code)
	}

	// 3. List Remotes
	reqList := newReq(http.MethodGet, "/api/v1/remotes", nil)
	reqList.Header.Set("Authorization", "Bearer "+token)
	wList := httptest.NewRecorder()
	handler.ServeHTTP(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wList.Code)
	}

	// 4. Delete Remote
	reqDel := newReq(http.MethodDelete, "/api/v1/remotes/test-remote-s3", nil)
	reqDel.Header.Set("Authorization", "Bearer "+token)
	wDel := httptest.NewRecorder()
	handler.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d", wDel.Code)
	}
}

func TestDaemon_StorageOperations(t *testing.T) {
	srv, handler, token, cleanup := setupTestDaemon(t)
	defer cleanup()

	// Register in-memory mock driver
	mockDrv := storage.NewMockDriver("mem-remote")
	srv.RegisterDriver("mem-remote", mockDrv)

	// 1. Upload Object (PUT)
	content := []byte("daemon storage stream content")
	reqPut := newReq(http.MethodPut, "/api/v1/storage/mem-remote/files/sample.txt", bytes.NewReader(content))
	reqPut.Header.Set("Authorization", "Bearer "+token)
	wPut := httptest.NewRecorder()
	handler.ServeHTTP(wPut, reqPut)
	if wPut.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on upload, got %d (body: %s)", wPut.Code, wPut.Body.String())
	}

	// 2. Stat Object (HEAD)
	reqHead := newReq(http.MethodHead, "/api/v1/storage/mem-remote/files/sample.txt", nil)
	reqHead.Header.Set("Authorization", "Bearer "+token)
	wHead := httptest.NewRecorder()
	handler.ServeHTTP(wHead, reqHead)
	if wHead.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on head, got %d", wHead.Code)
	}
	if wHead.Header().Get("Content-Length") != "29" {
		t.Fatalf("expected Content-Length 29, got %s", wHead.Header().Get("Content-Length"))
	}

	// 3. Download Object (GET)
	reqGet := newReq(http.MethodGet, "/api/v1/storage/mem-remote/files/sample.txt", nil)
	reqGet.Header.Set("Authorization", "Bearer "+token)
	wGet := httptest.NewRecorder()
	handler.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on download, got %d", wGet.Code)
	}
	resBody, _ := io.ReadAll(wGet.Body)
	if !bytes.Equal(resBody, content) {
		t.Fatalf("downloaded content mismatch: got %q, want %q", string(resBody), string(content))
	}

	// 4. List Objects (GET /objects)
	reqList := newReq(http.MethodGet, "/api/v1/storage/mem-remote/objects?prefix=files", nil)
	reqList.Header.Set("Authorization", "Bearer "+token)
	wList := httptest.NewRecorder()
	handler.ServeHTTP(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on listing, got %d", wList.Code)
	}

	// 5. Delete Object (DELETE)
	reqDel := newReq(http.MethodDelete, "/api/v1/storage/mem-remote/files/sample.txt", nil)
	reqDel.Header.Set("Authorization", "Bearer "+token)
	wDel := httptest.NewRecorder()
	handler.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content on delete, got %d", wDel.Code)
	}
}
