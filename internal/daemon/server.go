package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
	"github.com/aboutdevz/unistorage/pkg/storage/s3"
	"github.com/aboutdevz/unistorage/pkg/vault"
)

// Config holds daemon server settings.
type Config struct {
	Addr            string
	TokenFile       string
	VaultPath       string
	VaultPassphrase string
	StaticToken     string
}

// Server is the UniStorage local daemon HTTP server.
type Server struct {
	cfg        Config
	token      string
	vault      vault.Vault
	drivers    map[string]storage.Driver
	mu         sync.RWMutex
	httpServer *http.Server
	listener   net.Listener
}

// DefaultConfig returns safe default configuration bound to loopback 127.0.0.1:8080.
func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	return Config{
		Addr:            "127.0.0.1:8080",
		TokenFile:       filepath.Join(home, ".unistorage", "daemon.token"),
		VaultPath:       filepath.Join(home, ".unistorage", "vault.enc"),
		VaultPassphrase: "unistorage-default-passphrase",
	}
}

// New creates and initializes a daemon Server.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}

	s := &Server{
		cfg:     cfg,
		drivers: make(map[string]storage.Driver),
	}

	// 1. Initialize Bearer Token
	if err := s.initToken(); err != nil {
		return nil, fmt.Errorf("daemon token init error: %w", err)
	}

	// 2. Initialize Vault
	if cfg.VaultPath != "" {
		s.vault = vault.New(cfg.VaultPath)
	}

	return s, nil
}

// Token returns the active bearer token for this daemon instance.
func (s *Server) Token() string {
	return s.token
}

// RegisterDriver registers a storage driver under a remote name.
func (s *Server) RegisterDriver(name string, driver storage.Driver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drivers[name] = driver
}

// GetDriver returns the driver for the given remote name.
func (s *Server) GetDriver(name string) (storage.Driver, error) {
	s.mu.RLock()
	d, ok := s.drivers[name]
	s.mu.RUnlock()
	if ok {
		return d, nil
	}

	// Attempt to load from vault if available
	if s.vault != nil && s.cfg.VaultPassphrase != "" {
		prof, err := s.vault.GetRemote(s.cfg.VaultPassphrase, name)
		if err == nil && prof != nil {
			var created storage.Driver
			switch prof.Type {
			case "local":
				created, err = local.New(prof.Path)
			case "s3":
				created, err = s3.New(context.Background(), s3.Config{
					Endpoint:  prof.Endpoint,
					Region:    prof.Region,
					Bucket:    prof.Bucket,
					AccessKey: prof.AccessKey,
					SecretKey: prof.SecretKey,
				})
			default:
				return nil, fmt.Errorf("unknown driver type %q", prof.Type)
			}
			if err != nil {
				return nil, fmt.Errorf("failed to instantiate remote driver %q: %w", name, err)
			}
			s.RegisterDriver(name, created)
			return created, nil
		}
	}

	return nil, fmt.Errorf("remote %q not found", name)
}

// initToken loads or generates a 256-bit CSPRNG bearer token stored with 0600 permissions.
func (s *Server) initToken() error {
	if s.cfg.StaticToken != "" {
		s.token = s.cfg.StaticToken
		return nil
	}

	if s.cfg.TokenFile == "" {
		return errors.New("daemon: token file path is required")
	}

	// If token file exists, load it
	if data, err := os.ReadFile(s.cfg.TokenFile); err == nil {
		tok := strings.TrimSpace(string(data))
		if len(tok) >= 32 {
			s.token = tok
			return nil
		}
	}

	// Generate 32 bytes (256 bits) of CSPRNG entropy
	var tokenBytes [32]byte
	if _, err := io.ReadFull(rand.Reader, tokenBytes[:]); err != nil {
		return fmt.Errorf("failed to generate random token: %w", err)
	}
	s.token = hex.EncodeToString(tokenBytes[:])

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(s.cfg.TokenFile), 0700); err != nil {
		return fmt.Errorf("failed to create token dir: %w", err)
	}

	// Write token file with strict 0600 permissions
	if err := os.WriteFile(s.cfg.TokenFile, []byte(s.token+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// Start binds to the configured loopback address and serves HTTP requests.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("failed to bind daemon on %s: %w", s.cfg.Addr, err)
	}
	s.listener = ln
	s.httpServer = &http.Server{
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Minute, // Allow large streaming transfers
		IdleTimeout:  60 * time.Second,
	}

	return s.httpServer.Serve(ln)
}

// Stop gracefully stops the server.
func (s *Server) Stop(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Addr returns the bound listener address.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.Addr
}

// Handler builds and returns the hardened HTTP handler with security middlewares.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public Health Endpoints
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Remote Profile Management Endpoints
	mux.HandleFunc("GET /api/v1/remotes", s.handleListRemotes)
	mux.HandleFunc("POST /api/v1/remotes", s.handleCreateRemote)
	mux.HandleFunc("GET /api/v1/remotes/{name}", s.handleGetRemote)
	mux.HandleFunc("DELETE /api/v1/remotes/{name}", s.handleDeleteRemote)

	// Storage CRUD & Streaming Endpoints
	mux.HandleFunc("GET /api/v1/storage/", s.handleStorageGet)
	mux.HandleFunc("PUT /api/v1/storage/", s.handleStoragePut)
	mux.HandleFunc("DELETE /api/v1/storage/", s.handleStorageDelete)
	mux.HandleFunc("HEAD /api/v1/storage/", s.handleStorageHead)

	// Wrap with security middleware
	return s.securityMiddleware(mux)
}

// securityMiddleware enforces:
// 1. Strict Host header validation (blocks DNS rebinding).
// 2. Strict CORS origin denial (blocks cross-origin browser drive-bys).
// 3. Bearer token authentication with constant-time comparison.
func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Host Header Validation
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		switch host {
		case "127.0.0.1", "localhost", "::1":
			// Loopback allowed
		default:
			s.writeJSONError(w, http.StatusForbidden, "forbidden", "dns-rebinding protection: invalid host header")
			return
		}

		// 2. CORS Origin Denial
		if origin := r.Header.Get("Origin"); origin != "" {
			s.writeJSONError(w, http.StatusForbidden, "forbidden", "cors origin denied")
			return
		}

		// 3. Authentication Check
		// Exempt health endpoints
		if r.URL.Path == "/healthz" || r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			s.writeJSONError(w, http.StatusUnauthorized, "unauthorized", "valid bearer token required in authorization header")
			return
		}

		givenToken := strings.TrimPrefix(authHeader, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(givenToken), []byte(s.token)) != 1 {
			s.writeJSONError(w, http.StatusUnauthorized, "unauthorized", "valid bearer token required in authorization header")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) writeJSONError(w http.ResponseWriter, statusCode int, errType string, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   errType,
		"message": message,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": "0.1.0",
	})
}

func (s *Server) handleListRemotes(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", "vault not initialized")
		return
	}

	names, err := s.vault.ListRemotes(s.cfg.VaultPassphrase)
	if err != nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	var remotes []vault.RemoteProfile
	for _, name := range names {
		prof, err := s.vault.GetRemote(s.cfg.VaultPassphrase, name)
		if err == nil && prof != nil {
			// Redact secret keys for listing safety
			safeProf := *prof
			if safeProf.SecretKey != "" {
				safeProf.SecretKey = "********"
			}
			remotes = append(remotes, safeProf)
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"remotes": remotes})
}

func (s *Server) handleCreateRemote(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", "vault not initialized")
		return
	}

	var prof vault.RemoteProfile
	if err := json.NewDecoder(r.Body).Decode(&prof); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "bad_request", "invalid JSON payload")
		return
	}
	if prof.Name == "" || prof.Type == "" {
		s.writeJSONError(w, http.StatusBadRequest, "bad_request", "name and type are required")
		return
	}

	if err := s.vault.SaveRemote(s.cfg.VaultPassphrase, prof); err != nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]string{
		"status": "created",
		"name":   prof.Name,
	})
}

func (s *Server) handleGetRemote(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", "vault not initialized")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		s.writeJSONError(w, http.StatusBadRequest, "bad_request", "remote name required")
		return
	}

	prof, err := s.vault.GetRemote(s.cfg.VaultPassphrase, name)
	if err != nil {
		if errors.Is(err, vault.ErrRemoteNotFound) {
			s.writeJSONError(w, http.StatusNotFound, "not_found", "remote profile not found")
			return
		}
		s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, prof)
}

func (s *Server) handleDeleteRemote(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", "vault not initialized")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		s.writeJSONError(w, http.StatusBadRequest, "bad_request", "remote name required")
		return
	}

	if err := s.vault.DeleteRemote(s.cfg.VaultPassphrase, name); err != nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	s.mu.Lock()
	delete(s.drivers, name)
	s.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// parseStoragePath extracts remote name and internal object path from /api/v1/storage/{remote}/...
func parseStoragePath(fullURLPath string) (remote string, objPath string, isList bool) {
	trimmed := strings.TrimPrefix(fullURLPath, "/api/v1/storage/")
	parts := strings.SplitN(trimmed, "/", 2)
	remote = parts[0]
	if len(parts) > 1 {
		objPath = parts[1]
	}

	// Check if this is the objects listing endpoint
	if objPath == "objects" || objPath == "objects/" {
		return remote, "", true
	}
	if strings.HasPrefix(objPath, "objects/") {
		objPath = strings.TrimPrefix(objPath, "objects/")
	}
	return remote, objPath, false
}

func (s *Server) handleStorageGet(w http.ResponseWriter, r *http.Request) {
	remote, objPath, isList := parseStoragePath(r.URL.Path)
	drv, err := s.GetDriver(remote)
	if err != nil {
		s.writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	if isList {
		prefix := r.URL.Query().Get("prefix")
		recursive := r.URL.Query().Get("recursive") != "false"
		maxKeys, _ := strconv.Atoi(r.URL.Query().Get("max_keys"))
		token := r.URL.Query().Get("token")

		if adv, ok := drv.(storage.AdvancedDriver); ok {
			res, err := adv.ListWithOptions(r.Context(), storage.ListOptions{
				Prefix:            prefix,
				Recursive:         recursive,
				MaxKeys:           maxKeys,
				ContinuationToken: token,
			})
			if err != nil {
				s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
				return
			}
			s.writeJSON(w, http.StatusOK, res)
			return
		}

		objs, err := drv.List(r.Context(), prefix)
		if err != nil {
			s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"objects": objs})
		return
	}

	// Stream object download
	info, err := drv.Stat(r.Context(), objPath)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.writeJSONError(w, http.StatusNotFound, "not_found", "object not found")
			return
		}
		s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	if info.ETag != "" {
		w.Header().Set("ETag", `"`+info.ETag+`"`)
	}
	w.Header().Set("Last-Modified", info.ModTime.UTC().Format(http.TimeFormat))

	if err := drv.Stream(r.Context(), objPath, w); err != nil {
		// If error occurs mid-stream, header already sent; log and return
		return
	}
}

func (s *Server) handleStoragePut(w http.ResponseWriter, r *http.Request) {
	remote, objPath, _ := parseStoragePath(r.URL.Path)
	drv, err := s.GetDriver(remote)
	if err != nil {
		s.writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	size := r.ContentLength
	err = drv.Write(r.Context(), objPath, r.Body, size)
	if err != nil {
		if errors.Is(err, storage.ErrPathTraversal) || errors.Is(err, storage.ErrInvalidPath) {
			s.writeJSONError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"status": "uploaded",
		"size":   size,
		"path":   objPath,
	})
}

func (s *Server) handleStorageDelete(w http.ResponseWriter, r *http.Request) {
	remote, objPath, _ := parseStoragePath(r.URL.Path)
	drv, err := s.GetDriver(remote)
	if err != nil {
		s.writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	if err := drv.Delete(r.Context(), objPath); err != nil {
		s.writeJSONError(w, http.StatusInternalServerError, "error", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStorageHead(w http.ResponseWriter, r *http.Request) {
	remote, objPath, _ := parseStoragePath(r.URL.Path)
	drv, err := s.GetDriver(remote)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	info, err := drv.Stat(r.Context(), objPath)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	if info.ETag != "" {
		w.Header().Set("ETag", `"`+info.ETag+`"`)
	}
	w.Header().Set("Last-Modified", info.ModTime.UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
}
