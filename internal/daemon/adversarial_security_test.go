package daemon_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aboutdevz/unistorage/internal/daemon"
)

func setupAdversarialDaemon(t *testing.T) (http.Handler, string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "unistorage-adversarial-daemon-*")
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

	return srv.Handler(), srv.Token(), cleanup
}

// TestAdversarial_DNSRebinding verifies that any non-loopback Host header is rejected with HTTP 403 Forbidden.
func TestAdversarial_DNSRebinding(t *testing.T) {
	handler, validToken, cleanup := setupAdversarialDaemon(t)
	defer cleanup()

	forgedHosts := []string{
		"evil.com",
		"evil.com:8080",
		"attacker.com:8080",
		"sub.localhost.attacker.com",
		"sub.localhost.attacker.com:8080",
		"localhost.attacker.com",
		"attacker.localhost.com",
		"127.0.0.1.attacker.com",
		"127.0.0.2",
		"0.0.0.0",
		"0.0.0.0:8080",
		"192.168.1.1",
		"10.0.0.1:8080",
		"example.com",
		"",
		"[::2]",
		"[::2]:8080",
		"attacker.com:9999",
	}

	endpoints := []struct {
		method    string
		path      string
		withToken bool
	}{
		{http.MethodGet, "/api/v1/remotes", true},
		{http.MethodGet, "/healthz", false},
		{http.MethodGet, "/api/v1/health", false},
		{http.MethodPost, "/api/v1/remotes", true},
	}

	for _, ep := range endpoints {
		for _, host := range forgedHosts {
			testName := fmt.Sprintf("%s_%s_Host=%s", ep.method, ep.path, host)
			t.Run(testName, func(t *testing.T) {
				req := httptest.NewRequest(ep.method, ep.path, nil)
				req.Host = host
				if ep.withToken {
					req.Header.Set("Authorization", "Bearer "+validToken)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				if w.Code != http.StatusForbidden {
					t.Errorf("Host %q against %s %s: expected HTTP 403 Forbidden, got %d (body: %s)",
						host, ep.method, ep.path, w.Code, w.Body.String())
				}
			})
		}
	}
}

// TestAdversarial_ValidHosts verifies that legitimate loopback Host headers are accepted.
func TestAdversarial_ValidHosts(t *testing.T) {
	handler, validToken, cleanup := setupAdversarialDaemon(t)
	defer cleanup()

	validHosts := []string{
		"127.0.0.1:8080",
		"127.0.0.1",
		"localhost:8080",
		"localhost",
		"[::1]:8080",
		"[::1]",
		"::1",
	}

	for _, host := range validHosts {
		t.Run("ValidHost="+host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/remotes", nil)
			req.Host = host
			req.Header.Set("Authorization", "Bearer "+validToken)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Valid Host %q: expected HTTP 200 OK, got %d (body: %s)", host, w.Code, w.Body.String())
			}
		})
	}
}

// TestAdversarial_CORSOriginDenial verifies that any Origin header triggers HTTP 403 Forbidden.
func TestAdversarial_CORSOriginDenial(t *testing.T) {
	handler, validToken, cleanup := setupAdversarialDaemon(t)
	defer cleanup()

	maliciousOrigins := []string{
		"http://evil.com",
		"https://evil.com",
		"http://attacker.com:8080",
		"http://sub.localhost.attacker.com",
		"null",
		"http://localhost:3000",
		"http://127.0.0.1:8080",
		"https://127.0.0.1:8080",
		"file://",
		"chrome-extension://abcdefghijklmnop",
	}

	for _, origin := range maliciousOrigins {
		// Scenario 1: With valid Bearer token
		t.Run("ValidToken_Origin="+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/remotes", nil)
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Origin", origin)
			req.Header.Set("Authorization", "Bearer "+validToken)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Origin %q with valid token: expected HTTP 403 Forbidden, got %d (body: %s)",
					origin, w.Code, w.Body.String())
			}
		})

		// Scenario 2: Without Bearer token
		t.Run("NoToken_Origin="+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/remotes", nil)
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Origin %q without token: expected HTTP 403 Forbidden, got %d (body: %s)",
					origin, w.Code, w.Body.String())
			}
		})

		// Scenario 3: Preflight OPTIONS request
		t.Run("Preflight_OPTIONS_Origin="+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/api/v1/remotes", nil)
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Origin", origin)
			req.Header.Set("Access-Control-Request-Method", "POST")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Preflight OPTIONS Origin %q: expected HTTP 403 Forbidden, got %d (body: %s)",
					origin, w.Code, w.Body.String())
			}
		})

		// Scenario 4: Health endpoint with Origin
		t.Run("Health_Origin="+origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("Health endpoint with Origin %q: expected HTTP 403 Forbidden, got %d (body: %s)",
					origin, w.Code, w.Body.String())
			}
		})
	}
}

// TestAdversarial_CombinedHostAndOrigin verifies defense when both Host and Origin are forged.
func TestAdversarial_CombinedHostAndOrigin(t *testing.T) {
	handler, validToken, cleanup := setupAdversarialDaemon(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/remotes", nil)
	req.Host = "evil.com"
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Authorization", "Bearer "+validToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for forged host + origin, got %d", w.Code)
	}
}
