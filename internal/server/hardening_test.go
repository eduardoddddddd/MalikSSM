package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/malikssm/malik/internal/vault"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := vault.OpenStore(filepath.Join(t.TempDir(), "hardening.db"))
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.AllowAutoUnseal = false
	return New(store)
}

func do(srv *Server, method, path, remoteAddr, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestRemoteClientsCannotInitializeVault(t *testing.T) {
	srv := newTestServer(t)
	body := `{"passphrase":"Attacker-Chosen-Pass!"}`

	if rec := do(srv, http.MethodPost, "/v1/system/init", "192.168.1.66:50000", body, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("remote /v1/system/init: expected 403, got %d %s", rec.Code, rec.Body)
	}
	if rec := do(srv, http.MethodPost, "/v1/auth/login", "192.168.1.66:50000", body, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("remote auto-init via /v1/auth/login: expected 403, got %d %s", rec.Code, rec.Body)
	}
	// A request relayed by a local reverse proxy is not "local" either.
	if rec := do(srv, http.MethodPost, "/v1/system/init", "127.0.0.1:50000", body, map[string]string{"X-Forwarded-For": "203.0.113.9"}); rec.Code != http.StatusForbidden {
		t.Fatalf("proxied /v1/system/init: expected 403, got %d %s", rec.Code, rec.Body)
	}
	if srv.store.IsInitialized() {
		t.Fatalf("vault must remain uninitialized after remote attempts")
	}

	if rec := do(srv, http.MethodPost, "/v1/system/init", "127.0.0.1:50000", `{"passphrase":"Owner-Pass-2026!"}`, nil); rec.Code != http.StatusCreated {
		t.Fatalf("local init: expected 201, got %d %s", rec.Code, rec.Body)
	}
}

func TestInitAllowedFromServerOwnNonLoopbackIP(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/system/init", strings.NewReader(`{"passphrase":"Owner-Pass-2026!"}`))
	req.RemoteAddr = "100.64.0.5:51000"
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("100.64.0.5"), Port: 8443}))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("init from the server's own Tailscale IP: expected 201, got %d %s", rec.Code, rec.Body)
	}
}

func TestLoginLockoutAfterRepeatedFailures(t *testing.T) {
	srv := newTestServer(t)
	if rec := do(srv, http.MethodPost, "/v1/system/init", "127.0.0.1:1", `{"passphrase":"Owner-Pass-2026!"}`, nil); rec.Code != http.StatusCreated {
		t.Fatalf("init failed: %d %s", rec.Code, rec.Body)
	}

	attacker := "192.168.1.66:40000"
	for i := 0; i < maxPassphraseFailures; i++ {
		if rec := do(srv, http.MethodPost, "/v1/auth/login", attacker, `{"passphrase":"wrong-guess"}`, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}
	rec := do(srv, http.MethodPost, "/v1/auth/login", attacker, `{"passphrase":"Owner-Pass-2026!"}`, nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After after %d failures, got %d", maxPassphraseFailures, rec.Code)
	}

	// Other clients are not affected, and the lockout expires.
	if rec := do(srv, http.MethodPost, "/v1/auth/login", "192.168.1.10:40000", `{"passphrase":"Owner-Pass-2026!"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("legitimate client from another IP: expected 200, got %d %s", rec.Code, rec.Body)
	}
	srv.limiter.now = func() time.Time { return time.Now().Add(lockoutDuration + time.Minute) }
	if rec := do(srv, http.MethodPost, "/v1/auth/login", attacker, `{"passphrase":"Owner-Pass-2026!"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("after lockout expiry: expected 200, got %d %s", rec.Code, rec.Body)
	}
}

func TestNoCORSHeadersByDefault(t *testing.T) {
	srv := newTestServer(t)
	rec := do(srv, http.MethodGet, "/v1/system/status", "127.0.0.1:1", "", map[string]string{"Origin": "https://evil.example"})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no CORS header by default, got %q", got)
	}

	srv.CORSOrigin = "https://chat.openai.com"
	rec = do(srv, http.MethodGet, "/v1/system/status", "127.0.0.1:1", "", nil)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://chat.openai.com" {
		t.Fatalf("expected configured CORS origin, got %q", got)
	}
}

func TestForwardedForOnlyTrustedFromLocalProxy(t *testing.T) {
	spoofed := httptest.NewRequest(http.MethodGet, "/", nil)
	spoofed.RemoteAddr = "192.168.1.66:1234"
	spoofed.Header.Set("X-Forwarded-For", "10.0.0.1")
	if ip := extractClientIP(spoofed); ip != "192.168.1.66" {
		t.Fatalf("X-Forwarded-For from a remote peer must be ignored, got %s", ip)
	}

	proxied := httptest.NewRequest(http.MethodGet, "/", nil)
	proxied.RemoteAddr = "127.0.0.1:1234"
	proxied.Header.Set("X-Forwarded-For", "100.64.0.7")
	if ip := extractClientIP(proxied); ip != "100.64.0.7" {
		t.Fatalf("X-Forwarded-For from a local proxy should be used, got %s", ip)
	}
}

func TestQueryTokenOnlyAcceptedOnAuditStream(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/secrets?token=mlk_sess_abc", nil)
	if tok := extractToken(req); tok != "" {
		t.Fatalf("?token= must be ignored outside the SSE audit stream, got %q", tok)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/audit/stream?token=mlk_sess_abc", nil)
	if tok := extractToken(req); tok != "mlk_sess_abc" {
		t.Fatalf("?token= must be accepted on the SSE audit stream, got %q", tok)
	}
}
