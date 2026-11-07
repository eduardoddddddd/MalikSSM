package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/malikssm/malik/internal/vault"
)

type ctxKey int

const callerCtxKey ctxKey = 1

// Server wraps the Vault Store and exposes REST v1, AWS Secrets Manager emulation,
// OpenAPI 3.1.0 for ChatGPT Actions, and the embedded Web UI.
type Server struct {
	store   *vault.Store
	mux     *http.ServeMux
	limiter *authLimiter

	// CORSOrigin enables cross-origin browser access for exactly this origin. Empty (the default)
	// sends no CORS headers: the embedded UI is same-origin and CLI/SDK/boto3/ChatGPT clients do not need CORS.
	CORSOrigin string
}

// New constructs and wires a new MalikSSM HTTP server.
func New(store *vault.Store) *Server {
	s := &Server{
		store:   store,
		mux:     http.NewServeMux(),
		limiter: newAuthLimiter(),
	}
	s.registerRoutes()
	return s
}

// ServeHTTP implements http.Handler with CORS, security headers, and AWS protocol routing.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.CORSOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", s.CORSOrigin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Malik-Token, X-Malik-Agent, X-Amz-Target, X-Amz-Date, X-Amz-Security-Token")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// AWS Secrets Manager Boto3 / CLI Emulation:
	// AWS SDKs send POST / with header X-Amz-Target: secretsmanager.<Operation>
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.") {
		s.requireAuth(s.handleAWSRequest)(w, r)
		return
	}

	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	// Embedded Web UI
	s.mux.HandleFunc("GET /", s.handleRootOrUI)
	s.mux.HandleFunc("GET /ui", s.handleRootOrUI)

	// OpenAPI 3.1 for ChatGPT Actions
	s.mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)

	// Public System & Auth Endpoints
	s.mux.HandleFunc("GET /v1/system/status", s.handleStatus)
	s.mux.HandleFunc("POST /v1/system/init", s.handleInit)
	s.mux.HandleFunc("POST /v1/system/unlock", s.handleUnlock)
	s.mux.HandleFunc("POST /v1/auth/login", s.handleLogin)

	// Authenticated Vault Endpoints
	s.mux.HandleFunc("POST /v1/system/lock", s.requireAuth(s.handleLock))
	s.mux.HandleFunc("GET /v1/secrets", s.requireAuth(s.handleListSecrets))
	s.mux.HandleFunc("POST /v1/secrets", s.requireAuth(s.handlePutSecretBody))
	s.mux.HandleFunc("GET /v1/search", s.requireAuth(s.handleSearchSecrets))
	s.mux.HandleFunc("GET /v1/secrets/{path...}", s.requireAuth(s.handleGetSecret))
	s.mux.HandleFunc("PUT /v1/secrets/{path...}", s.requireAuth(s.handlePutSecretPath))
	s.mux.HandleFunc("DELETE /v1/secrets/{path...}", s.requireAuth(s.handleDeleteSecret))
	s.mux.HandleFunc("GET /v1/totp/{path...}", s.requireAuth(s.handleGetTOTP))

	// App Tokens & Audit
	s.mux.HandleFunc("GET /v1/tokens", s.requireAuth(s.handleListTokens))
	s.mux.HandleFunc("POST /v1/tokens", s.requireAuth(s.handleCreateToken))
	s.mux.HandleFunc("DELETE /v1/tokens/{id}", s.requireAuth(s.handleRevokeToken))
	s.mux.HandleFunc("GET /v1/audit", s.requireAuth(s.handleListAudit))
	s.mux.HandleFunc("GET /v1/audit/stream", s.requireAuth(s.handleAuditStream))
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken := extractToken(r)
		agent := strings.TrimSpace(r.Header.Get("X-Malik-Agent"))
		if agent == "" {
			ua := r.Header.Get("User-Agent")
			switch {
			case strings.Contains(strings.ToLower(ua), "boto3") || strings.Contains(strings.ToLower(ua), "aws-cli"):
				agent = "aws-boto3"
			case strings.Contains(strings.ToLower(ua), "chatgpt") || strings.Contains(strings.ToLower(ua), "openai"):
				agent = "chatgpt"
			case strings.Contains(strings.ToLower(ua), "mozilla"):
				agent = "web-ui"
			default:
				agent = "api-client"
			}
		}

		clientIP := extractClientIP(r)
		caller, err := s.store.AuthenticateToken(rawToken, agent, clientIP)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized: invalid or expired session/token. Run 'malik login' or pass a valid App Token.")
			return
		}

		ctx := context.WithValue(r.Context(), callerCtxKey, caller)
		next(w, r.WithContext(ctx))
	}
}

func getCaller(r *http.Request) *vault.CallerIdentity {
	if v, ok := r.Context().Value(callerCtxKey).(*vault.CallerIdentity); ok {
		return v
	}
	return nil
}

func extractToken(r *http.Request) string {
	if tok := strings.TrimSpace(r.Header.Get("X-Malik-Token")); tok != "" {
		return tok
	}
	if secTok := strings.TrimSpace(r.Header.Get("X-Amz-Security-Token")); strings.HasPrefix(secTok, "mlk_") {
		return secTok
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	// Support AWS SigV4 Credential=<mlk_token>/20261106/... so boto3 works with aws_access_key_id="mlk_..."
	if strings.Contains(auth, "Credential=") {
		parts := strings.SplitAfter(auth, "Credential=")
		if len(parts) > 1 {
			cred := strings.Split(parts[1], "/")[0]
			if strings.HasPrefix(cred, "mlk_") {
				return cred
			}
		}
	}
	if strings.HasPrefix(auth, "mlk_") {
		return auth
	}
	// EventSource cannot send headers, so the SSE audit stream is the only route that accepts ?token=
	// (tokens in URLs end up in proxy logs and browser history).
	if r.URL.Path == "/v1/audit/stream" {
		if qTok := strings.TrimSpace(r.URL.Query().Get("token")); qTok != "" {
			return qTok
		}
	}
	return ""
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isLocalRequest is true only for requests made on the server itself (not relayed by a local reverse
// proxy): either over loopback, or to the server's own non-loopback listen IP (e.g. a Tailscale-only bind)
// from that same IP.
func isLocalRequest(r *http.Request) bool {
	if r.Header.Get("X-Forwarded-For") != "" {
		return false
	}
	peer := remoteHost(r)
	if isLoopbackHost(peer) {
		return true
	}
	if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && local != nil {
		if localHost, _, err := net.SplitHostPort(local.String()); err == nil {
			peerIP, localIP := net.ParseIP(peer), net.ParseIP(localHost)
			return peerIP != nil && localIP != nil && peerIP.Equal(localIP)
		}
	}
	return false
}

// extractClientIP returns the TCP peer address. X-Forwarded-For is honoured only when the peer is a
// reverse proxy on the same host; otherwise any client could spoof the IP recorded in the audit log.
func extractClientIP(r *http.Request) string {
	host := remoteHost(r)
	if isLoopbackHost(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"error":  msg,
		"status": status,
	})
}
