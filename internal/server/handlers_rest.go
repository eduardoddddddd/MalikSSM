package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/malikssm/malik/internal/security"
	"github.com/malikssm/malik/internal/vault"
)

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Status())
}

func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
		AutoUnseal *bool  `json:"auto_unseal"`
		ClientHost string `json:"client_host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	autoUnseal := true
	if req.AutoUnseal != nil {
		autoUnseal = *req.AutoUnseal
	}

	if err := s.store.InitVault(req.Passphrase, autoUnseal); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	host := req.ClientHost
	if host == "" {
		host = "Win-Server-Setup"
	}
	token, sess, err := s.store.CreateSession(req.Passphrase, host, "setup", extractClientIP(r), 24*time.Hour)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status":     "initialized",
		"token":      token,
		"expires_at": sess.ExpiresAt,
		"vault":      s.store.Status(),
	})
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
		AutoUnseal bool   `json:"auto_unseal"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.store.Unlock(req.Passphrase, req.AutoUnseal, extractClientIP(r)); err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.store.Status())
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RevokeSessions   bool `json:"revoke_sessions"`
		RemoveAutoUnseal bool `json:"remove_auto_unseal"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	caller := getCaller(r)
	if !caller.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "only admin sessions can lock the vault")
		return
	}
	if err := s.store.Lock(req.RevokeSessions, req.RemoveAutoUnseal, caller); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.store.Status())
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
		ClientHost string `json:"client_host"`
		AgentName  string `json:"agent_name"`
		TTLHours   int    `json:"ttl_hours"`
		TTLDays    int    `json:"ttl_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// If vault is not yet initialized, auto-initialize on first login for frictionless onboarding
	if !s.store.IsInitialized() {
		if err := s.store.InitVault(req.Passphrase, true); err != nil {
			writeJSONError(w, http.StatusBadRequest, "vault not initialized and auto-init failed: "+err.Error())
			return
		}
	}

	ttl := 12 * time.Hour
	if req.TTLDays > 0 {
		ttl = time.Duration(req.TTLDays) * 24 * time.Hour
	} else if req.TTLHours > 0 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}

	host := strings.TrimSpace(req.ClientHost)
	if host == "" {
		host = "Workstation"
	}
	agent := strings.TrimSpace(req.AgentName)
	if agent == "" {
		agent = "malik-cli"
	}

	token, sess, err := s.store.CreateSession(req.Passphrase, host, agent, extractClientIP(r), ttl)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":       token,
		"session_id":  sess.ID,
		"client_host": sess.ClientHost,
		"expires_at":  sess.ExpiresAt,
		"vault":       s.store.Status(),
	})
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	prefix := r.URL.Query().Get("prefix")
	items, err := s.store.ListSecrets(caller, prefix)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []vault.SecretMetadata{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(items),
		"secrets": items,
	})
}

func (s *Server) handleSearchSecrets(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	q := r.URL.Query().Get("q")
	if q == "" {
		q = r.URL.Query().Get("query")
	}
	var tags []string
	if rawTags := r.URL.Query().Get("tags"); rawTags != "" {
		tags = strings.Split(rawTags, ",")
	}
	hits, err := s.store.SearchSecrets(caller, q, tags)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hits == nil {
		hits = []vault.SearchResult{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"query":   q,
		"count":   len(hits),
		"results": hits,
	})
}

func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	secPath := r.PathValue("path")
	ver, _ := strconv.Atoi(r.URL.Query().Get("version"))
	stage := r.URL.Query().Get("stage")
	field := strings.TrimSpace(r.URL.Query().Get("field"))

	sec, err := s.store.GetSecret(caller, secPath, ver, stage)
	if err != nil {
		switch err {
		case vault.ErrSecretNotFound:
			writeJSONError(w, http.StatusNotFound, err.Error())
		case vault.ErrAccessDenied:
			writeJSONError(w, http.StatusForbidden, err.Error())
		case security.ErrVaultLocked:
			writeJSONError(w, http.StatusLocked, err.Error())
		default:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	if field != "" {
		val, ok := sec.Data[field]
		if !ok {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("field %q not found in secret %q (available fields: %v)", field, sec.Path, sec.SchemaKeys))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"path":    sec.Path,
			"field":   field,
			"value":   val,
			"version": sec.Version,
		})
		return
	}

	writeJSON(w, http.StatusOK, sec)
}

func (s *Server) handlePutSecretBody(w http.ResponseWriter, r *http.Request) {
	var in vault.PutSecretInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.doPutSecret(w, r, in)
}

func (s *Server) handlePutSecretPath(w http.ResponseWriter, r *http.Request) {
	var in vault.PutSecretInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in.Path = r.PathValue("path")
	s.doPutSecret(w, r, in)
}

func (s *Server) doPutSecret(w http.ResponseWriter, r *http.Request, in vault.PutSecretInput) {
	caller := getCaller(r)
	meta, err := s.store.PutSecret(caller, in)
	if err != nil {
		switch err {
		case vault.ErrAccessDenied:
			writeJSONError(w, http.StatusForbidden, err.Error())
		case security.ErrVaultLocked:
			writeJSONError(w, http.StatusLocked, err.Error())
		default:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	secPath := r.PathValue("path")
	if err := s.store.DeleteSecret(caller, secPath); err != nil {
		switch err {
		case vault.ErrSecretNotFound:
			writeJSONError(w, http.StatusNotFound, err.Error())
		case vault.ErrAccessDenied:
			writeJSONError(w, http.StatusForbidden, err.Error())
		default:
			writeJSONError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": vault.NormalizePath(secPath)})
}

func (s *Server) handleGetTOTP(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	secPath := r.PathValue("path")
	res, err := s.store.GenerateTOTP(caller, secPath)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":              vault.NormalizePath(secPath),
		"code":              res.Code,
		"period":            res.Period,
		"seconds_remaining": res.SecondsRemaining,
		"digits":            res.Digits,
		"algorithm":         res.Algorithm,
	})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	if !caller.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "only admin sessions can list app tokens")
		return
	}
	list, err := s.store.ListAppTokens()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if list == nil {
		list = []vault.AppToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": list})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	var req struct {
		Name          string   `json:"name"`
		AllowedScopes []string `json:"allowed_scopes"`
		Permissions   []string `json:"permissions"`
		TTLDays       int      `json:"ttl_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var ttl time.Duration
	if req.TTLDays > 0 {
		ttl = time.Duration(req.TTLDays) * 24 * time.Hour
	}

	rawTok, meta, err := s.store.CreateAppToken(caller, req.Name, req.AllowedScopes, req.Permissions, ttl)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":    rawTok,
		"metadata": meta,
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	id := r.PathValue("id")
	if err := s.store.RevokeAppToken(caller, id); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	if !caller.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "only admin sessions can view full audit logs")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.store.ListAudit(limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []vault.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) handleAuditStream(w http.ResponseWriter, r *http.Request) {
	caller := getCaller(r)
	if !caller.IsAdmin {
		writeJSONError(w, http.StatusForbidden, "only admin sessions can subscribe to audit stream")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := s.store.SubscribeAudit()
	defer unsub()

	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-ch:
			raw, _ := json.Marshal(entry)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(raw))
			flusher.Flush()
		}
	}
}
