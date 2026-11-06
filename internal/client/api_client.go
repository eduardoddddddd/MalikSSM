package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/malikssm/malik/internal/totp"
	"github.com/malikssm/malik/internal/vault"
)

// Client is the HTTP client used by the CLI, MCP server, and process injector.
type Client struct {
	ServerURL string
	Token     string
	AgentName string
	HTTP      *http.Client
}

// New creates a new MalikSSM API client using automatic DPAPI session resolution.
func New(overrideServer, overrideToken, agentName string) *Client {
	srv, tok := ResolveConnection(overrideServer, overrideToken)
	if agentName == "" {
		agentName = "malik-cli"
	}
	return &Client{
		ServerURL: srv,
		Token:     tok,
		AgentName: agentName,
		HTTP: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *Client) doJSON(method, endpoint string, reqBody any, respOut any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, c.ServerURL+endpoint, bodyReader)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("X-Malik-Agent", c.AgentName)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to MalikSSM server at %s: %w", c.ServerURL, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		var errObj struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBytes, &errObj) == nil && errObj.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", errObj.Error, resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	if respOut != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, respOut); err != nil {
			return fmt.Errorf("failed to decode server response: %w", err)
		}
	}
	return nil
}

// Status queries the server's vault status.
func (c *Client) Status() (*vault.VaultStatus, error) {
	var st vault.VaultStatus
	if err := c.doJSON(http.MethodGet, "/v1/system/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Login authenticates with the master passphrase and saves the session to local Windows DPAPI storage.
func (c *Client) Login(passphrase string, ttlHours int, ttlDays int) (*LocalSession, error) {
	host, _ := os.Hostname()
	if host == "" {
		host = "Workstation"
	}

	var resp struct {
		Token      string            `json:"token"`
		SessionID  string            `json:"session_id"`
		ClientHost string            `json:"client_host"`
		ExpiresAt  time.Time         `json:"expires_at"`
		Vault      vault.VaultStatus `json:"vault"`
	}
	err := c.doJSON(http.MethodPost, "/v1/auth/login", map[string]any{
		"passphrase":  passphrase,
		"client_host": host,
		"agent_name":  c.AgentName,
		"ttl_hours":   ttlHours,
		"ttl_days":    ttlDays,
	}, &resp)
	if err != nil {
		return nil, err
	}

	c.Token = resp.Token
	sess := &LocalSession{
		ServerURL:  c.ServerURL,
		Token:      resp.Token,
		SessionID:  resp.SessionID,
		ClientHost: resp.ClientHost,
		ExpiresAt:  resp.ExpiresAt,
	}
	if err := SaveLocalSession(sess); err != nil {
		return nil, fmt.Errorf("logged in, but failed to save DPAPI session cache: %w", err)
	}
	return sess, nil
}

// Lock triggers the Panic Lock on the server.
func (c *Client) Lock(revokeSessions bool) (*vault.VaultStatus, error) {
	var st vault.VaultStatus
	err := c.doJSON(http.MethodPost, "/v1/system/lock", map[string]any{
		"revoke_sessions": revokeSessions,
	}, &st)
	return &st, err
}

// Unlock unlocks the server vault with the master passphrase.
func (c *Client) Unlock(passphrase string, autoUnseal bool) (*vault.VaultStatus, error) {
	var st vault.VaultStatus
	err := c.doJSON(http.MethodPost, "/v1/system/unlock", map[string]any{
		"passphrase":  passphrase,
		"auto_unseal": autoUnseal,
	}, &st)
	return &st, err
}

// ListSecrets returns all secrets metadata (optionally filtered by prefix).
func (c *Client) ListSecrets(prefix string) ([]vault.SecretMetadata, error) {
	var resp struct {
		Secrets []vault.SecretMetadata `json:"secrets"`
	}
	ep := "/v1/secrets"
	if prefix != "" {
		ep += "?prefix=" + url.QueryEscape(prefix)
	}
	if err := c.doJSON(http.MethodGet, ep, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Secrets, nil
}

// SearchSecrets runs a semantic/fuzzy search across path, tags, description, and schema_keys.
func (c *Client) SearchSecrets(query string, tags []string) ([]vault.SearchResult, error) {
	var resp struct {
		Results []vault.SearchResult `json:"results"`
	}
	q := url.Values{}
	if query != "" {
		q.Set("q", query)
	}
	if len(tags) > 0 {
		q.Set("tags", strings.Join(tags, ","))
	}
	if err := c.doJSON(http.MethodGet, "/v1/search?"+q.Encode(), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Results, nil
}

// GetSecret fetches and decrypts a secret by path, optional version, or stage.
func (c *Client) GetSecret(secPath string, version int, stage string) (*vault.DecryptedSecret, error) {
	var sec vault.DecryptedSecret
	norm := vault.NormalizePath(secPath)
	q := url.Values{}
	if version > 0 {
		q.Set("version", fmt.Sprintf("%d", version))
	}
	if stage != "" {
		q.Set("stage", stage)
	}
	ep := "/v1/secrets/" + norm
	if enc := q.Encode(); enc != "" {
		ep += "?" + enc
	}
	if err := c.doJSON(http.MethodGet, ep, nil, &sec); err != nil {
		return nil, err
	}
	return &sec, nil
}

// PutSecret creates or updates a secret.
func (c *Client) PutSecret(in vault.PutSecretInput) (*vault.SecretMetadata, error) {
	var meta vault.SecretMetadata
	if err := c.doJSON(http.MethodPost, "/v1/secrets", in, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// DeleteSecret deletes a secret by path.
func (c *Client) DeleteSecret(secPath string) error {
	norm := vault.NormalizePath(secPath)
	return c.doJSON(http.MethodDelete, "/v1/secrets/"+norm, nil, nil)
}

// GetTOTP generates a live 6-digit 2FA code for the given secret path.
func (c *Client) GetTOTP(secPath string) (*totp.Result, error) {
	var res totp.Result
	norm := vault.NormalizePath(secPath)
	if err := c.doJSON(http.MethodGet, "/v1/totp/"+norm, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// CreateAppToken creates a scoped machine/application token (`mlk_live_...`).
func (c *Client) CreateAppToken(name string, scopes []string, perms []string, ttlDays int) (string, *vault.AppToken, error) {
	var resp struct {
		Token    string         `json:"token"`
		Metadata vault.AppToken `json:"metadata"`
	}
	err := c.doJSON(http.MethodPost, "/v1/tokens", map[string]any{
		"name":           name,
		"allowed_scopes": scopes,
		"permissions":    perms,
		"ttl_days":       ttlDays,
	}, &resp)
	if err != nil {
		return "", nil, err
	}
	return resp.Token, &resp.Metadata, nil
}

// ListAppTokens lists all machine tokens.
func (c *Client) ListAppTokens() ([]vault.AppToken, error) {
	var resp struct {
		Tokens []vault.AppToken `json:"tokens"`
	}
	if err := c.doJSON(http.MethodGet, "/v1/tokens", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Tokens, nil
}

// RevokeAppToken revokes a machine token by ID.
func (c *Client) RevokeAppToken(id string) error {
	return c.doJSON(http.MethodDelete, "/v1/tokens/"+id, nil, nil)
}

// ListAudit returns the most recent audit entries.
func (c *Client) ListAudit(limit int) ([]vault.AuditEntry, error) {
	var resp struct {
		Entries []vault.AuditEntry `json:"entries"`
	}
	ep := fmt.Sprintf("/v1/audit?limit=%d", limit)
	if err := c.doJSON(http.MethodGet, ep, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Entries, nil
}
