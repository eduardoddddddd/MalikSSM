package vault

import (
	"time"

	"github.com/malikssm/malik/internal/security"
)

const (
	TypeKV     = "kv"
	TypeString = "string"
	TypeEnv    = "env"
	TypeSSHKey = "ssh_key"
	TypeTOTP   = "totp"

	StageCurrent  = "AWSCURRENT"
	StagePrevious = "AWSPREVIOUS"
)

// SecretMetadata holds all unencrypted discovery fields so AI agents can search
// and understand what secrets exist and what keys they contain without exposing values.
type SecretMetadata struct {
	Path            string    `json:"path"`
	ARN             string    `json:"arn"`
	Type            string    `json:"type"`
	Description     string    `json:"description"`
	Tags            []string  `json:"tags"`
	SchemaKeys      []string  `json:"schema_keys"`
	BlindOnly       bool      `json:"blind_only"`
	CurrentVersion  int       `json:"current_version"`
	PreviousVersion int       `json:"previous_version,omitempty"`
	VersionCount    int       `json:"version_count"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	LastAccessedAt  time.Time `json:"last_accessed_at,omitempty"`
	LastAccessedBy  string    `json:"last_accessed_by,omitempty"`
}

// SecretVersion stores a single encrypted version of a secret.
type SecretVersion struct {
	Version   int                    `json:"version"`
	Stages    []string               `json:"stages"`
	CreatedAt time.Time              `json:"created_at"`
	CreatedBy string                 `json:"created_by"`
	Envelope  *security.EnvelopeBlob `json:"envelope"`
}

// SecretRecord is the full record persisted in the database bucket.
type SecretRecord struct {
	SecretMetadata
	Versions map[int]*SecretVersion `json:"versions"`
}

// DecryptedSecret is returned to authorized callers when reading a secret value.
type DecryptedSecret struct {
	SecretMetadata
	Version int               `json:"version"`
	Stages  []string          `json:"stages"`
	Value   string            `json:"value,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}

// SearchResult is returned by semantic/fuzzy search queries.
type SearchResult struct {
	SecretMetadata
	Score     int      `json:"score"`
	MatchedBy []string `json:"matched_by"`
}

// Session represents an authenticated user session (e.g. from morning `malik login`).
type Session struct {
	ID         string    `json:"id"`
	TokenHash  string    `json:"token_hash"`
	ClientHost string    `json:"client_host"`
	ClientIP   string    `json:"client_ip,omitempty"`
	AgentName  string    `json:"agent_name"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// AppToken represents a scoped machine/application token (e.g. for 24/7 bots or ChatGPT Actions).
type AppToken struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	TokenPrefix   string    `json:"token_prefix"`
	TokenHash     string    `json:"token_hash"`
	AllowedScopes []string  `json:"allowed_scopes"` // e.g. ["apis/openai/*", "clientes/acme/*"]
	Permissions   []string  `json:"permissions"`    // ["read", "search", "totp", "write"]
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	LastUsedAt    time.Time `json:"last_used_at,omitempty"`
}

// CallerIdentity describes who is making a request to the Vault.
type CallerIdentity struct {
	Subject       string   `json:"subject"`    // e.g. "admin-session", "app:bot-telegram"
	AgentName     string   `json:"agent_name"` // e.g. "claude", "antigravity", "malik-cli", "chatgpt", "boto3"
	ClientIP      string   `json:"client_ip"`
	IsAdmin       bool     `json:"is_admin"`
	AllowedScopes []string `json:"allowed_scopes"`
	Permissions   []string `json:"permissions"`
}

// AuditEntry is an immutable audit log record stored on every vault action.
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // LOGIN, SEARCH, GET_SECRET, SET_SECRET, DELETE_SECRET, TOTP, EXEC, LOCK, DENIED
	Path      string    `json:"path,omitempty"`
	Subject   string    `json:"subject"`
	Agent     string    `json:"agent"`
	ClientIP  string    `json:"client_ip"`
	Status    string    `json:"status"` // OK, DENIED, ERROR
	Detail    string    `json:"detail,omitempty"`
}

// VaultStatus summarizes the health and state of the server on the Windows Server.
type VaultStatus struct {
	Initialized     bool      `json:"initialized"`
	Unlocked        bool      `json:"unlocked"`
	AutoUnsealReady bool      `json:"auto_unseal_ready"`
	SecretCount     int       `json:"secret_count"`
	ActiveSessions  int       `json:"active_sessions"`
	AppTokenCount   int       `json:"app_token_count"`
	Encryption      string    `json:"encryption"`
	HardwareBacking string    `json:"hardware_backing"`
	ServerTime      time.Time `json:"server_time"`
}
