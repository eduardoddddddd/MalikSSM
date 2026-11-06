package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/malikssm/malik/internal/security"
)

const (
	DefaultServerURL  = "http://127.0.0.1:8443"
	dpapiSessionCtx   = "MalikSSM::LocalClientSessionCache::v1"
)

// LocalSession stores the workstation's active session with the Windows Server server.
type LocalSession struct {
	ServerURL  string    `json:"server_url"`
	Token      string    `json:"token"`
	SessionID  string    `json:"session_id,omitempty"`
	ClientHost string    `json:"client_host,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	SavedAt    time.Time `json:"saved_at"`
}

// ConfigDir returns the directory where MalikSSM stores its local workstation state (%APPDATA%\MalikSSM).
func ConfigDir() string {
	if custom := os.Getenv("MALIK_CONFIG_DIR"); custom != "" {
		_ = os.MkdirAll(custom, 0700)
		return custom
	}
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base, _ = os.UserHomeDir()
	}
	dir := filepath.Join(base, "MalikSSM")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

// SessionFilePath returns the path to the hardware-DPAPI encrypted session file (`session.bin`).
func SessionFilePath() string {
	return filepath.Join(ConfigDir(), "session.bin")
}

// SaveLocalSession encrypts the session payload using Windows DPAPI and writes it to `%APPDATA%\MalikSSM\session.bin`.
func SaveLocalSession(sess *LocalSession) error {
	sess.SavedAt = time.Now().UTC()
	raw, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	defer security.Zeroize(raw)

	sealed, err := security.ProtectBytesHardware(raw, dpapiSessionCtx)
	if err != nil {
		return err
	}
	return os.WriteFile(SessionFilePath(), sealed, 0600)
}

// LoadLocalSession reads and decrypts `%APPDATA%\MalikSSM\session.bin` using Windows DPAPI.
func LoadLocalSession() (*LocalSession, error) {
	sealed, err := os.ReadFile(SessionFilePath())
	if err != nil {
		return nil, err
	}
	raw, err := security.UnprotectBytesHardware(sealed, dpapiSessionCtx)
	if err != nil {
		return nil, err
	}
	defer security.Zeroize(raw)

	var sess LocalSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// ClearLocalSession deletes the local workstation session file.
func ClearLocalSession() error {
	err := os.Remove(SessionFilePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ResolveConnection resolves the effective ServerURL and Token using AWS-style precedence:
// 1. Explicit CLI flags (overrideServer / overrideToken)
// 2. Environment variables (MALIK_SERVER / MALIK_TOKEN) for unattended 24/7 bots
// 3. Hardware-DPAPI local session cache (%APPDATA%\MalikSSM\session.bin) from `malik login`
func ResolveConnection(overrideServer string, overrideToken string) (serverURL string, token string) {
	serverURL = strings.TrimSpace(overrideServer)
	if serverURL == "" {
		serverURL = strings.TrimSpace(os.Getenv("MALIK_SERVER"))
	}
	token = strings.TrimSpace(overrideToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("MALIK_TOKEN"))
	}

	if sess, err := LoadLocalSession(); err == nil && sess != nil {
		if serverURL == "" && sess.ServerURL != "" {
			serverURL = sess.ServerURL
		}
		if token == "" && sess.Token != "" {
			token = sess.Token
		}
	}

	if serverURL == "" {
		serverURL = DefaultServerURL
	}
	serverURL = strings.TrimRight(serverURL, "/")
	return serverURL, token
}
