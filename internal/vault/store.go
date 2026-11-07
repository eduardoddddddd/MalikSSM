package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/malikssm/malik/internal/security"
	"github.com/malikssm/malik/internal/totp"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketSystem   = []byte("system")
	bucketSecrets  = []byte("secrets")
	bucketSessions = []byte("sessions")
	bucketTokens   = []byte("app_tokens")
	bucketAudit    = []byte("audit")

	keyVaultMeta = []byte("vault_key_meta")

	ErrNotInitialized = errors.New("vault is not initialized yet")
	ErrAlreadyInit    = errors.New("vault is already initialized")
	ErrSecretNotFound = errors.New("secret not found")
	ErrAccessDenied   = errors.New("access denied: caller token does not have permission for this secret path or action")
	ErrUnauthorized   = errors.New("unauthorized: invalid or expired session/token")
)

// Store is the thread-safe, ACID-transactional Vault engine backed by bbolt and LockedKey in RAM.
type Store struct {
	db         *bolt.DB
	dbPath     string
	unsealPath string

	mu  sync.RWMutex
	kek *security.LockedKey

	subMu       sync.Mutex
	subscribers map[chan AuditEntry]struct{}

	// AllowAutoUnseal permits writing and using the malik.db.unseal blob. It defaults to true only on
	// Windows (DPAPI). On macOS/Linux the blob is merely bound to hostname/UID/machine-id, which anyone
	// with disk access can read, so it is opt-in there.
	AllowAutoUnseal bool
	// BindSessionsToIP rejects a session token used from an IP other than the one that created it,
	// limiting the value of a copied session.bin token.
	BindSessionsToIP bool
}

// OpenStore opens or creates the bbolt database file and attempts Hardware Auto-Unseal if configured.
func OpenStore(dbPath string) (*Store, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open vault database %s: %w", dbPath, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketSystem, bucketSecrets, bucketSessions, bucketTokens, bucketAudit} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	s := &Store{
		db:               db,
		dbPath:           dbPath,
		unsealPath:       dbPath + ".unseal",
		subscribers:      make(map[chan AuditEntry]struct{}),
		AllowAutoUnseal:  runtime.GOOS == "windows",
		BindSessionsToIP: true,
	}

	// If Hardware DPAPI Auto-Unseal file exists on the Servidor Central, unseal into VirtualLocked RAM automatically.
	if s.AllowAutoUnseal {
		_ = s.TryAutoUnseal()
	}

	return s, nil
}

// Close securely wipes the Master Key in RAM and closes the underlying database.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.kek != nil {
		s.kek.Destroy()
		s.kek = nil
	}
	s.mu.Unlock()
	return s.db.Close()
}

// IsInitialized returns true if the vault has been initialized with a master passphrase.
func (s *Store) IsInitialized() bool {
	var init bool
	_ = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSystem)
		init = b != nil && len(b.Get(keyVaultMeta)) > 0
		return nil
	})
	return init
}

// IsUnlocked returns true if the Master Key (KEK) is currently locked in physical RAM.
func (s *Store) IsUnlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kek != nil && s.kek.IsUnlocked()
}

// HasAutoUnseal returns true if a hardware-bound DPAPI unseal blob is present.
func (s *Store) HasAutoUnseal() bool {
	_, err := os.Stat(s.unsealPath)
	return err == nil
}

// InitVault initializes a brand-new vault with a Master Passphrase and optional Hardware Auto-Unseal.
func (s *Store) InitVault(passphrase string, enableAutoUnseal bool) error {
	if s.IsInitialized() {
		return ErrAlreadyInit
	}
	if len(passphrase) < 6 {
		return errors.New("master passphrase must be at least 6 characters")
	}
	enableAutoUnseal = enableAutoUnseal && s.AllowAutoUnseal

	meta, lk, err := security.CreateVaultKeyMeta([]byte(passphrase))
	if err != nil {
		return err
	}

	var sealedAutoUnseal []byte
	if enableAutoUnseal {
		rawKEK := security.DeriveKEK([]byte(passphrase), meta.Salt)
		sealedAutoUnseal, err = security.ProtectBytesHardware(rawKEK, s.dbPath)
		security.Zeroize(rawKEK)
		if err != nil {
			lk.Destroy()
			return fmt.Errorf("failed to create auto-unseal key: %w", err)
		}
	}

	rawMeta, err := json.Marshal(meta)
	if err != nil {
		lk.Destroy()
		return err
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSystem).Put(keyVaultMeta, rawMeta)
	})
	if err != nil {
		lk.Destroy()
		return err
	}

	if enableAutoUnseal && len(sealedAutoUnseal) > 0 {
		_ = os.WriteFile(s.unsealPath, sealedAutoUnseal, 0600)
	}

	s.mu.Lock()
	if s.kek != nil {
		s.kek.Destroy()
	}
	s.kek = lk
	s.mu.Unlock()

	s.RecordAudit("INIT_VAULT", "", "admin", "system", "127.0.0.1", "OK", fmt.Sprintf("auto_unseal=%v", enableAutoUnseal))
	return nil
}

// TryAutoUnseal attempts to unseal the Master KEK using the auto-unseal blob (Windows DPAPI, or opt-in host-bound obfuscation elsewhere).
func (s *Store) TryAutoUnseal() error {
	if !s.IsInitialized() {
		return ErrNotInitialized
	}
	sealed, err := os.ReadFile(s.unsealPath)
	if err != nil {
		return err
	}

	rawKEK, err := security.UnprotectBytesHardware(sealed, s.dbPath)
	if err != nil {
		return err
	}

	meta, err := s.loadKeyMeta()
	if err != nil {
		security.Zeroize(rawKEK)
		return err
	}

	lk, err := security.UnlockWithRawKEK(rawKEK, meta)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.kek != nil {
		s.kek.Destroy()
	}
	s.kek = lk
	s.mu.Unlock()

	s.RecordAudit("AUTO_UNSEAL", "", "system", "auto-unseal", "127.0.0.1", "OK", "Vault auto-unsealed via "+security.HardwareProviderName())
	return nil
}

// Unlock verifies the Master Passphrase, loads the KEK into VirtualLocked RAM, and optionally updates Auto-Unseal.
func (s *Store) Unlock(passphrase string, updateAutoUnseal bool, clientIP string) error {
	if !s.IsInitialized() {
		return ErrNotInitialized
	}
	meta, err := s.loadKeyMeta()
	if err != nil {
		return err
	}

	lk, err := security.UnlockWithPassphrase([]byte(passphrase), meta)
	if err != nil {
		s.RecordAudit("UNLOCK", "", "admin", "auth", clientIP, "DENIED", "Invalid master passphrase")
		return err
	}

	if updateAutoUnseal && s.AllowAutoUnseal {
		rawKEK := security.DeriveKEK([]byte(passphrase), meta.Salt)
		if sealed, err := security.ProtectBytesHardware(rawKEK, s.dbPath); err == nil {
			_ = os.WriteFile(s.unsealPath, sealed, 0600)
		}
		security.Zeroize(rawKEK)
	}

	s.mu.Lock()
	if s.kek != nil {
		s.kek.Destroy()
	}
	s.kek = lk
	s.mu.Unlock()

	s.RecordAudit("UNLOCK", "", "admin", "auth", clientIP, "OK", "Vault unlocked into physical RAM")
	return nil
}

// VerifyPassphrase checks if the provided passphrase matches the Master Key (and unlocks if currently locked).
func (s *Store) VerifyPassphrase(passphrase string, clientIP string) error {
	return s.Unlock(passphrase, false, clientIP)
}

// Lock wipes the Master Key from RAM immediately (Panic Button) and optionally revokes all active sessions.
func (s *Store) Lock(revokeSessions bool, removeAutoUnseal bool, caller *CallerIdentity) error {
	s.mu.Lock()
	if s.kek != nil {
		s.kek.Destroy()
		s.kek = nil
	}
	s.mu.Unlock()

	if removeAutoUnseal {
		_ = os.Remove(s.unsealPath)
	}
	if revokeSessions {
		_ = s.db.Update(func(tx *bolt.Tx) error {
			_ = tx.DeleteBucket(bucketSessions)
			_, err := tx.CreateBucket(bucketSessions)
			return err
		})
	}

	sub, agent, ip := "admin", "system", "127.0.0.1"
	if caller != nil {
		sub, agent, ip = caller.Subject, caller.AgentName, caller.ClientIP
	}
	s.RecordAudit("LOCK_VAULT", "", sub, agent, ip, "OK", fmt.Sprintf("revoke_sessions=%v remove_auto_unseal=%v", revokeSessions, removeAutoUnseal))
	return nil
}

func (s *Store) loadKeyMeta() (*security.VaultKeyMeta, error) {
	var meta security.VaultKeyMeta
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSystem)
		raw := b.Get(keyVaultMeta)
		if len(raw) == 0 {
			return ErrNotInitialized
		}
		return json.Unmarshal(raw, &meta)
	})
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

// CreateSession verifies the Master Passphrase (unlocking the vault if locked) and issues a session token (`mlk_sess_...`).
func (s *Store) CreateSession(passphrase string, clientHost string, agentName string, clientIP string, ttl time.Duration) (string, *Session, error) {
	if err := s.VerifyPassphrase(passphrase, clientIP); err != nil {
		return "", nil, err
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}

	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", nil, err
	}
	rawToken := "mlk_sess_" + hex.EncodeToString(rawBytes)
	tokenHash := hashToken(rawToken)

	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)

	now := time.Now().UTC()
	sess := &Session{
		ID:         hex.EncodeToString(idBytes),
		TokenHash:  tokenHash,
		ClientHost: clientHost,
		ClientIP:   clientIP,
		AgentName:  agentName,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		LastUsedAt: now,
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(sess)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketSessions).Put([]byte(tokenHash), raw)
	})
	if err != nil {
		return "", nil, err
	}

	s.RecordAudit("LOGIN_SESSION", "", "admin:"+clientHost, agentName, clientIP, "OK", fmt.Sprintf("session_id=%s ttl=%s", sess.ID, ttl))
	return rawToken, sess, nil
}

// CreateAppToken creates a scoped machine/application token (`mlk_live_...`) for 24/7 bots, scripts, or ChatGPT Actions.
func (s *Store) CreateAppToken(caller *CallerIdentity, name string, allowedScopes []string, permissions []string, ttl time.Duration) (string, *AppToken, error) {
	if caller == nil || !caller.IsAdmin {
		return "", nil, ErrAccessDenied
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("token name is required")
	}
	if len(allowedScopes) == 0 {
		allowedScopes = []string{"*"}
	}
	if len(permissions) == 0 {
		permissions = []string{"read", "search", "totp"}
	}

	rawBytes := make([]byte, 28)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", nil, err
	}
	rawToken := "mlk_live_" + hex.EncodeToString(rawBytes)
	tokenHash := hashToken(rawToken)

	idBytes := make([]byte, 6)
	_, _ = rand.Read(idBytes)
	now := time.Now().UTC()

	var expires time.Time
	if ttl > 0 {
		expires = now.Add(ttl)
	}

	tok := &AppToken{
		ID:            hex.EncodeToString(idBytes),
		Name:          name,
		TokenPrefix:   rawToken[:17] + "...",
		TokenHash:     tokenHash,
		AllowedScopes: allowedScopes,
		Permissions:   permissions,
		CreatedAt:     now,
		ExpiresAt:     expires,
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(tok)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketTokens).Put([]byte(tok.ID), raw)
	})
	if err != nil {
		return "", nil, err
	}

	s.RecordAudit("TOKEN_CREATE", "", caller.Subject, caller.AgentName, caller.ClientIP, "OK", fmt.Sprintf("app=%s scopes=%v perms=%v", name, allowedScopes, permissions))
	return rawToken, tok, nil
}

// ListAppTokens returns all configured application tokens (without exposing their raw token secret).
func (s *Store) ListAppTokens() ([]AppToken, error) {
	var list []AppToken
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		return b.ForEach(func(_, v []byte) error {
			var t AppToken
			if err := json.Unmarshal(v, &t); err == nil {
				list = append(list, t)
			}
			return nil
		})
	})
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list, err
}

// RevokeAppToken deletes a machine/app token by ID.
func (s *Store) RevokeAppToken(caller *CallerIdentity, id string) error {
	if caller == nil || !caller.IsAdmin {
		return ErrAccessDenied
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Delete([]byte(id))
	})
	if err == nil {
		s.RecordAudit("TOKEN_REVOKE", "", caller.Subject, caller.AgentName, caller.ClientIP, "OK", "revoked token id="+id)
	}
	return err
}

// AuthenticateToken validates either a session token (`mlk_sess_...`) or an app token (`mlk_live_...`).
func (s *Store) AuthenticateToken(rawToken string, agentHeader string, clientIP string) (*CallerIdentity, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, ErrUnauthorized
	}
	h := hashToken(rawToken)
	now := time.Now().UTC()

	if strings.HasPrefix(rawToken, "mlk_sess_") {
		var sess Session
		err := s.db.View(func(tx *bolt.Tx) error {
			data := tx.Bucket(bucketSessions).Get([]byte(h))
			if len(data) == 0 {
				return ErrUnauthorized
			}
			return json.Unmarshal(data, &sess)
		})
		if err != nil {
			return nil, ErrUnauthorized
		}
		if now.After(sess.ExpiresAt) {
			return nil, ErrUnauthorized
		}
		if s.BindSessionsToIP && sess.ClientIP != "" && clientIP != sess.ClientIP {
			s.RecordAudit("SESSION_IP_MISMATCH", "", "admin:"+sess.ClientHost, agentHeader, clientIP, "DENIED",
				fmt.Sprintf("session_id=%s issued_to=%s", sess.ID, sess.ClientIP))
			return nil, ErrUnauthorized
		}
		agent := agentHeader
		if agent == "" {
			agent = sess.AgentName
		}
		if agent == "" {
			agent = "malik-cli"
		}
		return &CallerIdentity{
			Subject:       "admin:" + sess.ClientHost,
			AgentName:     agent,
			ClientIP:      clientIP,
			IsAdmin:       true,
			AllowedScopes: []string{"*"},
			Permissions:   []string{"*"},
		}, nil
	}

	// Check AppTokens
	var matched *AppToken
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(_, v []byte) error {
			var t AppToken
			if err := json.Unmarshal(v, &t); err == nil {
				if security.ConstantTimeEqual([]byte(t.TokenHash), []byte(h)) {
					matched = &t
				}
			}
			return nil
		})
	})
	if matched == nil {
		return nil, ErrUnauthorized
	}
	if !matched.ExpiresAt.IsZero() && now.After(matched.ExpiresAt) {
		return nil, ErrUnauthorized
	}

	agent := agentHeader
	if agent == "" {
		agent = "app:" + matched.Name
	}
	return &CallerIdentity{
		Subject:       "app:" + matched.Name,
		AgentName:     agent,
		ClientIP:      clientIP,
		IsAdmin:       false,
		AllowedScopes: matched.AllowedScopes,
		Permissions:   matched.Permissions,
	}, nil
}

// CheckAccess verifies whether a CallerIdentity is allowed to perform action ("read", "write", "search", "totp", "delete") on secretPath.
func CheckAccess(caller *CallerIdentity, action string, secretPath string) bool {
	if caller == nil {
		return false
	}
	if caller.IsAdmin {
		return true
	}

	hasPerm := false
	for _, p := range caller.Permissions {
		if p == "*" || strings.EqualFold(p, action) {
			hasPerm = true
			break
		}
	}
	if !hasPerm {
		return false
	}

	if secretPath == "" {
		return true
	}
	normPath := NormalizePath(secretPath)
	for _, scope := range caller.AllowedScopes {
		scope = NormalizePath(scope)
		if scope == "*" || scope == "**" {
			return true
		}
		if strings.HasSuffix(scope, "/*") {
			prefix := strings.TrimSuffix(scope, "/*")
			if normPath == prefix || strings.HasPrefix(normPath, prefix+"/") {
				return true
			}
		}
		if matched, _ := path.Match(scope, normPath); matched {
			return true
		}
		if scope == normPath {
			return true
		}
	}
	return false
}

// NormalizePath cleans and normalizes a secret path (e.g. "/Apis/OpenAI/Prod/" -> "apis/openai/prod").
func NormalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.Trim(p, "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

// PutSecretInput contains the parameters for creating or updating a secret.
type PutSecretInput struct {
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	BlindOnly   *bool             `json:"blind_only,omitempty"` // nil = keep the current flag on rotation
	Value       string            `json:"value,omitempty"`
	Data        map[string]string `json:"data,omitempty"`
}

// PutSecret encrypts and stores a new or updated secret version using Envelope AES-256-GCM.
func (s *Store) PutSecret(caller *CallerIdentity, in PutSecretInput) (*SecretMetadata, error) {
	s.mu.RLock()
	kek := s.kek
	s.mu.RUnlock()
	if kek == nil || !kek.IsUnlocked() {
		return nil, security.ErrVaultLocked
	}

	normPath := NormalizePath(in.Path)
	if normPath == "" {
		return nil, errors.New("secret path cannot be empty")
	}
	if !CheckAccess(caller, "write", normPath) {
		s.RecordAudit("SET_SECRET", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "DENIED", "insufficient scope/permission")
		return nil, ErrAccessDenied
	}

	secType := strings.ToLower(strings.TrimSpace(in.Type))
	if secType == "" {
		if len(in.Data) > 0 {
			secType = TypeKV
		} else {
			secType = TypeString
		}
	}

	// Normalize payload & extract SchemaKeys for AI discovery without decryption
	var schemaKeys []string
	var plaintextBytes []byte
	var err error

	if len(in.Data) > 0 {
		for k := range in.Data {
			schemaKeys = append(schemaKeys, k)
		}
		sort.Strings(schemaKeys)
		plaintextBytes, err = json.Marshal(in.Data)
		if err != nil {
			return nil, err
		}
	} else {
		// Check if Value is valid JSON object and type is kv/env
		trimmed := strings.TrimSpace(in.Value)
		if (secType == TypeKV || secType == TypeEnv) && strings.HasPrefix(trimmed, "{") {
			var parsed map[string]any
			if jsonErr := json.Unmarshal([]byte(trimmed), &parsed); jsonErr == nil {
				dataMap := make(map[string]string, len(parsed))
				for k, v := range parsed {
					schemaKeys = append(schemaKeys, k)
					dataMap[k] = fmt.Sprintf("%v", v)
				}
				sort.Strings(schemaKeys)
				plaintextBytes, _ = json.Marshal(dataMap)
			}
		}
		if len(plaintextBytes) == 0 {
			schemaKeys = []string{"value"}
			plaintextBytes = []byte(in.Value)
		}
	}
	defer security.Zeroize(plaintextBytes)

	now := time.Now().UTC()
	var resultMeta SecretMetadata

	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecrets)
		var rec SecretRecord
		existing := b.Get([]byte(normPath))

		nextVer := 1
		if len(existing) > 0 {
			if err := json.Unmarshal(existing, &rec); err != nil {
				return err
			}
			nextVer = rec.CurrentVersion + 1
		} else {
			rec = SecretRecord{
				SecretMetadata: SecretMetadata{
					Path:      normPath,
					ARN:       fmt.Sprintf("arn:aws:secretsmanager:local:000000000000:secret:%s", normPath),
					CreatedAt: now,
				},
				Versions: make(map[int]*SecretVersion),
			}
		}

		blob, err := security.SealSecret(kek, normPath, nextVer, secType, plaintextBytes)
		if err != nil {
			return err
		}

		// Demote previous stages
		for vNum, ver := range rec.Versions {
			if vNum == rec.CurrentVersion {
				ver.Stages = []string{StagePrevious}
				rec.PreviousVersion = vNum
			} else {
				ver.Stages = nil
			}
		}

		rec.Versions[nextVer] = &SecretVersion{
			Version:   nextVer,
			Stages:    []string{StageCurrent},
			CreatedAt: now,
			CreatedBy: caller.AgentName,
			Envelope:  blob,
		}

		rec.Type = secType
		if in.Description != "" || rec.Description == "" {
			rec.Description = in.Description
		}
		if len(in.Tags) > 0 || len(rec.Tags) == 0 {
			rec.Tags = normalizeTags(in.Tags)
		}
		rec.SchemaKeys = schemaKeys
		switch {
		case in.BlindOnly != nil:
			rec.BlindOnly = *in.BlindOnly
		case len(existing) == 0:
			// New secrets are blind unless the caller says otherwise: agents use them through
			// remote_exec / secrets_exec and never see the values.
			rec.BlindOnly = true
		}
		rec.CurrentVersion = nextVer
		rec.VersionCount = len(rec.Versions)
		rec.UpdatedAt = now

		rawRec, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(normPath), rawRec); err != nil {
			return err
		}
		resultMeta = rec.SecretMetadata
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.RecordAudit("SET_SECRET", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "OK", fmt.Sprintf("v%d keys=%v", resultMeta.CurrentVersion, schemaKeys))
	return &resultMeta, nil
}

// GetSecret retrieves and decrypts a secret by path and optional version or staging label.
func (s *Store) GetSecret(caller *CallerIdentity, secretPath string, version int, stage string) (*DecryptedSecret, error) {
	s.mu.RLock()
	kek := s.kek
	s.mu.RUnlock()
	if kek == nil || !kek.IsUnlocked() {
		return nil, security.ErrVaultLocked
	}

	normPath := NormalizePath(secretPath)
	if !CheckAccess(caller, "read", normPath) {
		s.RecordAudit("GET_SECRET", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "DENIED", "scope denied")
		return nil, ErrAccessDenied
	}

	var rec SecretRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketSecrets).Get([]byte(normPath))
		if len(raw) == 0 {
			return ErrSecretNotFound
		}
		return json.Unmarshal(raw, &rec)
	})
	if err != nil {
		return nil, err
	}

	targetVer := rec.CurrentVersion
	if version > 0 {
		targetVer = version
	} else if strings.EqualFold(stage, StagePrevious) && rec.PreviousVersion > 0 {
		targetVer = rec.PreviousVersion
	}

	verObj, ok := rec.Versions[targetVer]
	if !ok {
		return nil, fmt.Errorf("version %d not found for secret %s", targetVer, normPath)
	}

	plaintext, err := security.OpenSecret(kek, normPath, targetVer, rec.Type, verObj.Envelope)
	if err != nil {
		s.RecordAudit("GET_SECRET", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "ERROR", err.Error())
		return nil, err
	}
	defer security.Zeroize(plaintext)

	// Update LastAccessedAt on the record as it is *now* (re-read inside the write transaction),
	// so a concurrent PutSecret rotation is never overwritten with the stale copy read above.
	now := time.Now().UTC()
	rec.LastAccessedAt = now
	rec.LastAccessedBy = caller.AgentName
	_ = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecrets)
		raw := b.Get([]byte(normPath))
		if len(raw) == 0 {
			return nil
		}
		var latest SecretRecord
		if err := json.Unmarshal(raw, &latest); err != nil {
			return nil
		}
		latest.LastAccessedAt = now
		latest.LastAccessedBy = caller.AgentName
		updated, err := json.Marshal(latest)
		if err != nil {
			return nil
		}
		return b.Put([]byte(normPath), updated)
	})

	out := &DecryptedSecret{
		SecretMetadata: rec.SecretMetadata,
		Version:        targetVer,
		Stages:         verObj.Stages,
	}

	var kvMap map[string]string
	if len(plaintext) > 0 && plaintext[0] == '{' && json.Unmarshal(plaintext, &kvMap) == nil {
		out.Data = kvMap
		out.Value = string(plaintext)
	} else {
		out.Value = string(plaintext)
		out.Data = map[string]string{"value": out.Value}
	}

	s.RecordAudit("GET_SECRET", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "OK", fmt.Sprintf("v%d", targetVer))
	return out, nil
}

// DeleteSecret removes a secret from the vault.
func (s *Store) DeleteSecret(caller *CallerIdentity, secretPath string) error {
	normPath := NormalizePath(secretPath)
	if !CheckAccess(caller, "write", normPath) && !CheckAccess(caller, "delete", normPath) {
		s.RecordAudit("DELETE_SECRET", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "DENIED", "permission denied")
		return ErrAccessDenied
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecrets)
		if b.Get([]byte(normPath)) == nil {
			return ErrSecretNotFound
		}
		return b.Delete([]byte(normPath))
	})
	if err != nil {
		return err
	}
	s.RecordAudit("DELETE_SECRET", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "OK", "deleted")
	return nil
}

// ListSecrets returns metadata for all secrets visible to the caller (optionally filtered by prefix).
func (s *Store) ListSecrets(caller *CallerIdentity, prefix string) ([]SecretMetadata, error) {
	normPrefix := NormalizePath(prefix)
	var list []SecretMetadata

	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).ForEach(func(_, v []byte) error {
			var rec SecretRecord
			if err := json.Unmarshal(v, &rec); err == nil {
				if normPrefix != "" && !strings.HasPrefix(rec.Path, normPrefix) {
					return nil
				}
				if CheckAccess(caller, "search", rec.Path) || CheckAccess(caller, "read", rec.Path) {
					list = append(list, rec.SecretMetadata)
				}
			}
			return nil
		})
	})
	sort.Slice(list, func(i, j int) bool {
		return list[i].Path < list[j].Path
	})
	return list, err
}

// SearchSecrets performs semantic/fuzzy multi-token search across path, tags, description, and schema_keys.
// This allows AI agents (Claude, Antigravity, ChatGPT) to find any credential on the first try without knowing its exact path.
func (s *Store) SearchSecrets(caller *CallerIdentity, query string, filterTags []string) ([]SearchResult, error) {
	all, err := s.ListSecrets(caller, "")
	if err != nil {
		return nil, err
	}

	q := strings.ToLower(strings.TrimSpace(query))
	tokens := strings.FieldsFunc(q, func(r rune) bool {
		return r == ' ' || r == '/' || r == '-' || r == '_' || r == ',' || r == '.'
	})
	normFilterTags := normalizeTags(filterTags)

	var results []SearchResult
	for _, meta := range all {
		score := 0
		var matchedBy []string

		// Tag filter check
		if len(normFilterTags) > 0 {
			for _, ft := range normFilterTags {
				for _, t := range meta.Tags {
					if strings.Contains(t, ft) {
						score += 30
						matchedBy = appendUnique(matchedBy, "tag:"+t)
					}
				}
			}
			if score == 0 && q == "" {
				continue
			}
		}

		if q == "" && len(normFilterTags) == 0 {
			results = append(results, SearchResult{SecretMetadata: meta, Score: 1, MatchedBy: []string{"all"}})
			continue
		}

		pathLower := strings.ToLower(meta.Path)
		descLower := strings.ToLower(meta.Description)

		if pathLower == q {
			score += 100
			matchedBy = appendUnique(matchedBy, "exact_path")
		} else if strings.Contains(pathLower, q) {
			score += 50
			matchedBy = appendUnique(matchedBy, "path")
		}

		for _, tok := range tokens {
			if len(tok) < 2 {
				continue
			}
			if strings.Contains(pathLower, tok) {
				score += 25
				matchedBy = appendUnique(matchedBy, "path:"+tok)
			}
			for _, tag := range meta.Tags {
				if tag == tok {
					score += 35
					matchedBy = appendUnique(matchedBy, "tag:"+tag)
				} else if strings.Contains(tag, tok) {
					score += 20
					matchedBy = appendUnique(matchedBy, "tag:"+tag)
				}
			}
			if strings.Contains(descLower, tok) {
				score += 15
				matchedBy = appendUnique(matchedBy, "description")
			}
			for _, sk := range meta.SchemaKeys {
				if strings.Contains(strings.ToLower(sk), tok) {
					score += 10
					matchedBy = appendUnique(matchedBy, "field:"+sk)
				}
			}
		}

		if score > 0 {
			results = append(results, SearchResult{
				SecretMetadata: meta,
				Score:          score,
				MatchedBy:      matchedBy,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].Path < results[j].Path
	})

	s.RecordAudit("SEARCH", query, caller.Subject, caller.AgentName, caller.ClientIP, "OK", fmt.Sprintf("hits=%d", len(results)))
	return results, nil
}

// GenerateTOTP decrypts the target secret and computes its live 6-digit RFC 6238 TOTP code.
func (s *Store) GenerateTOTP(caller *CallerIdentity, secretPath string) (*totp.Result, error) {
	normPath := NormalizePath(secretPath)
	if !CheckAccess(caller, "totp", normPath) && !CheckAccess(caller, "read", normPath) {
		s.RecordAudit("TOTP", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "DENIED", "totp permission denied")
		return nil, ErrAccessDenied
	}

	sec, err := s.GetSecret(caller, normPath, 0, StageCurrent)
	if err != nil {
		return nil, err
	}

	seed := sec.Value
	if len(sec.Data) > 0 {
		for _, candidate := range []string{"totp", "otp", "seed", "mfa", "secret", "two_factor", "value"} {
			if v, ok := sec.Data[candidate]; ok && strings.TrimSpace(v) != "" {
				seed = v
				break
			}
		}
	}

	res, err := totp.Generate(seed, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	s.RecordAudit("TOTP", normPath, caller.Subject, caller.AgentName, caller.ClientIP, "OK", fmt.Sprintf("remaining=%ds", res.SecondsRemaining))
	return res, nil
}

// Status returns the current health and statistics of the Vault.
func (s *Store) Status() VaultStatus {
	var secCount, sessCount, tokCount int
	now := time.Now().UTC()

	_ = s.db.View(func(tx *bolt.Tx) error {
		secCount = tx.Bucket(bucketSecrets).Stats().KeyN
		tokCount = tx.Bucket(bucketTokens).Stats().KeyN
		_ = tx.Bucket(bucketSessions).ForEach(func(_, v []byte) error {
			var sess Session
			if json.Unmarshal(v, &sess) == nil && now.Before(sess.ExpiresAt) {
				sessCount++
			}
			return nil
		})
		return nil
	})

	return VaultStatus{
		Initialized:     s.IsInitialized(),
		Unlocked:        s.IsUnlocked(),
		AutoUnsealReady: s.HasAutoUnseal(),
		SecretCount:     secCount,
		ActiveSessions:  sessCount,
		AppTokenCount:   tokCount,
		Encryption:      "Envelope AES-256-GCM + Argon2id (64MB) + RAM Page Lock",
		HardwareBacking: security.HardwareProviderName(),
		ServerTime:      now,
	}
}

// RecordAudit writes an immutable entry to the audit log and broadcasts to real-time SSE listeners.
func (s *Store) RecordAudit(action, secPath, subject, agent, clientIP, status, detail string) {
	now := time.Now().UTC()
	idBytes := make([]byte, 4)
	_, _ = rand.Read(idBytes)
	key := fmt.Sprintf("%020d_%s", now.UnixNano(), hex.EncodeToString(idBytes))

	entry := AuditEntry{
		ID:        key,
		Timestamp: now,
		Action:    action,
		Path:      secPath,
		Subject:   subject,
		Agent:     agent,
		ClientIP:  clientIP,
		Status:    status,
		Detail:    detail,
	}

	_ = s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketAudit).Put([]byte(key), raw)
	})

	s.subMu.Lock()
	for ch := range s.subscribers {
		select {
		case ch <- entry:
		default:
		}
	}
	s.subMu.Unlock()
}

// ListAudit returns the most recent audit entries (up to limit).
func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var list []AuditEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudit).Cursor()
		for k, v := c.Last(); k != nil && len(list) < limit; k, v = c.Prev() {
			var e AuditEntry
			if json.Unmarshal(v, &e) == nil {
				list = append(list, e)
			}
		}
		return nil
	})
	return list, err
}

// SubscribeAudit registers a channel for live SSE audit events.
func (s *Store) SubscribeAudit() (chan AuditEntry, func()) {
	ch := make(chan AuditEntry, 32)
	s.subMu.Lock()
	s.subscribers[ch] = struct{}{}
	s.subMu.Unlock()

	unsubscribe := func() {
		s.subMu.Lock()
		delete(s.subscribers, ch)
		close(ch)
		s.subMu.Unlock()
	}
	return ch, unsubscribe
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte("MalikSSM::TokenHash::v1::" + raw))
	return hex.EncodeToString(sum[:])
}

func normalizeTags(tags []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, t := range tags {
		for _, part := range strings.Split(t, ",") {
			clean := strings.ToLower(strings.TrimSpace(part))
			if clean != "" {
				if _, ok := seen[clean]; !ok {
					seen[clean] = struct{}{}
					out = append(out, clean)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
