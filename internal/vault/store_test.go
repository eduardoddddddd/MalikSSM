package vault

import (
	"path/filepath"
	"testing"
	"time"
)

func TestVaultStoreLifecycleVersioningScopesAndAutoUnseal(t *testing.T) {
	tmpDir := t.TempDir()
	dbFile := filepath.Join(tmpDir, "malik_test.db")

	store, err := OpenStore(dbFile)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	if store.IsInitialized() {
		t.Fatalf("expected new store to be uninitialized")
	}

	// Initialize with Auto-Unseal enabled (uses Windows DPAPI on Servidor Central)
	if err := store.InitVault("MasterPass-ROG-2026!", true); err != nil {
		t.Fatalf("InitVault failed: %v", err)
	}
	if !store.IsUnlocked() || !store.HasAutoUnseal() {
		t.Fatalf("expected store to be unlocked and have auto-unseal blob")
	}

	// Simulate Morning Session Login
	sessToken, _, err := store.CreateSession("MasterPass-ROG-2026!", "PC-Despacho", "claude", "127.0.0.1", 12*time.Hour)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	adminCaller, err := store.AuthenticateToken(sessToken, "claude", "127.0.0.1")
	if err != nil || !adminCaller.IsAdmin {
		t.Fatalf("AuthenticateToken failed: %v", err)
	}

	// Store Secret v1
	meta1, err := store.PutSecret(adminCaller, PutSecretInput{
		Path:        "clientes/acme/ssh-prod",
		Type:        TypeKV,
		Description: "Servidor principal de ACME en Hetzner",
		Tags:        []string{"ssh", "acme", "hetzner", "prod"},
		Data: map[string]string{
			"host":     "195.201.10.22",
			"port":     "22",
			"username": "ubuntu",
			"password": "OldPassword_v1",
			"totp":     "JBSWY3DPEHPK3PXP",
		},
	})
	if err != nil {
		t.Fatalf("PutSecret v1 failed: %v", err)
	}
	if meta1.CurrentVersion != 1 || len(meta1.SchemaKeys) != 5 {
		t.Fatalf("unexpected v1 metadata: %+v", meta1)
	}

	// Rotate to v2
	meta2, err := store.PutSecret(adminCaller, PutSecretInput{
		Path: "clientes/acme/ssh-prod",
		Type: TypeKV,
		Data: map[string]string{
			"host":     "195.201.10.22",
			"port":     "22",
			"username": "ubuntu",
			"password": "NewPassword_v2",
			"totp":     "JBSWY3DPEHPK3PXP",
		},
	})
	if err != nil {
		t.Fatalf("PutSecret v2 failed: %v", err)
	}
	if meta2.CurrentVersion != 2 || meta2.PreviousVersion != 1 {
		t.Fatalf("expected v2 current and v1 previous, got %+v", meta2)
	}

	// Read AWSCURRENT and AWSPREVIOUS
	curSec, err := store.GetSecret(adminCaller, "clientes/acme/ssh-prod", 0, StageCurrent)
	if err != nil || curSec.Data["password"] != "NewPassword_v2" {
		t.Fatalf("expected v2 password, got %+v (err=%v)", curSec, err)
	}
	prevSec, err := store.GetSecret(adminCaller, "clientes/acme/ssh-prod", 0, StagePrevious)
	if err != nil || prevSec.Data["password"] != "OldPassword_v1" {
		t.Fatalf("expected v1 previous password, got %+v (err=%v)", prevSec, err)
	}

	// Store a restricted secret outside acme scope
	_, err = store.PutSecret(adminCaller, PutSecretInput{
		Path:        "bancos/personal/master",
		Description: "Acceso bancario privado",
		Tags:        []string{"finanzas", "privado"},
		Value:       "PIN-9999",
	})
	if err != nil {
		t.Fatalf("PutSecret bancos failed: %v", err)
	}

	// Test Semantic Search
	hits, err := store.SearchSecrets(adminCaller, "hetzner ssh acme", nil)
	if err != nil || len(hits) == 0 || hits[0].Path != "clientes/acme/ssh-prod" {
		t.Fatalf("expected semantic search to rank clientes/acme/ssh-prod first, got %+v", hits)
	}

	// Test TOTP generation from secret
	otpRes, err := store.GenerateTOTP(adminCaller, "clientes/acme/ssh-prod")
	if err != nil || len(otpRes.Code) != 6 {
		t.Fatalf("GenerateTOTP failed: %v", err)
	}

	// Test Scoped App Token (only allowed clientes/acme/*)
	rawAppTok, _, err := store.CreateAppToken(adminCaller, "bot-acme", []string{"clientes/acme/*"}, []string{"read", "search"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateAppToken failed: %v", err)
	}
	botCaller, err := store.AuthenticateToken(rawAppTok, "bot-acme", "10.0.0.5")
	if err != nil {
		t.Fatalf("AuthenticateToken bot failed: %v", err)
	}

	// Bot can read clientes/acme/ssh-prod
	if _, err := store.GetSecret(botCaller, "clientes/acme/ssh-prod", 0, ""); err != nil {
		t.Fatalf("expected botCaller to read clientes/acme/ssh-prod, got %v", err)
	}
	// Bot MUST be denied access to bancos/personal/master
	if _, err := store.GetSecret(botCaller, "bancos/personal/master", 0, ""); err != ErrAccessDenied {
		t.Fatalf("expected ErrAccessDenied for bot reading bancos/personal/master, got %v", err)
	}

	// Simulate Servidor Central Reboot: close store and reopen -> should Auto-Unseal via Windows DPAPI automatically!
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	reopened, err := OpenStore(dbFile)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer reopened.Close()

	if !reopened.IsUnlocked() {
		t.Fatalf("expected reopened store to auto-unseal via Windows DPAPI")
	}
	afterRebootSec, err := reopened.GetSecret(adminCaller, "clientes/acme/ssh-prod", 0, "")
	if err != nil || afterRebootSec.Data["password"] != "NewPassword_v2" {
		t.Fatalf("expected secret readable immediately after auto-unseal reboot, got err=%v", err)
	}
}
