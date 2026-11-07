package vault

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newUnlockedStore(t *testing.T) (*Store, *CallerIdentity) {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "hardening.db"))
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.AllowAutoUnseal = false
	if err := store.InitVault("Hardening-Pass-2026!", true); err != nil {
		t.Fatalf("InitVault failed: %v", err)
	}
	tok, _, err := store.CreateSession("Hardening-Pass-2026!", "PC-Test", "test", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	caller, err := store.AuthenticateToken(tok, "test", "127.0.0.1")
	if err != nil {
		t.Fatalf("AuthenticateToken failed: %v", err)
	}
	return store, caller
}

func TestAutoUnsealBlobNotWrittenWhenDisallowed(t *testing.T) {
	store, _ := newUnlockedStore(t)
	if store.HasAutoUnseal() {
		t.Fatalf("auto-unseal blob must not be written when AllowAutoUnseal is false")
	}
	if err := store.Unlock("Hardening-Pass-2026!", true, "127.0.0.1"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if store.HasAutoUnseal() {
		t.Fatalf("Unlock(updateAutoUnseal=true) must not write the blob when AllowAutoUnseal is false")
	}
}

func TestSessionTokenBoundToIssuingIP(t *testing.T) {
	store, _ := newUnlockedStore(t)
	tok, _, err := store.CreateSession("Hardening-Pass-2026!", "PC-Despacho", "claude", "100.64.0.10", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if _, err := store.AuthenticateToken(tok, "claude", "100.64.0.10"); err != nil {
		t.Fatalf("expected session to work from its own IP: %v", err)
	}
	if _, err := store.AuthenticateToken(tok, "claude", "203.0.113.7"); err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized from a different IP, got %v", err)
	}

	store.BindSessionsToIP = false
	if _, err := store.AuthenticateToken(tok, "claude", "203.0.113.7"); err != nil {
		t.Fatalf("expected session to work from any IP when binding is disabled: %v", err)
	}
}

func TestBlindOnlyIsKeptOnRotationUnlessExplicitlyChanged(t *testing.T) {
	store, caller := newUnlockedStore(t)
	yes, no := true, false

	if _, err := store.PutSecret(caller, PutSecretInput{Path: "apis/stripe", Value: "sk_live_1", BlindOnly: &yes}); err != nil {
		t.Fatal(err)
	}
	meta, err := store.PutSecret(caller, PutSecretInput{Path: "apis/stripe", Value: "sk_live_2"})
	if err != nil {
		t.Fatal(err)
	}
	if !meta.BlindOnly {
		t.Fatalf("rotation without blind_only must keep the secret blind")
	}
	meta, err = store.PutSecret(caller, PutSecretInput{Path: "apis/stripe", Value: "sk_live_3", BlindOnly: &no})
	if err != nil {
		t.Fatal(err)
	}
	if meta.BlindOnly {
		t.Fatalf("explicit blind_only=false must clear the flag")
	}
}

// Before the fix, GetSecret re-wrote the whole record it had read earlier, so a concurrent rotation
// could be silently reverted (lost version).
func TestConcurrentReadsDoNotLoseRotations(t *testing.T) {
	store, caller := newUnlockedStore(t)
	const path = "db/postgres/prod"
	if _, err := store.PutSecret(caller, PutSecretInput{Path: path, Data: map[string]string{"password": "v1"}}); err != nil {
		t.Fatal(err)
	}

	const rotations = 40
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = store.GetSecret(caller, path, 0, "")
				}
			}
		}()
	}
	for i := 2; i <= rotations+1; i++ {
		if _, err := store.PutSecret(caller, PutSecretInput{Path: path, Data: map[string]string{"password": fmt.Sprintf("v%d", i)}}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()

	sec, err := store.GetSecret(caller, path, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if sec.CurrentVersion != rotations+1 || sec.VersionCount != rotations+1 {
		t.Fatalf("expected v%d with %d versions, got current=v%d count=%d", rotations+1, rotations+1, sec.CurrentVersion, sec.VersionCount)
	}
	if want := fmt.Sprintf("v%d", rotations+1); sec.Data["password"] != want {
		t.Fatalf("expected latest value %q, got %q", want, sec.Data["password"])
	}
}
