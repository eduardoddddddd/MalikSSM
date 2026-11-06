package security

import (
	"bytes"
	"testing"
)

func TestEnvelopeEncryptionAndTamperProtection(t *testing.T) {
	pass := []byte("SuperSecret-ROG-Ally-Master-Pass-2026!")
	meta, kek, err := CreateVaultKeyMeta(pass)
	if err != nil {
		t.Fatalf("CreateVaultKeyMeta failed: %v", err)
	}
	defer kek.Destroy()

	// Ensure input passphrase slice was zeroized
	for _, b := range pass {
		if b != 0 {
			t.Fatalf("expected input passphrase buffer to be zeroized in RAM")
		}
	}

	payload := []byte(`{"host":"10.0.0.15","username":"root","password":"ultra_secret_password"}`)
	blob, err := SealSecret(kek, "servers/rog-ally/ssh", 1, "kv", payload)
	if err != nil {
		t.Fatalf("SealSecret failed: %v", err)
	}

	// Decrypt with matching AAD parameters
	decrypted, err := OpenSecret(kek, "servers/rog-ally/ssh", 1, "kv", blob)
	if err != nil {
		t.Fatalf("OpenSecret failed: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Fatalf("decrypted payload mismatch: got %s", string(decrypted))
	}

	// Attempt path substitution attack (swapping encrypted blob into another secret path)
	if _, err := OpenSecret(kek, "servers/other/ssh", 1, "kv", blob); err == nil {
		t.Fatalf("expected AAD path substitution attack to fail")
	}

	// Attempt version rollback attack
	if _, err := OpenSecret(kek, "servers/rog-ally/ssh", 2, "kv", blob); err == nil {
		t.Fatalf("expected AAD version tampering attack to fail")
	}

	// Verify wrong passphrase rejection
	if _, err := UnlockWithPassphrase([]byte("wrong-password"), meta); err == nil {
		t.Fatalf("expected wrong passphrase to fail")
	}

	// Lock vault and verify operations fail immediately
	kek.Destroy()
	if kek.IsUnlocked() {
		t.Fatalf("expected LockedKey to report locked after Destroy()")
	}
	if _, err := OpenSecret(kek, "servers/rog-ally/ssh", 1, "kv", blob); err != ErrVaultLocked {
		t.Fatalf("expected ErrVaultLocked after Destroy(), got %v", err)
	}
}

func TestWindowsDPAPIHardwareProtect(t *testing.T) {
	secret := []byte("32-byte-hardware-bound-masterkey")
	sealed, err := ProtectBytesHardware(secret, "unit-test-context")
	if err != nil {
		t.Fatalf("ProtectBytesHardware failed: %v", err)
	}
	if bytes.Equal(sealed, secret) {
		t.Fatalf("sealed bytes must not equal plaintext")
	}

	unsealed, err := UnprotectBytesHardware(sealed, "unit-test-context")
	if err != nil {
		t.Fatalf("UnprotectBytesHardware failed: %v", err)
	}
	if !bytes.Equal(unsealed, secret) {
		t.Fatalf("unsealed bytes mismatch")
	}

	// Wrong context must fail DPAPI entropy check
	if _, err := UnprotectBytesHardware(sealed, "wrong-context"); err == nil {
		t.Fatalf("expected DPAPI unprotect with wrong entropy context to fail")
	}
}
