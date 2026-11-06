package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	ArgonTime    uint32 = 3
	ArgonMemory  uint32 = 64 * 1024 // 64 MB
	ArgonThreads uint8  = 4
	KeySize             = 32 // 256-bit AES-GCM
	SaltSize            = 16
	canaryPlain         = "MalikSSM::AuthenticatedCanary::v1"
	canaryAAD           = "malik:vault:canary:v1"
)

var (
	ErrInvalidPassphrase = errors.New("invalid master passphrase or corrupted vault canary")
	ErrTamperedEnvelope  = errors.New("cryptographic integrity check failed: secret envelope or AAD was tampered with")
)

// EnvelopeBlob represents a single version's encrypted Data Encryption Key (DEK)
// and encrypted payload, bound to a specific path, version, and secret type via GCM AAD.
type EnvelopeBlob struct {
	WrappedDEK      []byte `json:"wrapped_dek"`
	DEKNonce        []byte `json:"dek_nonce"`
	Ciphertext      []byte `json:"ciphertext"`
	PayloadNonce    []byte `json:"payload_nonce"`
	Algorithm       string `json:"algorithm"`
}

// VaultKeyMeta is stored in the database header to verify master passphrases.
type VaultKeyMeta struct {
	Salt            []byte `json:"salt"`
	CanaryNonce     []byte `json:"canary_nonce"`
	CanaryEncrypted []byte `json:"canary_encrypted"`
	KDF             string `json:"kdf"`
}

// GenerateSalt creates a cryptographically random 16-byte salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to read random salt: %w", err)
	}
	return salt, nil
}

// DeriveKEK derives a 256-bit Key Encryption Key from a passphrase and salt using Argon2id.
func DeriveKEK(passphrase []byte, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)
}

// CreateVaultKeyMeta initializes a new VaultKeyMeta and returns the locked Master Key (KEK).
func CreateVaultKeyMeta(passphrase []byte) (*VaultKeyMeta, *LockedKey, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, nil, err
	}
	rawKEK := DeriveKEK(passphrase, salt)
	Zeroize(passphrase)

	nonce, encCanary, err := encryptAESGCM(rawKEK, []byte(canaryPlain), []byte(canaryAAD))
	if err != nil {
		Zeroize(rawKEK)
		return nil, nil, err
	}

	lk, err := NewLockedKey(rawKEK) // NewLockedKey zeroizes rawKEK
	if err != nil {
		return nil, nil, err
	}

	return &VaultKeyMeta{
		Salt:            salt,
		CanaryNonce:     nonce,
		CanaryEncrypted: encCanary,
		KDF:             "Argon2id(t=3,m=64MB,p=4)+AES-256-GCM",
	}, lk, nil
}

// UnlockWithPassphrase verifies the passphrase against VaultKeyMeta and returns a LockedKey in RAM.
func UnlockWithPassphrase(passphrase []byte, meta *VaultKeyMeta) (*LockedKey, error) {
	rawKEK := DeriveKEK(passphrase, meta.Salt)
	Zeroize(passphrase)

	return UnlockWithRawKEK(rawKEK, meta)
}

// UnlockWithRawKEK verifies a 32-byte raw KEK (e.g. unsealed via Windows DPAPI/TPM)
// against the vault canary and locks it into physical RAM.
func UnlockWithRawKEK(rawKEK []byte, meta *VaultKeyMeta) (*LockedKey, error) {
	if len(rawKEK) != KeySize {
		Zeroize(rawKEK)
		return nil, ErrInvalidKey
	}
	plain, err := decryptAESGCM(rawKEK, meta.CanaryNonce, meta.CanaryEncrypted, []byte(canaryAAD))
	if err != nil || string(plain) != canaryPlain {
		Zeroize(rawKEK)
		Zeroize(plain)
		return nil, ErrInvalidPassphrase
	}
	Zeroize(plain)
	return NewLockedKey(rawKEK)
}

// SealSecret performs Envelope Encryption:
// 1. Generates an ephemeral 256-bit DEK via crypto/rand.
// 2. Encrypts the secret plaintext with the DEK using AES-256-GCM and AAD bound to path+version+type.
// 3. Encrypts the DEK with the LockedKey (KEK) using AES-256-GCM and AAD bound to path+version.
// 4. Immediately zeroizes the ephemeral DEK in RAM.
func SealSecret(kek *LockedKey, path string, version int, secretType string, plaintext []byte) (*EnvelopeBlob, error) {
	if kek == nil || !kek.IsUnlocked() {
		return nil, ErrVaultLocked
	}

	dek := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral DEK: %w", err)
	}
	defer Zeroize(dek)

	payloadAAD := fmt.Appendf(nil, "payload:%s:v%d:%s", path, version, secretType)
	payloadNonce, ciphertext, err := encryptAESGCM(dek, plaintext, payloadAAD)
	if err != nil {
		return nil, err
	}

	dekAAD := fmt.Appendf(nil, "dek:%s:v%d", path, version)
	var dekNonce, wrappedDEK []byte
	err = kek.Use(func(masterKey []byte) error {
		var wrapErr error
		dekNonce, wrappedDEK, wrapErr = encryptAESGCM(masterKey, dek, dekAAD)
		return wrapErr
	})
	if err != nil {
		return nil, err
	}

	return &EnvelopeBlob{
		WrappedDEK:   wrappedDEK,
		DEKNonce:     dekNonce,
		Ciphertext:   ciphertext,
		PayloadNonce: payloadNonce,
		Algorithm:    "Envelope-AES-256-GCM-AAD",
	}, nil
}

// OpenSecret reverses Envelope Encryption, verifying both the DEK AAD and Payload AAD,
// and immediately zeroizing the ephemeral DEK in RAM before returning.
func OpenSecret(kek *LockedKey, path string, version int, secretType string, blob *EnvelopeBlob) ([]byte, error) {
	if kek == nil || !kek.IsUnlocked() {
		return nil, ErrVaultLocked
	}
	if blob == nil {
		return nil, errors.New("nil envelope blob")
	}

	dekAAD := fmt.Appendf(nil, "dek:%s:v%d", path, version)
	var dek []byte
	err := kek.Use(func(masterKey []byte) error {
		var unwrapErr error
		dek, unwrapErr = decryptAESGCM(masterKey, blob.DEKNonce, blob.WrappedDEK, dekAAD)
		return unwrapErr
	})
	if err != nil {
		return nil, ErrTamperedEnvelope
	}
	defer Zeroize(dek)

	payloadAAD := fmt.Appendf(nil, "payload:%s:v%d:%s", path, version, secretType)
	plaintext, err := decryptAESGCM(dek, blob.PayloadNonce, blob.Ciphertext, payloadAAD)
	if err != nil {
		return nil, ErrTamperedEnvelope
	}
	return plaintext, nil
}

func encryptAESGCM(key, plaintext, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func decryptAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid GCM nonce length")
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}
