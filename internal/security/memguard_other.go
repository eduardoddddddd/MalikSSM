//go:build !windows

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

func lockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

func unlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

// HardwareProviderName returns a human-readable description of the OS hardware/memory backing.
func HardwareProviderName() string {
	// The "seal" below derives its key from hostname, UID and machine-id, all readable on the host:
	// it binds data to the machine but is obfuscation, not hardware-backed protection.
	switch runtime.GOOS {
	case "darwin":
		return "macOS host-bound obfuscation (not hardware-backed) + unix.Mlock"
	case "linux":
		return "Linux machine-id-bound obfuscation (not hardware-backed) + unix.Mlock"
	default:
		return runtime.GOOS + " host-bound obfuscation (not hardware-backed) + unix.Mlock"
	}
}

func deriveHostKey(extraContext string, salt []byte) []byte {
	host, _ := os.Hostname()
	u, _ := user.Current()
	uid := "0"
	if u != nil {
		uid = u.Uid + ":" + u.Username + ":" + u.HomeDir
	}

	machineID := ""
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if raw, err := os.ReadFile(p); err == nil && len(raw) > 0 {
			machineID = strings.TrimSpace(string(raw))
			break
		}
	}

	material := fmt.Sprintf("MalikSSM::UnixHostSeal::%s::%s::%s::%s::%s",
		runtime.GOOS, host, uid, machineID, extraContext)
	return argon2.IDKey([]byte(material), salt, 2, 32*1024, 2, 32)
}

// ProtectBytesHardware seals sensitive bytes on macOS and Linux using Argon2id + AES-256-GCM
// bound to the host identity, OS user UID, and machine-id.
func ProtectBytesHardware(plaintext []byte, extraContext string) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("cannot protect empty payload")
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := deriveHostKey(extraContext, salt)
	defer Zeroize(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	sealed := gcm.Seal(nil, nonce, plaintext, []byte(extraContext))
	out := make([]byte, 0, len(salt)+len(nonce)+len(sealed))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// UnprotectBytesHardware unseals bytes previously protected with ProtectBytesHardware on macOS/Linux.
func UnprotectBytesHardware(ciphertext []byte, extraContext string) ([]byte, error) {
	if len(ciphertext) < 16+12 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	salt := ciphertext[:16]
	rest := ciphertext[16:]

	key := deriveHostKey(extraContext, salt)
	defer Zeroize(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return nil, fmt.Errorf("invalid sealed blob")
	}
	nonce := rest[:nonceSize]
	enc := rest[nonceSize:]
	return gcm.Open(nil, nonce, enc, []byte(extraContext))
}
