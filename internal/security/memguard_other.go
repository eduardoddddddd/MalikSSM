//go:build !windows

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/user"
)

func lockMemory(_ []byte) error {
	return nil
}

func unlockMemory(_ []byte) error {
	return nil
}

func deriveHostFallbackKey(extraContext string) []byte {
	host, _ := os.Hostname()
	u, _ := user.Current()
	uid := "0"
	if u != nil {
		uid = u.Uid + ":" + u.Username
	}
	h := sha256.New()
	h.Write([]byte("MalikSSM::FallbackKey::" + host + "::" + uid + "::" + extraContext))
	return h.Sum(nil)
}

func ProtectBytesHardware(plaintext []byte, extraContext string) ([]byte, error) {
	key := deriveHostFallbackKey(extraContext)
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
	return gcm.Seal(nonce, nonce, plaintext, []byte(extraContext)), nil
}

func UnprotectBytesHardware(ciphertext []byte, extraContext string) ([]byte, error) {
	key := deriveHostFallbackKey(extraContext)
	defer Zeroize(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	enc := ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, enc, []byte(extraContext))
}
