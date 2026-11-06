package security

import (
	"crypto/subtle"
	"errors"
	"runtime"
	"sync"
)

var (
	ErrVaultLocked = errors.New("vault is currently locked (master key not present in memory)")
	ErrInvalidKey  = errors.New("invalid key length: expected 32 bytes (256 bits)")
)

// Zeroize overwrites a byte slice with zeros and enforces a compiler barrier
// via runtime.KeepAlive so dead-store optimization cannot strip the wipe.
func Zeroize(b []byte) {
	if len(b) == 0 {
		return
	}
	clear(b)
	runtime.KeepAlive(b)
}

// ConstantTimeEqual compares two byte slices in constant time to prevent timing side-channels.
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// LockedKey holds a 256-bit Master Key (KEK) locked in physical RAM via OS VirtualLock/mlock
// so the operating system never swaps the key out to pagefile.sys / swap disk.
type LockedKey struct {
	mu     sync.RWMutex
	buf    []byte
	locked bool
}

// NewLockedKey allocates a dedicated buffer, copies the 32-byte key into it,
// locks the memory pages in physical RAM, and immediately zeroizes the caller's input slice.
func NewLockedKey(rawKey []byte) (*LockedKey, error) {
	if len(rawKey) != 32 {
		Zeroize(rawKey)
		return nil, ErrInvalidKey
	}
	buf := make([]byte, 32)
	copy(buf, rawKey)
	Zeroize(rawKey)

	locked := lockMemory(buf) == nil
	return &LockedKey{
		buf:    buf,
		locked: locked,
	}, nil
}

// Use executes fn with read-only access to the locked key inside a read lock.
// Callers must NOT retain a reference to the slice outside the callback.
func (lk *LockedKey) Use(fn func(key []byte) error) error {
	lk.mu.RLock()
	defer lk.mu.RUnlock()

	if len(lk.buf) != 32 {
		return ErrVaultLocked
	}
	return fn(lk.buf)
}

// IsUnlocked returns true if the key is currently active in RAM.
func (lk *LockedKey) IsUnlocked() bool {
	lk.mu.RLock()
	defer lk.mu.RUnlock()
	return len(lk.buf) == 32
}

// Destroy immediately wipes the Master Key in physical RAM with zeros and unlocks the page.
func (lk *LockedKey) Destroy() {
	lk.mu.Lock()
	defer lk.mu.Unlock()

	if len(lk.buf) > 0 {
		Zeroize(lk.buf)
		if lk.locked {
			_ = unlockMemory(lk.buf)
			lk.locked = false
		}
		lk.buf = nil
	}
}
