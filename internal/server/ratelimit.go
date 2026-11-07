package server

import (
	"context"
	"sync"
	"time"
)

const (
	maxPassphraseFailures = 5
	failureWindow         = 15 * time.Minute
	lockoutDuration       = 15 * time.Minute
	// Each passphrase check runs Argon2id with 64 MB of RAM; cap how many run at once so a burst of
	// login attempts cannot exhaust the server's memory.
	maxConcurrentKDF = 2
)

type failRecord struct {
	count        int
	first        time.Time
	blockedUntil time.Time
}

// authLimiter throttles passphrase-based endpoints (init, unlock, login) per client IP and bounds
// the number of concurrent Argon2id derivations.
type authLimiter struct {
	mu    sync.Mutex
	fails map[string]*failRecord
	kdf   chan struct{}
	now   func() time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{
		fails: make(map[string]*failRecord),
		kdf:   make(chan struct{}, maxConcurrentKDF),
		now:   time.Now,
	}
}

// blocked reports whether ip is currently locked out and for how long.
func (l *authLimiter) blocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.fails[ip]
	if !ok {
		return false, 0
	}
	now := l.now()
	if now.Before(rec.blockedUntil) {
		return true, rec.blockedUntil.Sub(now)
	}
	if now.Sub(rec.first) > failureWindow {
		delete(l.fails, ip)
	}
	return false, 0
}

func (l *authLimiter) failure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	rec, ok := l.fails[ip]
	if !ok || now.Sub(rec.first) > failureWindow {
		rec = &failRecord{first: now}
		l.fails[ip] = rec
	}
	rec.count++
	if rec.count >= maxPassphraseFailures {
		rec.blockedUntil = now.Add(lockoutDuration)
	}
}

func (l *authLimiter) success(ip string) {
	l.mu.Lock()
	delete(l.fails, ip)
	l.mu.Unlock()
}

// acquireKDF waits for a free Argon2id slot; the returned func releases it.
func (l *authLimiter) acquireKDF(ctx context.Context) (func(), error) {
	select {
	case l.kdf <- struct{}{}:
		return func() { <-l.kdf }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
