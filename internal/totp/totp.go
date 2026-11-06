package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Result contains the generated TOTP code and its validity window.
type Result struct {
	Code             string `json:"code"`
	Period           int    `json:"period"`
	SecondsRemaining int    `json:"seconds_remaining"`
	Digits           int    `json:"digits"`
	Algorithm        string `json:"algorithm"`
}

// Generate computes the current RFC 6238 TOTP code from either a Base32 secret string
// or a full otpauth://totp/... URI.
func Generate(secretOrURI string, now time.Time) (*Result, error) {
	rawSecret := strings.TrimSpace(secretOrURI)
	digits := 6
	period := 30
	algo := "SHA1"

	if strings.HasPrefix(strings.ToLower(rawSecret), "otpauth://") {
		u, err := url.Parse(rawSecret)
		if err != nil {
			return nil, fmt.Errorf("invalid otpauth URI: %w", err)
		}
		q := u.Query()
		rawSecret = q.Get("secret")
		if d := q.Get("digits"); d != "" {
			if parsed, err := strconv.Atoi(d); err == nil && (parsed == 6 || parsed == 8) {
				digits = parsed
			}
		}
		if p := q.Get("period"); p != "" {
			if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
				period = parsed
			}
		}
		if a := strings.ToUpper(q.Get("algorithm")); a == "SHA1" || a == "SHA256" || a == "SHA512" {
			algo = a
		}
	}

	// Normalize Base32 secret (strip spaces, hyphens, uppercase, pad with '=')
	cleaned := strings.ToUpper(rawSecret)
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.TrimRight(cleaned, "=")
	if cleaned == "" {
		return nil, fmt.Errorf("empty TOTP secret")
	}
	if rem := len(cleaned) % 8; rem != 0 {
		cleaned += strings.Repeat("=", 8-rem)
	}

	key, err := base32.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid Base32 TOTP secret: %w", err)
	}

	unixSec := now.Unix()
	counter := uint64(unixSec / int64(period))
	remaining := period - int(unixSec%int64(period))

	var hasher func() hash.Hash
	switch algo {
	case "SHA256":
		hasher = sha256.New
	case "SHA512":
		hasher = sha512.New
	default:
		hasher = sha1.New
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(hasher, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)

	mod := int(math.Pow10(digits))
	otp := binCode % mod
	formatStr := fmt.Sprintf("%%0%dd", digits)

	return &Result{
		Code:             fmt.Sprintf(formatStr, otp),
		Period:           period,
		SecondsRemaining: remaining,
		Digits:           digits,
		Algorithm:        algo,
	}, nil
}
