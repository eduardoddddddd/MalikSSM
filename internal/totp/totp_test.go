package totp

import (
	"testing"
	"time"
)

func TestTOTPGeneration(t *testing.T) {
	// RFC 6238 ASCII "12345678901234567890" -> Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	res, err := Generate(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(res.Code) != 6 || res.Code != "287082" {
		t.Fatalf("expected RFC 6238 vector 287082 at t=59, got %s", res.Code)
	}

	// Test otpauth:// URI with spaces/hyphens
	uri := "otpauth://totp/GitHub:edu?secret=JBSW-Y3DP-EHPK-3PXP&issuer=GitHub&digits=6&period=30"
	res2, err := Generate(uri, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("Generate URI failed: %v", err)
	}
	if len(res2.Code) != 6 {
		t.Fatalf("expected 6 digit code, got %s", res2.Code)
	}
}
