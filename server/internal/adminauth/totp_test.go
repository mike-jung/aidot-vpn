package adminauth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, the SHA-1 rows.
//
// Hand-rolled crypto is checked against the specification's own vectors
// or it is not checked at all: an implementation that is self-consistent
// and wrong produces codes no authenticator app will ever match, and the
// first person to find out is an admin locked out of the console.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// The RFC's seed is the ASCII "12345678901234567890".
	secret := strings.TrimRight(
		base32.StdEncoding.EncodeToString([]byte("12345678901234567890")), "=")

	// Times from Appendix B with their 8-digit codes; we emit 6, so
	// compare the last six as the RFC's truncation defines.
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		at := time.Unix(c.unix, 0).UTC()
		if !VerifyTOTP(secret, c.want, at) {
			t.Errorf("code %s should verify at %d", c.want, c.unix)
		}
	}
}

func TestTOTPRejectsWrongCode(t *testing.T) {
	s, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyTOTP(s, "000000", time.Now()) && VerifyTOTP(s, "111111", time.Now()) {
		t.Error("two different wrong codes both verified")
	}
	if VerifyTOTP(s, "12345", time.Now()) {
		t.Error("a five-digit code verified")
	}
	if VerifyTOTP("", "123456", time.Now()) {
		t.Error("an empty secret verified")
	}
}

// A code from two minutes ago must not work; skew is one step, not four.
func TestTOTPRejectsStaleCode(t *testing.T) {
	secret := strings.TrimRight(
		base32.StdEncoding.EncodeToString([]byte("12345678901234567890")), "=")
	if VerifyTOTP(secret, "287082", time.Unix(59+120, 0).UTC()) {
		t.Error("a code two minutes old verified")
	}
}

func TestTOTPURIIsScannable(t *testing.T) {
	u := TOTPURI("ABCDEF", "AidotVpn", "admin@aidot-link.com")
	for _, want := range []string{"otpauth://totp/", "secret=ABCDEF", "issuer=AidotVpn", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("URI missing %q: %s", want, u)
		}
	}
}
