package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP, RFC 6238, in the standard library.
//
// The algorithm is thirty lines and the dependencies are hmac, sha1 and
// base32 — all in the standard library. Pulling a module in for this
// would add a supply chain to the one part of the system that decides
// whether someone is who they claim to be.
//
// SHA-1 is correct here and not a lapse: RFC 6238's default, what every
// authenticator app implements, and HMAC-SHA1's security does not rest
// on SHA-1's collision resistance.

const (
	totpPeriod = 30 * time.Second
	totpDigits = 6

	// One step either side.
	//
	// Phone clocks drift and people finish typing after the code turns
	// over. Wider than one step starts to matter: each extra step is
	// another thirty seconds in which a shoulder-surfed code still
	// works.
	totpSkew = 1
)

// NewTOTPSecret returns a fresh base32 secret.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, 20) // 160 bits, RFC 4226's recommendation
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "="), nil
}

// TOTPURI builds the otpauth:// URI an authenticator app scans.
func TOTPURI(secret, issuer, account string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", int(totpPeriod.Seconds())))
	return fmt.Sprintf("otpauth://totp/%s:%s?%s",
		url.PathEscape(issuer), url.PathEscape(account), v.Encode())
}

// VerifyTOTP checks a code against the secret, allowing one step of skew.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits || secret == "" {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	counter := now.Unix() / int64(totpPeriod.Seconds())
	for skew := -totpSkew; skew <= totpSkew; skew++ {
		// hmac.Equal, not ==: comparing generated codes with a
		// short-circuiting compare leaks how many leading digits were
		// right, one request at a time.
		if hmac.Equal([]byte(hotp(key, counter+int64(skew))), []byte(code)) {
			return true
		}
	}
	return false
}

func hotp(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (int64(sum[offset]&0x7f) << 24) |
		(int64(sum[offset+1]) << 16) |
		(int64(sum[offset+2]) << 8) |
		int64(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, value%1_000_000)
}
