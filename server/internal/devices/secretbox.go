package devices

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Encryption at rest for settings that must remain readable.
//
// The enrollment password has to be shown in plaintext — an admin reads
// it aloud to whoever is holding the phone. So hashing is out; this is
// reversible by design.
//
// ## What this actually protects against
//
// Not an attacker who has the server: the key is in the server's
// environment, so anything that reads `.env` reads the password too.
//
// It protects against the database alone. A nightly backup on a share, a
// dump attached to a ticket, a read replica, a SQL injection that can
// SELECT but not read files — in all of those the ciphertext is useless
// without a key that never went into the database. Those are the ways
// this kind of value actually leaks, and they are worth defending even
// though a full host compromise defeats it.
//
// Values are stored with an algorithm prefix so the format is
// self-describing and a row can be read without guessing:
//
//	aesgcm:<base64(nonce ‖ ciphertext ‖ tag)>
//	plain:<value>      — no key configured
//
// The `plain:` case is deliberate rather than a silent fallback to
// encryption-shaped storage. A deployment with no key should look
// unencrypted in the database, because it is.

const (
	prefixAESGCM = "aesgcm:"
	prefixPlain  = "plain:"

	// SettingsKeyEnv holds base64 of 32 random bytes. `npm start`
	// generates one when .env lacks it.
	SettingsKeyEnv = "SETTINGS_ENCRYPTION_KEY"
)

// ErrSettingsKey is returned when a stored value needs a key that is
// absent or wrong — a misconfiguration, not a corrupt row.
var ErrSettingsKey = errors.New("SETTINGS_ENCRYPTION_KEY 가 없거나 올바르지 않습니다")

func settingsKey() ([]byte, bool) {
	raw := os.Getenv(SettingsKeyEnv)
	if raw == "" {
		return nil, false
	}
	k, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(k) != 32 {
		return nil, false
	}
	return k, true
}

// sealSetting encrypts a value for storage.
func sealSetting(plaintext string) (string, error) {
	key, ok := settingsKey()
	if !ok {
		return prefixPlain + plaintext, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("sealSetting: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("sealSetting: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("sealSetting: nonce: %w", err)
	}
	// Nonce prepended to the sealed output, which is how it is recovered
	// on the way back. GCM needs it and it is not secret.
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefixAESGCM + base64.StdEncoding.EncodeToString(sealed), nil
}

// openSetting decrypts a stored value.
//
// Accepts a bare value with no prefix as plaintext, so rows written
// before 1.2.3 keep working. They are re-encrypted on the next write.
func openSetting(stored string) (string, error) {
	switch {
	case strings.HasPrefix(stored, prefixPlain):
		return strings.TrimPrefix(stored, prefixPlain), nil

	case strings.HasPrefix(stored, prefixAESGCM):
		key, ok := settingsKey()
		if !ok {
			return "", ErrSettingsKey
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, prefixAESGCM))
		if err != nil {
			return "", fmt.Errorf("openSetting: base64: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("openSetting: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("openSetting: %w", err)
		}
		if len(raw) < gcm.NonceSize() {
			return "", errors.New("openSetting: ciphertext too short")
		}
		nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
		out, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			// GCM authenticates, so this is a wrong key or a tampered
			// row — not something to paper over with a fallback.
			return "", ErrSettingsKey
		}
		return string(out), nil

	default:
		// Pre-1.2.3 rows.
		return stored, nil
	}
}
