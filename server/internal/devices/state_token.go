package devices

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/aidotvpn/server/internal/domain"
)

// A dedicated read-only REST credential; never reuse a WireGuard or enrollment key.
// Registration/re-registration replaces it atomically. VPN key rotation preserves it.
func issueStateToken(ctx context.Context, tx *sql.Tx, id domain.ID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	_, err := tx.ExecContext(ctx, `INSERT INTO device_state_tokens (device_id, token_hash) VALUES (?, ?)
 ON DUPLICATE KEY UPDATE token_hash=VALUES(token_hash), created_at=CURRENT_TIMESTAMP(6)`, id.Bytes(), digest[:])
	if err != nil {
		return "", fmt.Errorf("issue state credential: %w", err)
	}
	return token, nil
}
