package devices

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/aidotvpn/server/internal/auth"
	"github.com/aidotvpn/server/internal/domain"
)

// Certificate bookkeeping, wired in 0.23.0.
//
// `client_certs` has existed since migration 0001, with a comment
// describing exactly what it is for — "we record only the issued cert
// metadata and a SHA-256 fingerprint, never the private key" — and no
// code has ever inserted a row. `auth.IssuanceResult` even carries every
// column the table wants (serial, fingerprint, validity window) purely so
// a caller could persist them. Nobody did.
//
// The consequences are not academic. Without these rows there is:
//
//   - no way to answer "which certificates are outstanding for this
//     device", which is the first question in any incident;
//   - no revocation list, so `auth.mtls`'s documented `revoked_at` check
//     has nothing to check against;
//   - no expiry visibility, so an operator cannot see a fleet about to
//     fall off a cliff until it does.
//
// Four columns leave the wiring baseline with this: fingerprint_sha256,
// not_before, not_after and revocation_reason.

// recordClientCert persists the metadata of a freshly issued certificate.
//
// Runs inside the registration transaction so the certificate record and
// the device key it belongs to commit together. A cert row without its
// key — or a key whose cert was never recorded — would be worse than
// either alone, because the revocation path would then disagree with the
// authentication path about what exists.
func (s *Service) recordClientCert(
	ctx context.Context,
	q executor,
	deviceID domain.ID,
	res *auth.IssuanceResult,
) error {
	if res == nil {
		// The legacy server-side-keygen path can return nil when no CSR
		// was supplied. Nothing to record; not an error.
		return nil
	}
	if len(res.SerialBytes) == 0 || len(res.FingerprintSHA256) == 0 {
		// Refusing beats inserting a row with zeroed identifiers: the
		// unique keys on serial and fingerprint would then collide on
		// the *second* such cert, turning a silent bookkeeping gap into
		// a registration failure much later and far from the cause.
		return fmt.Errorf("recordClientCert: issuance result is missing serial or fingerprint")
	}

	_, err := q.ExecContext(ctx, `
		INSERT INTO client_certs
		  (id, device_id, serial, fingerprint_sha256, not_before, not_after)
		VALUES (?, ?, ?, ?, ?, ?)`,
		domain.NewID().Bytes(), deviceID.Bytes(),
		res.SerialBytes, res.FingerprintSHA256,
		res.NotBefore.UTC(), res.NotAfter.UTC())
	if err != nil {
		return fmt.Errorf("recordClientCert: %w", err)
	}
	return nil
}

// revokeClientCerts marks a device's outstanding certificates revoked.
//
// The reason is stored rather than only audited. Both matter and they
// answer different questions: the audit log records that a human took an
// action, while this column lets the mTLS path report *why* a
// presented certificate is refused — which is the difference between a
// device showing "access revoked: lost handset" and showing a generic
// handshake failure.
func (s *Service) revokeClientCerts(
	ctx context.Context,
	q executor,
	deviceID domain.ID,
	reason string,
) error {
	if reason == "" {
		reason = "unspecified"
	}
	if len(reason) > 128 {
		reason = reason[:128]
	}
	_, err := q.ExecContext(ctx, `
		UPDATE client_certs
		   SET revoked_at = CURRENT_TIMESTAMP(6), revocation_reason = ?
		 WHERE device_id = ? AND revoked_at IS NULL`,
		reason, deviceID.Bytes())
	if err != nil {
		return fmt.Errorf("revokeClientCerts: %w", err)
	}
	return nil
}

// ClientCert is one row of client_certs, for the console's device detail
// view.
type ClientCert struct {
	Serial            []byte
	FingerprintSHA256 []byte
	NotBefore         string
	NotAfter          string
	RevokedAt         string
	RevocationReason  string
}

// ListClientCerts returns a device's certificates, newest first.
func (s *Service) ListClientCerts(ctx context.Context, deviceID domain.ID) ([]ClientCert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT serial, fingerprint_sha256,
		       DATE_FORMAT(not_before, '%Y-%m-%dT%H:%i:%sZ'),
		       DATE_FORMAT(not_after,  '%Y-%m-%dT%H:%i:%sZ'),
		       COALESCE(DATE_FORMAT(revoked_at, '%Y-%m-%dT%H:%i:%sZ'), ''),
		       COALESCE(revocation_reason, '')
		  FROM client_certs
		 WHERE device_id = ?
		 ORDER BY not_before DESC`,
		deviceID.Bytes())
	if err != nil {
		return nil, fmt.Errorf("ListClientCerts: %w", err)
	}
	defer rows.Close()

	var out []ClientCert
	for rows.Next() {
		var c ClientCert
		if err := rows.Scan(&c.Serial, &c.FingerprintSHA256,
			&c.NotBefore, &c.NotAfter, &c.RevokedAt, &c.RevocationReason); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

var _ = sql.ErrNoRows
