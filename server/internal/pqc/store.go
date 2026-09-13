package pqc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// Store manages the per-tenant ML-KEM keypair in tenant_kem_keys.
//
// The table has existed since migration 0002 and held nothing: no code
// generated a keypair, so the hybrid PSK path could never run. This is
// the missing half — the pqc package's primitives were complete and
// tested the whole time.
//
// One keypair per tenant, not per device. The decapsulation key never
// leaves the controller; the encapsulation key is public by construction
// and is handed to every device of that tenant at registration. A
// per-device keypair would buy nothing: the secret that actually varies
// per device is the classical PSK, and the KEM contributes independent
// PQ-secure entropy on top of it.
type Store struct {
	DB     *sql.DB
	Logger *slog.Logger
}

// ErrNoKeypair is returned when a tenant has no keypair yet.
var ErrNoKeypair = errors.New("tenant has no ML-KEM keypair")

// EnsureKeypair returns the tenant's encapsulation key, generating the
// pair on first use.
//
// Generation is idempotent under concurrency: the INSERT is guarded by
// the table's primary key on tenant_id, and a duplicate-key error means
// another request won the race, so we re-read rather than failing. Two
// controllers starting simultaneously is a normal deployment, not an
// edge case.
func (s *Store) EnsureKeypair(ctx context.Context, tenantID domain.ID) ([]byte, error) {
	encap, err := s.EncapKey(ctx, tenantID)
	if err == nil {
		return encap, nil
	}
	if !errors.Is(err, ErrNoKeypair) {
		return nil, err
	}

	newEncap, decap, err := GenerateTenantKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate tenant keypair: %w", err)
	}

	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO tenant_kem_keys (tenant_id, algorithm, public_key, secret_key)
		VALUES (?, ?, ?, ?)`,
		tenantID.Bytes(), AlgorithmMLKEM768, newEncap, decap)
	if err != nil {
		// Lost the race — read whatever the winner wrote. Returning the
		// key we just generated would be worse than useless: devices
		// registered against it could never be decapsulated, because the
		// matching decap key was never stored.
		if existing, rerr := s.EncapKey(ctx, tenantID); rerr == nil {
			if s.Logger != nil {
				s.Logger.Info("tenant KEM keypair already existed; using the stored one",
					"tenant", tenantID.String())
			}
			return existing, nil
		}
		return nil, fmt.Errorf("store tenant keypair: %w", err)
	}

	if s.Logger != nil {
		s.Logger.Info("generated tenant ML-KEM keypair",
			"tenant", tenantID.String(), "algorithm", AlgorithmMLKEM768,
			"encap_key_bytes", len(newEncap))
	}
	return newEncap, nil
}

// EncapKey returns the tenant's public encapsulation key.
func (s *Store) EncapKey(ctx context.Context, tenantID domain.ID) ([]byte, error) {
	var (
		algorithm string
		encap     []byte
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT algorithm, public_key FROM tenant_kem_keys WHERE tenant_id = ?`,
		tenantID.Bytes()).Scan(&algorithm, &encap)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoKeypair
	}
	if err != nil {
		return nil, fmt.Errorf("read tenant encap key: %w", err)
	}
	if algorithm != AlgorithmMLKEM768 {
		// A row written by a future version with a different algorithm.
		// Refusing beats handing back a key our Decapsulate cannot use —
		// the device would encapsulate successfully and the server would
		// then derive a different PSK, producing a tunnel that
		// handshakes and drops every packet.
		return nil, fmt.Errorf("tenant keypair uses %q, this build supports %q",
			algorithm, AlgorithmMLKEM768)
	}
	if len(encap) != EncapKeySize {
		return nil, fmt.Errorf("stored encap key is %d bytes, want %d",
			len(encap), EncapKeySize)
	}
	return encap, nil
}

// DeriveShared decapsulates a device-supplied ciphertext.
func (s *Store) DeriveShared(ctx context.Context, tenantID domain.ID, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("ciphertext is %d bytes, want %d",
			len(ciphertext), CiphertextSize)
	}
	var decap []byte
	err := s.DB.QueryRowContext(ctx, `
		SELECT secret_key FROM tenant_kem_keys WHERE tenant_id = ?`,
		tenantID.Bytes()).Scan(&decap)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoKeypair
	}
	if err != nil {
		return nil, fmt.Errorf("read tenant decap key: %w", err)
	}
	return Decapsulate(decap, ciphertext)
}

// Rotate replaces a tenant's keypair.
//
// Deliberately NOT called on a schedule. Rotating invalidates every
// device's hybrid PSK at once — each one was derived from the old shared
// secret and cannot be recomputed — so the whole fleet must re-register
// before it can connect. That is an operator decision with a maintenance
// window attached, not something to do quietly every 90 days.
//
// The classical PSK is unaffected, so a device that never used the hybrid
// path keeps working.
func (s *Store) Rotate(ctx context.Context, tenantID domain.ID) error {
	encap, decap, err := GenerateTenantKeypair()
	if err != nil {
		return fmt.Errorf("generate tenant keypair: %w", err)
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE tenant_kem_keys
		   SET algorithm = ?, public_key = ?, secret_key = ?, rotated_at = ?
		 WHERE tenant_id = ?`,
		AlgorithmMLKEM768, encap, decap, time.Now().UTC(), tenantID.Bytes())
	if err != nil {
		return fmt.Errorf("rotate tenant keypair: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoKeypair
	}
	if s.Logger != nil {
		s.Logger.Warn("tenant ML-KEM keypair rotated — every device using the "+
			"hybrid PSK must re-register before it can connect",
			"tenant", tenantID.String())
	}
	return nil
}
