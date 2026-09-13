// Service ties the repository, IP allocator, mTLS issuer, and audit log
// together to provide the operations the Connect adapter exposes as RPCs.
//
// The methods on Service are transport-agnostic: they take and return
// plain Go structs, leaving protobuf concerns to the adapter layer.
package devices

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/auth"
	"github.com/aidotvpn/server/internal/domain"
	"github.com/aidotvpn/server/internal/pqc"
)

// Service exposes the device lifecycle operations.
type Service struct {
	db       *sql.DB
	repo     *Repo
	ca       *auth.CA
	audit    *audit.Writer
	tenantID domain.ID

	// keyLifetime caps how long a device cert / key is valid before it
	// must be rotated. Defaults to 24h. Tests override with a shorter value.
	keyLifetime time.Duration

	// attestation gates registration on hardware attestation. Nil means
	// the gate is absent entirely, which behaves as AttestationOff.
	attestation *AttestationGate

	// playIntegrity gates on Google Play Integrity — a different question
	// from hardware attestation; see playintegrity_gate.go.
	playIntegrity *PlayIntegrityGate

	// kem holds the tenant ML-KEM keypairs used for hybrid PSK
	// derivation. Nil means the hybrid path is unavailable and any
	// device that supplies a ciphertext is refused rather than silently
	// downgraded.
	kem *pqc.Store

	// now is injected for testing.
	now func() time.Time
}

// SetAttestationGate installs the attestation gate. Called at wiring time
// from the controller's main().
func (s *Service) SetAttestationGate(g *AttestationGate) { s.attestation = g }

// Config configures Service.
type Config struct {
	DB          *sql.DB
	CA          *auth.CA
	Audit       *audit.Writer
	TenantID    domain.ID
	KeyLifetime time.Duration // default 24h
	Now         func() time.Time
}

// New returns a Service ready to handle device operations.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil {
		return nil, errors.New("devices.New: DB is required")
	}
	if cfg.CA == nil {
		return nil, errors.New("devices.New: CA is required")
	}
	if cfg.Audit == nil {
		return nil, errors.New("devices.New: Audit is required")
	}
	if cfg.TenantID.IsZero() {
		return nil, errors.New("devices.New: TenantID is required")
	}
	s := &Service{
		db:          cfg.DB,
		repo:        NewRepo(),
		ca:          cfg.CA,
		audit:       cfg.Audit,
		tenantID:    cfg.TenantID,
		keyLifetime: cfg.KeyLifetime,
		now:         cfg.Now,
	}
	if s.keyLifetime <= 0 {
		s.keyLifetime = 24 * time.Hour
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	return s, nil
}

// Register registers a new device or refreshes an existing one for the
// authenticated user.
//
// Idempotency: a re-registration from the same (user, install_id) returns
// the existing device record but still issues a fresh key + cert. Pre-
// existing keys for the device are revoked as part of the same Tx so the
// previous installation can no longer connect.
func (s *Service) Register(ctx context.Context, p RegisterParams) (*RegisterResult, error) {
	if err := validateRegister(p); err != nil {
		return nil, err
	}
	if p.TenantID.IsZero() {
		p.TenantID = s.tenantID
	}

	// Gate outcomes, captured inside the transaction closure and written
	// to attestation_records before it commits, so the audit row and the
	// device row land together or not at all.
	var (
		newDeviceAttestation   AttestationOutcome
		newDevicePlayIntegrity PlayIntegrityOutcome
	)

	tenant, err := s.repo.findTenant(ctx, s.db, p.TenantID)
	if err != nil {
		return nil, fmt.Errorf("Register: tenant: %w", err)
	}

	var result *RegisterResult
	err = s.tx(ctx, func(tx *sql.Tx) error {
		// Find existing device or create new.
		dev, err := s.repo.findDeviceByInstall(ctx, tx, p.UserID, p.InstallID)
		if errors.Is(err, ErrNotFound) {
			dev = &Device{
				TenantID:    p.TenantID,
				UserID:      p.UserID,
				InstallID:   p.InstallID,
				DisplayName: p.DisplayName,
				Platform:    p.Platform,
				OSVersion:   p.OSVersion,
				AppVersion:  p.AppVersion,
				Model:       p.Model,
				OSSdk:       p.OSSdk,
				Status:      StatusPendingAttest,
				CreatedAt:   s.now(),

				DeploymentMode: p.DeploymentMode,
				HostPackage:    p.HostPackage,
			}
			// Attestation decides whether this device becomes active
			// (0.13.0).
			//
			// It used to be `if p.AttestationToken != ""` — any non-empty
			// string, never verified, with the actual certificate chain
			// discarded before it got here. A device that sent the letter
			// "x" was indistinguishable from one that proved TEE-backed
			// key generation on a locked, verified-boot handset.
			//
			// A device that fails verification stays in pending_attest,
			// and since 0.10.0 the gateway installs no WireGuard peer for
			// anything but `active` — so a refused device cannot even
			// complete a handshake.
			attested, attOut, aerr := s.runAttestationWithOutcome(ctx, p)
			if aerr != nil {
				return aerr
			}
			piOut, pierr := s.runPlayIntegrity(ctx, p)
			if pierr != nil {
				return pierr
			}
			if attested {
				dev.Status = StatusActive
			}
			newDeviceAttestation = attOut
			newDevicePlayIntegrity = piOut
			if err := s.repo.insertDevice(ctx, tx, dev); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			// Existing device: revoke old keys before issuing a new one.
			// Bring a revoked device back.
			//
			// findDeviceByInstall now returns soft-deleted rows, so this
			// branch handles the re-enrolment of a handset an admin had
			// revoked. Clearing deleted_at and restoring status is what
			// "register again" means for that phone; leaving them set
			// would give it an allocation it could never use.
			if err := s.repo.reactivateDevice(ctx, tx, dev.ID); err != nil {
				return err
			}
			dev.Status = "active"

			if err := s.repo.revokeAllKeys(ctx, tx, dev.ID); err != nil {
				return fmt.Errorf("revokeAllKeys: %w", err)
			}

			// Re-attest on every registration, not just the first.
			//
			// Registration is also how a device recovers after an app
			// reinstall or a factory reset, so treating attestation as a
			// one-time gate would mean a handset that was rooted after
			// enrolment keeps its active status indefinitely. Re-checking
			// here is what makes rooting a device actually cost the
			// attacker something.
			attested, attOut, aerr := s.runAttestationWithOutcome(ctx, p)
			if aerr != nil {
				return aerr
			}
			piOut, pierr := s.runPlayIntegrity(ctx, p)
			if pierr != nil {
				return pierr
			}
			newDeviceAttestation = attOut
			newDevicePlayIntegrity = piOut
			if attested && dev.Status == StatusPendingAttest {
				if _, err := tx.ExecContext(ctx,
					`UPDATE devices SET status = 'active' WHERE id = ?`,
					dev.ID.Bytes()); err != nil {
					return fmt.Errorf("promote to active: %w", err)
				}
				dev.Status = StatusActive
			} else if !attested && dev.Status == StatusActive {
				// Previously-good device now failing. In permissive mode
				// we only log; demoting a working fleet mid-rollout would
				// be worse than the risk it addresses. Enforce mode never
				// reaches here — runAttestation returns an error.
				if s.attestation != nil && s.attestation.Logger != nil {
					s.attestation.Logger.Warn(
						"active device failed re-attestation (permissive: not demoted)",
						"device", dev.ID.String(), "install", p.InstallID)
				}
			}
			// Refresh display fields if they changed.
			//
			// deployment_mode is refreshed too (0.17.0): a site migrating
			// from the standalone app to an embedded build re-registers
			// with the same install_id, and a stale mode would tell the
			// admin the tunnel lives in an app that no longer hosts it.
			mode := p.DeploymentMode
			if !mode.Valid() {
				mode = DeploymentStandalone
			}
			if dev.DisplayName != p.DisplayName || string(dev.Platform) != string(p.Platform) ||
				dev.OSVersion != p.OSVersion || dev.AppVersion != p.AppVersion ||
				dev.Model != p.Model || dev.OSSdk != p.OSSdk ||
				dev.DeploymentMode != mode || dev.HostPackage != p.HostPackage {
				if _, err := tx.ExecContext(ctx, `
					UPDATE devices SET display_name = ?, platform = ?,
					                   os_version = ?, app_version = ?, model = ?, os_sdk = ?,
					                   deployment_mode = ?, host_package = ?
					WHERE id = ?`,
					p.DisplayName, string(p.Platform), p.OSVersion, p.AppVersion,
					nullIfEmpty(p.Model), nullIfZero(p.OSSdk), string(mode), nullIfEmpty(p.HostPackage),
					dev.ID.Bytes()); err != nil {
					return fmt.Errorf("update device fields: %w", err)
				}
				dev.DisplayName = p.DisplayName
				dev.Platform = p.Platform
				dev.OSVersion = p.OSVersion
				dev.Model = p.Model
				dev.OSSdk = p.OSSdk
				dev.AppVersion = p.AppVersion
				dev.DeploymentMode = mode
				dev.HostPackage = p.HostPackage
			}
		}

		// Record what the gates decided, whatever they decided. A refused
		// registration never reaches here (the gate returns an error), so
		// this row is the history of admissions — including permissive
		// ones that were admitted despite failing.
		s.recordAttestation(ctx, tx, dev.ID, newDeviceAttestation, newDevicePlayIntegrity)

		// Allocate IPs from the tenant's pools.
		alloc, err := s.allocateAndIssue(ctx, tx, dev, p.DevicePublicKey, tenant, p.ClientCertCSRPEM, p.KEMCiphertext)
		if err != nil {
			return err
		}

		alloc.StateToken, err = issueStateToken(ctx, tx, dev.ID)
		if err != nil {
			return err
		}

		// Snapshot the device's per-app split tunnel rule into the
		// allocation so the JSON wire format carries it without the
		// handler having to re-fetch the device. For new devices
		// findDeviceByInstall didn't run; AppFilter is the zero value
		// {Mode: ""} which we normalise to "off" downstream. For
		// existing devices the rule is whatever the admin set last.
		alloc.AppFilter = dev.AppFilter
		if alloc.AppFilter.Mode == "" {
			alloc.AppFilter.Mode = AppFilterOff
		}

		result = &RegisterResult{
			Device:     *dev,
			Allocation: *alloc,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Audit AFTER the transaction commits so we never write an audit row
	// for a failed registration.
	uid := p.UserID
	devID := result.Device.ID
	_ = s.audit.Append(ctx, audit.Entry{
		TenantID:   p.TenantID,
		ActorKind:  audit.ActorUser,
		ActorID:    &uid,
		Action:     "device.register",
		TargetKind: "device",
		TargetID:   &devID,
		Details: map[string]any{
			"install_id":  p.InstallID,
			"platform":    string(p.Platform),
			"app_version": p.AppVersion,
			"status":      string(result.Device.Status),
		},
	})

	return result, nil
}

// RotateKey issues a new keypair allocation for an already-registered
// device, preserving the device's allocated VPN addresses.
func (s *Service) RotateKey(ctx context.Context, p RotateKeyParams) (*RotateKeyResult, error) {
	if p.DeviceID.IsZero() {
		return nil, errors.New("RotateKey: DeviceID is zero")
	}
	if len(p.NewDevicePublicKey) != 32 {
		return nil, errors.New("RotateKey: NewDevicePublicKey must be 32 bytes")
	}

	dev, err := s.repo.findDeviceByID(ctx, s.db, p.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("RotateKey: %w", err)
	}
	if dev.Status == StatusRevoked {
		return nil, errors.New("RotateKey: device is revoked")
	}

	tenant, err := s.repo.findTenant(ctx, s.db, dev.TenantID)
	if err != nil {
		return nil, err
	}

	var alloc *Allocation
	err = s.tx(ctx, func(tx *sql.Tx) error {
		// Preserve current IPs across rotation.
		oldKey, err := s.repo.findActiveKey(ctx, tx, dev.ID)
		var preservedV4, preservedV6 netip.Addr
		if err == nil && oldKey != nil {
			preservedV4 = oldKey.IPv4
			preservedV6 = oldKey.IPv6
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}

		if err := s.repo.revokeAllKeys(ctx, tx, dev.ID); err != nil {
			return err
		}

		// Key rotation carries the device's fresh KEM ciphertext too: the
		// hybrid PSK is derived per device-key, so a rotation without one
		// would quietly downgrade a PQ-protected device to the classical
		// PSK at its next 12-hour cycle.
		a, err := s.allocateAndIssueWithReserved(ctx, tx, dev, p.NewDevicePublicKey,
			tenant, preservedV4, preservedV6, p.ClientCertCSRPEM, p.KEMCiphertext)
		if err != nil {
			return err
		}
		// Snapshot the per-app filter onto the rotation result the same
		// way Register does — so a 12h periodic key rotation also
		// surfaces any admin policy changes since the last rotation.
		a.AppFilter = dev.AppFilter
		if a.AppFilter.Mode == "" {
			a.AppFilter.Mode = AppFilterOff
		}
		alloc = a
		return nil
	})
	if err != nil {
		return nil, err
	}

	uid := dev.UserID
	devID := dev.ID
	_ = s.audit.Append(ctx, audit.Entry{
		TenantID:   dev.TenantID,
		ActorKind:  audit.ActorDevice,
		ActorID:    &devID,
		Action:     "device.rotate_key",
		TargetKind: "device",
		TargetID:   &devID,
		Details: map[string]any{
			"user_id": uid.String(),
		},
	})

	return &RotateKeyResult{Allocation: *alloc}, nil
}

// ListMyDevices returns every device the user owns, newest first.
func (s *Service) ListMyDevices(ctx context.Context, userID domain.ID) ([]Device, error) {
	if userID.IsZero() {
		return nil, errors.New("ListMyDevices: userID is zero")
	}
	return s.repo.listDevicesByUser(ctx, s.db, userID)
}

// Revoke marks a device as revoked and revokes all its keys.
//
// `actor` is the user or admin performing the revocation; it is recorded
// in the audit log. The caller is responsible for ensuring `actor` is
// authorized (the user owns the device, or has the realm admin role).
func (s *Service) Revoke(ctx context.Context, deviceID, actor domain.ID, reason string) error {
	if deviceID.IsZero() {
		return errors.New("Revoke: deviceID is zero")
	}
	dev, err := s.repo.findDeviceByID(ctx, s.db, deviceID)
	if err != nil {
		return fmt.Errorf("Revoke: %w", err)
	}

	err = s.tx(ctx, func(tx *sql.Tx) error {
		if err := s.repo.revokeAllKeys(ctx, tx, deviceID); err != nil {
			return err
		}
		// Mark the device's certificates revoked, with the operator's
		// reason. Previously the reason went only to the audit log, so
		// the mTLS path had no way to report why a presented cert was
		// refused.
		if err := s.revokeClientCerts(ctx, tx, deviceID, reason); err != nil {
			return err
		}
		return s.repo.softDeleteDevice(ctx, tx, deviceID)
	})
	if err != nil {
		return err
	}

	_ = s.audit.Append(ctx, audit.Entry{
		TenantID:   dev.TenantID,
		ActorKind:  audit.ActorUser,
		ActorID:    &actor,
		Action:     "device.revoke",
		TargetKind: "device",
		TargetID:   &deviceID,
		Details: map[string]any{
			"reason": reason,
		},
	})
	return nil
}

// UpdateAppFilter sets the per-device per-app split tunnel rule
// (Phase 8). The change is persisted and audited; the next time the
// device fetches its allocation (register / rotate-key / explicit
// poll) it will receive the new filter. Already-running tunnels do
// NOT pick up changes mid-session — we'd need a server-push channel
// (Phase 9) for live updates.
//
// Validation rules (enforced here, not at the DB):
//   - mode ∈ {"off", "include", "exclude"}; anything else → error
//   - mode == "off" → packages must be empty (we tolerate the call
//     succeeding with non-empty packages; we just clear them, so a
//     UI that posts both fields blindly stays correct)
//   - each package name validates against validatePackageName
//   - duplicate packages are deduped silently
//   - actor must own the device or administer its tenant — caller's
//     responsibility (the HTTP handler applies ownsDevice before calling)
func (s *Service) UpdateAppFilter(ctx context.Context, deviceID, actor domain.ID, mode AppFilterMode, packages []string) error {
	if deviceID.IsZero() {
		return errors.New("UpdateAppFilter: deviceID is zero")
	}
	switch mode {
	case AppFilterOff, AppFilterInclude, AppFilterExclude:
		// ok
	default:
		return fmt.Errorf("UpdateAppFilter: invalid mode %q", string(mode))
	}

	// Normalise: trim, dedupe, validate. 'off' wipes the list as a
	// matter of policy — we don't carry stale package lists when the
	// filter is off, and a future re-enable can repopulate.
	var clean []string
	if mode != AppFilterOff {
		seen := make(map[string]struct{}, len(packages))
		for _, raw := range packages {
			p := strings.TrimSpace(raw)
			if p == "" {
				continue
			}
			if err := validatePackageName(p); err != nil {
				return fmt.Errorf("UpdateAppFilter: package %q: %w", p, err)
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			clean = append(clean, p)
		}
	}

	dev, err := s.repo.findDeviceByID(ctx, s.db, deviceID)
	if err != nil {
		return fmt.Errorf("UpdateAppFilter: %w", err)
	}

	if err := s.repo.updateAppFilter(ctx, s.db, deviceID, mode, clean); err != nil {
		return fmt.Errorf("UpdateAppFilter: %w", err)
	}

	_ = s.audit.Append(ctx, audit.Entry{
		TenantID:   dev.TenantID,
		ActorKind:  audit.ActorUser,
		ActorID:    &actor,
		Action:     "device.app_filter.update",
		TargetKind: "device",
		TargetID:   &deviceID,
		Details: map[string]any{
			"mode":     string(mode),
			"packages": clean,
		},
	})
	return nil
}

// validatePackageName rejects strings that don't look like Android
// applicationIds. The actual rule is "package + class identifiers
// separated by '.', each segment starting with a letter, total ≤ 255
// chars". We're a touch more permissive than `aapt` — we don't enforce
// segment-starts-with-letter — but reject obvious garbage (paths,
// shell metacharacters, etc.) so a typo in the console can't end up
// in a packed JSON column on disk.
func validatePackageName(p string) error {
	if len(p) == 0 || len(p) > 255 {
		return errors.New("length must be 1–255 characters")
	}
	if !strings.Contains(p, ".") {
		return errors.New("must contain at least one '.' (e.g. com.example.app)")
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_':
			// ok
		default:
			return fmt.Errorf("invalid character %q", r)
		}
	}
	return nil
}

// --- internals ---------------------------------------------------------

// allocateAndIssue picks fresh IPs and issues a fresh PSK + client cert.
// csrPEM may be nil — in that case the server falls back to legacy
// server-generated mTLS keys (Phase 2c behaviour).
func (s *Service) allocateAndIssue(ctx context.Context, tx *sql.Tx, dev *Device,
	devicePubKey []byte, tenant *Tenant, csrPEM []byte, kemCiphertext []byte) (*Allocation, error) {
	return s.allocateAndIssueWithReserved(ctx, tx, dev, devicePubKey, tenant,
		netip.Addr{}, netip.Addr{}, csrPEM, kemCiphertext)
}

// allocateAndIssueWithReserved is the rotation-aware path that preserves
// the device's already-allocated addresses. Pass zero netip.Addrs to
// pick fresh IPs.
func (s *Service) allocateAndIssueWithReserved(ctx context.Context, tx *sql.Tx,
	dev *Device, devicePubKey []byte, tenant *Tenant,
	reservedV4, reservedV6 netip.Addr, csrPEM []byte, kemCiphertext []byte) (*Allocation, error) {

	v4Pool, err := netip.ParsePrefix(tenant.IPv4Pool)
	if err != nil {
		return nil, fmt.Errorf("tenant ipv4 pool: %w", err)
	}

	var v4 netip.Addr
	if reservedV4.IsValid() {
		v4 = reservedV4
	} else {
		v4, err = allocateIPv4(ctx, tx, tenant.ID, v4Pool)
		if err != nil {
			return nil, fmt.Errorf("allocateIPv4: %w", err)
		}
	}

	var v6 netip.Addr
	if tenant.IPv6Pool != "" {
		v6Pool, err := netip.ParsePrefix(tenant.IPv6Pool)
		if err != nil {
			return nil, fmt.Errorf("tenant ipv6 pool: %w", err)
		}
		if reservedV6.IsValid() {
			v6 = reservedV6
		} else {
			v6, err = allocateIPv6(ctx, tx, tenant.ID, v6Pool)
			if err != nil {
				return nil, fmt.Errorf("allocateIPv6: %w", err)
			}
		}
	}

	// Persist the new device key.
	now := s.now()
	expiresAt := now.Add(s.keyLifetime)
	dk := &DeviceKey{
		DeviceID:    dev.ID,
		PublicKey:   devicePubKey,
		IPv4:        v4,
		IPv6:        v6,
		ActivatedAt: now,
		ExpiresAt:   &expiresAt,
	}
	if err := s.repo.insertDeviceKey(ctx, tx, dk); err != nil {
		return nil, err
	}

	// Generate the classical PSK.
	pskBytes := make([]byte, 32)
	if _, err := rand.Read(pskBytes); err != nil {
		return nil, fmt.Errorf("psk rand: %w", err)
	}
	pskSource := PSKClassical

	// Hybrid post-quantum PSK (0.20.0).
	//
	// When the device encapsulated against the tenant's ML-KEM key and
	// sent us the ciphertext, mix the resulting shared secret into the
	// PSK. The device computes the identical value from its own copy of
	// the shared secret, so no negotiation is needed.
	//
	// Purely additive: a device that sends no ciphertext keeps the
	// classical PSK, which was always a valid PSK on its own. That
	// matters because the Android client cannot do ML-KEM without a new
	// dependency (see docs/pqc-ko.md), so for now every real client takes
	// this branch's else path — the server is ready, the client is the
	// remaining half.
	//
	// A ciphertext that IS supplied but fails to decapsulate is an error,
	// not a silent downgrade. Falling back would let an attacker strip
	// the PQ contribution by corrupting one field, which is precisely the
	// property hybrid construction exists to prevent.
	if len(kemCiphertext) > 0 {
		if s.kem == nil {
			return nil, errors.New(
				"device supplied a KEM ciphertext but this controller has no PQC store configured")
		}
		shared, kerr := s.kem.DeriveShared(ctx, dev.TenantID, kemCiphertext)
		if kerr != nil {
			return nil, fmt.Errorf("decapsulate device KEM ciphertext: %w", kerr)
		}
		hybrid, herr := pqc.HybridPSK(pskBytes, shared, dev.ID.Bytes())
		if herr != nil {
			return nil, fmt.Errorf("derive hybrid PSK: %w", herr)
		}
		pskBytes = hybrid
		pskSource = PSKPQCHybrid
	}

	psk := &PSK{
		DeviceKeyID: dk.ID,
		PSK:         pskBytes,
		Source:      pskSource,
		ActivatedAt: now,
		ExpiresAt:   &expiresAt,
	}
	if err := s.repo.insertPSK(ctx, tx, psk); err != nil {
		return nil, err
	}

	// Issue mTLS cert. Phase 5b path: client supplied a CSR around a
	// hardware-backed private key — we sign that. Legacy path: generate
	// the keypair server-side. We log a warning when we fall through to
	// the legacy path so operators can spot pre-Phase-5b clients in their
	// fleet.
	cert, err := s.issueClientCert(dev.ID, csrPEM, now)
	if err != nil {
		return nil, fmt.Errorf("issue mTLS cert: %w", err)
	}
	// Persist the certificate metadata (0.23.0). Same transaction as the
	// device key above, so the record and the credential it describes
	// commit together.
	if err := s.recordClientCert(ctx, tx, dev.ID, cert); err != nil {
		return nil, err
	}

	return &Allocation{
		DeviceKey:           *dk,
		PSK:                 *psk,
		ClientCertPEM:       cert.CertPEM,
		ClientCertExpiresAt: cert.NotAfter,
		CACertPEM:           s.ca.CertPEM(),
	}, nil
}

// issueClientCert issues an mTLS client cert. Honours CSR if provided.
func (s *Service) issueClientCert(deviceID domain.ID, csrPEM []byte, now time.Time) (*auth.IssuanceResult, error) {
	if len(csrPEM) > 0 {
		block, _ := pem.Decode(csrPEM)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("CSR PEM block missing or wrong type")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CSR: %w", err)
		}
		return s.ca.IssueFromCSR(auth.CSRIssuanceRequest{
			DeviceID:  deviceID,
			CSR:       csr,
			NotBefore: now,
			Lifetime:  s.keyLifetime,
		})
	}

	// Legacy path: server-generated key. Discouraged from Phase 5b on,
	// but still supported so old clients don't break.
	ctlKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("control key gen: %w", err)
	}
	return s.ca.Issue(auth.IssuanceRequest{
		DeviceID:  deviceID,
		PublicKey: &ctlKey.PublicKey,
		NotBefore: now,
		Lifetime:  s.keyLifetime,
	})
}

func (s *Service) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func validateRegister(p RegisterParams) error {
	if p.UserID.IsZero() {
		return errors.New("Register: UserID is zero")
	}
	if err := validateInstallID(p.InstallID); err != nil {
		return err
	}
	if p.DisplayName == "" {
		return errors.New("Register: DisplayName is required")
	}
	if len(p.DisplayName) > 128 {
		return errors.New("Register: DisplayName too long")
	}
	if len(p.DevicePublicKey) != 32 {
		return errors.New("Register: DevicePublicKey must be 32 bytes")
	}
	switch p.Platform {
	case PlatformAndroid, PlatformIOS, PlatformLinux,
		PlatformMacOS, PlatformWindows, PlatformOther, "":
	default:
		return fmt.Errorf("Register: unknown platform %q", p.Platform)
	}
	return nil
}

// suppress unused import warnings if helpers are trimmed later.
var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)

// SetKEMStore installs the PQC keypair store, enabling hybrid PSKs.
func (s *Service) SetKEMStore(st *pqc.Store) { s.kem = st }

// KEMStore returns the configured store, or nil.
func (s *Service) KEMStore() *pqc.Store { return s.kem }

// ListTenantDevices returns every device in a tenant. Admin-facing.
//
// Separate from ListMyDevices rather than a flag on it, so the caller
// has to say which they mean — the two answer different questions and
// silently widening one to the other is how a clinician ends up seeing
// the whole hospital's handsets.
func (s *Service) ListTenantDevices(ctx context.Context, tenantID domain.ID) ([]Device, error) {
	if tenantID.IsZero() {
		return nil, errors.New("ListTenantDevices: tenantID is zero")
	}
	return s.repo.listDevicesByTenant(ctx, s.db, tenantID)
}

// Get returns a single device by ID.
//
// Added in 0.26.0 for the /devices/{id}/effective endpoint. The service
// could list a user's devices and register one, but not read a specific
// one — every caller that needed a single device had been going through
// ListMyDevices and filtering, which does not work for an admin looking
// at someone else's handset.
func (s *Service) Get(ctx context.Context, deviceID domain.ID) (*Device, error) {
	return s.repo.findDeviceByID(ctx, s.db, deviceID)
}

// nullIfZero keeps "not reported" distinct from "reported as zero" in
// the posture columns: the check skips a NULL and would wrongly fail a 0.
func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
