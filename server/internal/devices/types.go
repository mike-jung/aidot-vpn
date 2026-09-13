// Package devices implements device registration, key rotation, and
// listing for AidotVpn. It is the transport-agnostic layer underneath
// DeviceService — the Connect-go handlers in cmd/controller/ wrap thin
// adapters around the methods here.
//
// The package owns three responsibilities:
//
//  1. Persistence (devices, device_keys, device_psks tables).
//  2. IP allocation from the tenant's WireGuard pool.
//  3. Cryptographic material generation (PSK now; PQC hybrid PSK in Phase 6).
//
// It composes the audit and auth packages but does not own them.
package devices

import (
	"net/netip"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// Platform mirrors the SQL enum on devices.platform.
type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
	PlatformWindows Platform = "windows"
	PlatformOther   Platform = "other"
)

// Status mirrors devices.status.
type Status string

const (
	StatusPendingAttest Status = "pending_attest"
	StatusActive        Status = "active"
	StatusSuspended     Status = "suspended"
	StatusRevoked       Status = "revoked"
)

// PSKSource mirrors device_psks.source.
type PSKSource string

const (
	PSKClassical PSKSource = "classical"
	PSKPQCHybrid PSKSource = "pqc_hybrid"
	PSKManual    PSKSource = "manual"
)

// AppFilterMode mirrors devices.app_filter_mode.
type AppFilterMode string

const (
	AppFilterOff     AppFilterMode = "off"
	AppFilterInclude AppFilterMode = "include"
	AppFilterExclude AppFilterMode = "exclude"
)

// AppFilter is the per-device app-routing rule for Phase 8 per-app
// split tunneling. Mirrors the (app_filter_mode, app_filter_packages)
// columns on `devices`.
//
// Invariants enforced by the service layer (not the DB):
//   - Mode == "off" implies len(Packages) == 0
//   - Modes "include" and "exclude" allow any (possibly empty) Packages
//   - Each package name is a valid Android applicationId
//     (0–255 chars, [a-zA-Z0-9_.], at least one '.')
type AppFilter struct {
	Mode     AppFilterMode
	Packages []string
}

// Device is the row shape we expose upstream.
type Device struct {
	ID          domain.ID
	TenantID    domain.ID
	UserID      domain.ID
	InstallID   string
	DisplayName string
	Platform    Platform
	OSVersion   string
	AppVersion  string
	// The handset model as the phone reports it (Build.MANUFACTURER +
	// MODEL). The app was already sending this and the controller
	// discarded it — the reason 디바이스 showed so little. MAC is not an
	// option: Android 10+ hides it from apps and randomises it per
	// network, so it identifies nothing.
	Model string
	// Android API level, for the posture check. 0 = not reported.
	OSSdk      int
	Status     Status
	LastSeenAt *time.Time
	CreatedAt  time.Time

	// Phase 8: per-app split tunnel filter. Default {Mode: "off"} for
	// devices created before migration 0008.
	AppFilter AppFilter

	// DeploymentMode is "standalone" or "embedded" — which shell hosts
	// the VpnService on this handset (migration 0010).
	//
	// install_id is generated per app storage, so a phone running both
	// shells registers twice: two keypairs, two IP allocations, two
	// policy assignments, and two identically-named rows in the console.
	// This column exists to make that duplicate attributable. It was
	// added in 0.11.0 and then never read by any Go code until 0.17.0,
	// so the case it exists to reveal stayed invisible for six releases.
	DeploymentMode DeploymentMode

	// HostPackage is the app that owns the VpnService. Always
	// com.aidotvpn.client.app in standalone mode; the business app's
	// package in embedded mode.
	//
	// Answers "which app on this phone holds the tunnel?" without asking
	// the user to read a settings screen aloud over the phone.
	HostPackage string
}

// DeploymentMode is which Android shell hosts the tunnel.
type DeploymentMode string

const (
	// DeploymentStandalone — the AidotVpn app hosts the VpnService and
	// business apps drive it over AIDL.
	DeploymentStandalone DeploymentMode = "standalone"
	// DeploymentEmbedded — the business app embeds :vpnlib and hosts the
	// VpnService itself (single APK).
	DeploymentEmbedded DeploymentMode = "embedded"
)

// Valid reports whether m is a known mode.
func (m DeploymentMode) Valid() bool {
	return m == DeploymentStandalone || m == DeploymentEmbedded
}

// DeviceKey is one row of device_keys.
type DeviceKey struct {
	ID          domain.ID
	DeviceID    domain.ID
	PublicKey   []byte // 32 bytes
	IPv4        netip.Addr
	IPv6        netip.Addr
	ActivatedAt time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

// PSK is one row of device_psks.
type PSK struct {
	ID          domain.ID
	DeviceKeyID domain.ID
	PSK         []byte // 32 bytes
	Source      PSKSource
	ActivatedAt time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

// Allocation bundles everything a freshly-registered or rotated device
// needs to start tunneling: its key + PSK + addresses + mTLS material
// + per-app split tunnel rule.
type Allocation struct {
	StateToken          string // Read-only device state credential; issued only on registration.
	DeviceKey           DeviceKey
	PSK                 PSK
	ClientCertPEM       []byte
	ClientCertExpiresAt time.Time
	CACertPEM           []byte
	// Phase 8: per-app split tunnel filter, snapshotted at allocation
	// time. The Android client applies this when bringing the tunnel
	// up. Live updates after this snapshot require either a fresh
	// rotateKey call (12h cycle) or a Phase 9 push channel.
	AppFilter AppFilter
}

// RegisterParams is the input to Service.Register.
type RegisterParams struct {
	TenantID    domain.ID
	UserID      domain.ID
	InstallID   string
	DisplayName string
	Platform    Platform
	OSVersion   string
	AppVersion  string
	Model       string
	// Android API level, for the posture check. 0 = not reported.
	OSSdk            int
	DevicePublicKey  []byte // 32 bytes
	AttestationToken string // optional; empty -> device lands in pending_attest

	// AttestationChainPEM is the Android Key Attestation certificate
	// chain, leaf first. This is the actual evidence.
	//
	// Before 0.13.0 the HTTP layer decoded this field from the request
	// and then never passed it here, so it was silently discarded on
	// every registration while `AttestationToken` — any non-empty string
	// — decided the device's status.
	AttestationChainPEM []byte

	// DeploymentMode and HostPackage describe which shell is registering
	// (0.17.0). Empty DeploymentMode defaults to standalone, which is
	// what every pre-0.17.0 client is.
	DeploymentMode DeploymentMode
	HostPackage    string

	// KEMCiphertext is the ML-KEM-768 ciphertext the device produced by
	// encapsulating against the tenant's encapsulation key (0.20.0).
	//
	// Optional. Present means the device wants a hybrid post-quantum PSK;
	// absent means the classical PSK, which is what every client does
	// today because Android has no ML-KEM without a new dependency.
	KEMCiphertext []byte

	// ClientCertCSRPEM is a PKCS#10 CSR the device built around a
	// hardware-backed mTLS keypair (Phase 5b). When provided, the
	// controller signs the public key inside instead of generating a
	// fresh keypair server-side. Empty for legacy callers — the
	// controller falls back to server-side key generation but logs a
	// deprecation warning.
	ClientCertCSRPEM []byte
}

// RegisterResult is the output of Service.Register.
type RegisterResult struct {
	Device     Device
	Allocation Allocation
}

// RotateKeyParams is the input to Service.RotateKey.
type RotateKeyParams struct {
	// KEMCiphertext lets a rotating device keep its hybrid PSK. Absent
	// means the classical PSK, same as at registration.
	KEMCiphertext []byte

	DeviceID           domain.ID // identified by mTLS cert SAN
	NewDevicePublicKey []byte    // 32 bytes
	AttestationToken   string    // optional
	ClientCertCSRPEM   []byte    // Phase 5b: required for hardware-backed cert
}

// RotateKeyResult is the output of Service.RotateKey.
type RotateKeyResult struct {
	Allocation Allocation
}
