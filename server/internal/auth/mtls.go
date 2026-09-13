// mtls.go: an internal CA for issuing short-lived client certificates to
// AidotVpn devices.
//
// Threat model:
//
//	The CA is held by the controller process (eventually behind an HSM or
//	step-ca instance). Each registered device, after OIDC + attestation
//	checks, receives a client certificate valid for hours, not months.
//	Compromise of an issued cert is bounded by its short lifetime;
//	compromise of the CA is bounded by the limited surface that holds it.
//
// Design choices:
//
//   - ECDSA P-256 by default. Smaller, faster, no padding-oracle pitfalls.
//   - Subject CN = stringified device UUID, with the same UUID embedded as
//     a URI SAN ("urn:aidotvpn:device:<uuid>") for tooling that prefers SANs.
//   - 24-hour validity, capped, regardless of caller request.
//   - Random 128-bit serial, monotonic-ish via time prefix for ops sanity.
//
// We do not implement CRL or OCSP here. Revocation in AidotVpn is handled
// by:
//  1. short cert lifetime (24h) — most "revocations" are simply non-renewal,
//  2. a `client_certs.revoked_at` column the controller checks on every
//     incoming gRPC request as part of the auth interceptor.
package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// MaxClientCertLifetime is the absolute cap on issued cert validity. Any
// caller asking for longer is silently truncated to this value — the cap
// is a controller-policy decision, not a per-call setting.
const MaxClientCertLifetime = 24 * time.Hour

// CA holds the issuing certificate and key. Construct with NewCA() (for a
// fresh self-signed CA) or LoadCA() (from existing PEM bytes).
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// CAOptions configure a fresh CA.
type CAOptions struct {
	CommonName string
	Org        string
	ValidYears int                    // default 10
	KeyType    CAKeyType              // default ECDSAP256
	NotBefore  time.Time              // default time.Now().UTC()
	RandSource func() ([]byte, error) // default crypto/rand 16-byte serial
}

// CAKeyType selects the key algorithm for a freshly-generated CA.
type CAKeyType int

const (
	ECDSAP256 CAKeyType = iota
	ECDSAP384
	RSA2048
	RSA3072
)

// NewCA generates a fresh self-signed root CA. For production AidotVpn
// deployments the operator should pre-generate the CA offline and feed
// it to LoadCA(); NewCA() is for tests and bootstrapping.
func NewCA(opts CAOptions) (*CA, error) {
	if opts.ValidYears <= 0 {
		opts.ValidYears = 10
	}
	if opts.NotBefore.IsZero() {
		opts.NotBefore = time.Now().UTC()
	}
	if opts.CommonName == "" {
		opts.CommonName = "AidotVpn Internal CA"
	}
	if opts.Org == "" {
		opts.Org = "AidotVpn"
	}

	priv, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, fmt.Errorf("CA keygen: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Org},
		},
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotBefore.AddDate(opts.ValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // direct-issue only; no intermediates
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("CA self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("CA reparse: %w", err)
	}
	return &CA{cert: cert, key: priv}, nil
}

// LoadCA parses CA cert + key from PEM bytes.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("LoadCA: cert PEM not found or wrong type")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("LoadCA: parse cert: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("LoadCA: certificate is not a CA")
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("LoadCA: key PEM not found")
	}
	var key crypto.Signer
	switch kb.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("LoadCA: EC key: %w", err)
		}
		key = k
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("LoadCA: RSA key: %w", err)
		}
		key = k
	case "PRIVATE KEY":
		// PKCS#8 wrapper.
		k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err != nil {
			return nil, fmt.Errorf("LoadCA: PKCS#8 key: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("LoadCA: PKCS#8 key is not a Signer")
		}
		key = s
	default:
		return nil, fmt.Errorf("LoadCA: unsupported key PEM type %q", kb.Type)
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("LoadCA: public key: %w", err)
	}
	if !bytes.Equal(pub, cert.RawSubjectPublicKeyInfo) {
		return nil, errors.New("LoadCA: certificate and private key do not match")
	}
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		return nil, errors.New("LoadCA: CA certificate is not currently valid")
	}
	return &CA{cert: cert, key: key}, nil
}

// LoadCAFiles is a convenience wrapper around LoadCA that reads from disk.
func LoadCAFiles(certPath, keyPath string) (*CA, error) {
	cp, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	kp, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	return LoadCA(cp, kp)
}

// CertPEM returns the CA certificate as PEM bytes.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// KeyPEM returns the CA private key in PKCS#8 PEM form.
//
// For production this should be retrieved only via an HSM; we expose it
// here so test code can persist a freshly-generated CA between runs.
func (c *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Cert returns the parsed CA certificate.
func (c *CA) Cert() *x509.Certificate { return c.cert }

// IssuanceRequest describes a client cert request from a registered device.
//
// PublicKey is the device's keypair (typically the same Curve25519 key it
// uses for WG, but can be a separate key dedicated to the control channel).
// We do NOT accept arbitrary CSRs from the wire — the controller
// constructs this struct after attestation and OIDC verification.
type IssuanceRequest struct {
	DeviceID  domain.ID
	PublicKey crypto.PublicKey
	NotBefore time.Time     // default time.Now().UTC()
	Lifetime  time.Duration // capped at MaxClientCertLifetime
}

// CSRIssuanceRequest is the Phase 5b path: the device sends its own
// PKCS#10 CSR built around a hardware-backed private key. The controller
// verifies the CSR signature, extracts the public key, and signs a leaf
// cert. The matching private key never leaves the device.
//
// Subject and SAN fields inside the CSR are IGNORED — the controller
// always uses its own canonical subject and URI SAN
// (urn:aidotvpn:device:<uuid>) regardless of what the client requested.
// This prevents a compromised app from talking the controller into
// issuing a cert for somebody else's device id.
type CSRIssuanceRequest struct {
	DeviceID  domain.ID
	CSR       *x509.CertificateRequest
	NotBefore time.Time
	Lifetime  time.Duration
}

// IssuanceResult is what we return to the device along with metadata to
// persist in the client_certs table.
type IssuanceResult struct {
	CertPEM           []byte   // PEM-encoded leaf certificate
	Serial            *big.Int // raw serial as big.Int
	SerialBytes       []byte   // 20-byte big-endian (left-padded)
	FingerprintSHA256 []byte   // 32 bytes
	NotBefore         time.Time
	NotAfter          time.Time
}

// Issue creates a leaf client certificate signed by this CA.
func (c *CA) Issue(req IssuanceRequest) (*IssuanceResult, error) {
	if req.DeviceID.IsZero() {
		return nil, errors.New("Issue: DeviceID is zero")
	}
	if req.PublicKey == nil {
		return nil, errors.New("Issue: PublicKey is nil")
	}

	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().UTC()
	}
	lifetime := req.Lifetime
	if lifetime <= 0 || lifetime > MaxClientCertLifetime {
		lifetime = MaxClientCertLifetime
	}
	notAfter := notBefore.Add(lifetime)

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	// urn:aidotvpn:device:<uuid> SAN URI for tools that key off SANs.
	deviceURI := &url.URL{
		Scheme: "urn",
		Opaque: "aidotvpn:device:" + req.DeviceID.String(),
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   req.DeviceID.String(),
			Organization: []string{"AidotVpn"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{deviceURI},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, req.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("Issue: sign: %w", err)
	}

	fp := sha256.Sum256(der)

	// Serial as 20 bytes (RFC 5280 max length), left-padded big-endian.
	serialBytes := make([]byte, 20)
	sb := serial.Bytes()
	copy(serialBytes[20-len(sb):], sb)

	return &IssuanceResult{
		CertPEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:            serial,
		SerialBytes:       serialBytes,
		FingerprintSHA256: fp[:],
		NotBefore:         notBefore,
		NotAfter:          notAfter,
	}, nil
}

// IssueFromCSR signs a leaf cert for a client-supplied PKCS#10 CSR.
//
// The CSR is verified for cryptographic integrity (the signature is
// checked against the public key embedded in the CSR), but its subject
// and SAN fields are deliberately ignored — this is an end-entity
// issuance flow, not a CA-style "trust the CSR's identity" flow.
//
// Public key restrictions:
//   - ECDSA keys must use a NIST curve (P-256, P-384, P-521).
//   - RSA keys must be at least 2048 bits.
//   - Ed25519 is allowed.
//   - Curve25519 X25519 keys are rejected (TLS doesn't use them for auth).
func (c *CA) IssueFromCSR(req CSRIssuanceRequest) (*IssuanceResult, error) {
	if req.DeviceID.IsZero() {
		return nil, errors.New("IssueFromCSR: DeviceID is zero")
	}
	if req.CSR == nil {
		return nil, errors.New("IssueFromCSR: CSR is nil")
	}
	// Verify the CSR's self-signature. This proves the device possesses
	// the matching private key for the public key inside the CSR.
	if err := req.CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("IssueFromCSR: invalid CSR signature: %w", err)
	}
	// Validate the public key type/size. The Phase 5b mobile client
	// generates ECDSA P-256 in Android Keystore; we accept that and a
	// short list of compatible alternatives but reject anything weak.
	if err := validateCSRPublicKey(req.CSR.PublicKey); err != nil {
		return nil, fmt.Errorf("IssueFromCSR: %w", err)
	}

	// Reuse the canonical Issue path now that we have a vetted public key.
	return c.Issue(IssuanceRequest{
		DeviceID:  req.DeviceID,
		PublicKey: req.CSR.PublicKey,
		NotBefore: req.NotBefore,
		Lifetime:  req.Lifetime,
	})
}

// validateCSRPublicKey enforces the algorithm/strength policy for
// client-supplied CSRs. Keep this short and explicit — security-critical
// allowlists should err on the side of strict.
func validateCSRPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			return fmt.Errorf("ECDSA curve %s not allowed", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("RSA key %d bits below minimum 2048", k.N.BitLen())
		}
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("public key type %T not allowed", pub)
	}
}

// generateKey returns a fresh private key of the requested type.
func generateKey(t CAKeyType) (crypto.Signer, error) {
	switch t {
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

// newSerial returns a random 128-bit serial as a positive big.Int.
// We use 128 bits (RFC 5280 §4.1.2.2 recommends ≥64; CA/Browser Forum
// recommends ≥64 entropy — 128 keeps us well above either bar).
func newSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	// Ensure positive (rand.Int returns [0, max), already non-negative,
	// but defensive against zero which some software dislikes).
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n, nil
}
