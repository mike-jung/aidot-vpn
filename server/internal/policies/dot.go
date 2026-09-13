package policies

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// DNS-over-TLS for the controller's hostname resolver.
//
// ## Why here and not on the client
//
// "DoT/DoH for the pushed resolver" sat in the gaps list for several
// releases. Examining it rather than implementing it changed the answer.
//
// `VpnService.Builder` accepts plain resolver addresses and nothing else —
// Android's Private DNS is a system-wide setting the user or an MDM sets,
// not something a VPN app can express. So client-side DoT is not
// available. But it also would not help, which is the more important
// half:
//
//	phone → gateway            already encrypted by WireGuard
//	gateway → internal resolver plaintext, on the hospital LAN  ← exposed
//	controller → internal resolver  plaintext  ← exposed, and ours
//
// DoT on the phone would encrypt a leg that is already inside a
// WireGuard tunnel. The leg actually exposed to a hospital-LAN observer
// runs between two machines the hospital operates, and one of them is
// this controller — which resolves every hostname policy on a five-minute
// cycle, in cleartext, revealing exactly which internal servers the VPN
// policy cares about.
//
// That is a real disclosure and one we can close without touching
// Android. So this is where DoT went.
//
// For device-wide DNS encryption, the answer is an MDM setting Private
// DNS via `DevicePolicyManager.setGlobalPrivateDnsModeSpecifiedHost`,
// not a VPN app. Documented rather than attempted.

// DoTConfig configures an encrypted upstream for hostname resolution.
type DoTConfig struct {
	// Addr is the resolver's host:port, e.g. "10.10.1.53:853".
	Addr string

	// ServerName is the name the resolver's certificate must present.
	//
	// Required, and deliberately not derived from Addr: a DoT resolver is
	// addressed by IP but authenticated by name, so taking the name from
	// the address would authenticate an IP against itself and verify
	// nothing.
	ServerName string

	// CAPath is a PEM bundle to verify the resolver against. Empty uses
	// the system roots, which is right for a public resolver and wrong
	// for an internal one signed by the hospital's own CA.
	CAPath string

	Timeout time.Duration
}

// NewDoTResolver returns a LookupIP function that talks DoT.
func NewDoTResolver(cfg DoTConfig) (func(context.Context, string) ([]netip.Addr, error), error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("DoT resolver: address is required")
	}
	if cfg.ServerName == "" {
		return nil, fmt.Errorf(
			"DoT resolver: server name is required — a resolver reached by IP is " +
				"authenticated by name, and omitting it would verify nothing")
	}
	if !strings.Contains(cfg.Addr, ":") {
		cfg.Addr = net.JoinHostPort(cfg.Addr, "853")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	tlsCfg := &tls.Config{
		ServerName: cfg.ServerName,
		MinVersion: tls.VersionTLS12,
	}
	if cfg.CAPath != "" {
		pem, err := os.ReadFile(cfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("DoT resolver: read CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("DoT resolver: %s contains no usable certificates", cfg.CAPath)
		}
		tlsCfg.RootCAs = pool
	}

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Always TCP+TLS regardless of what the resolver library
			// asks for. Go's resolver tries UDP first; honouring that
			// would silently send the query in cleartext, which is the
			// exact failure this function exists to prevent.
			d := tls.Dialer{
				NetDialer: &net.Dialer{Timeout: cfg.Timeout},
				Config:    tlsCfg,
			}
			return d.DialContext(ctx, "tcp", cfg.Addr)
		},
	}

	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return res.LookupNetIP(ctx, "ip", host)
	}, nil
}

// ResolverFromEnv builds the hostname resolver's upstream from
// configuration, returning nil when the system resolver should be used.
//
//	POLICY_RESOLVER_ADDR       10.10.1.53:53   (plaintext, existing)
//	POLICY_RESOLVER_DOT        true            (opt in to DoT)
//	POLICY_RESOLVER_DOT_NAME   dns.hospital.local
//	POLICY_RESOLVER_DOT_CA     /etc/aidotvpn/dns-ca.pem
//
// Returns an error rather than falling back when DoT is requested and
// cannot be configured. A silent downgrade to cleartext would leave an
// operator believing their DNS is encrypted while it is not — worse than
// never having offered the option.
func ResolverFromEnv() (func(context.Context, string) ([]netip.Addr, error), string, error) {
	addr := strings.TrimSpace(os.Getenv("POLICY_RESOLVER_ADDR"))
	useDoT := strings.EqualFold(strings.TrimSpace(os.Getenv("POLICY_RESOLVER_DOT")), "true")

	if !useDoT {
		if addr == "" {
			return nil, "system", nil
		}
		return NewSystemResolverAt(addr), "plaintext " + addr, nil
	}

	if addr == "" {
		return nil, "", fmt.Errorf("POLICY_RESOLVER_DOT=true requires POLICY_RESOLVER_ADDR")
	}
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "853")
	}
	name := strings.TrimSpace(os.Getenv("POLICY_RESOLVER_DOT_NAME"))
	if name == "" {
		return nil, "", fmt.Errorf(
			"POLICY_RESOLVER_DOT=true requires POLICY_RESOLVER_DOT_NAME " +
				"(the name on the resolver's certificate)")
	}

	fn, err := NewDoTResolver(DoTConfig{
		Addr:       addr,
		ServerName: name,
		CAPath:     strings.TrimSpace(os.Getenv("POLICY_RESOLVER_DOT_CA")),
	})
	if err != nil {
		return nil, "", err
	}
	return fn, "DoT " + addr + " (server_name=" + name + ")", nil
}
