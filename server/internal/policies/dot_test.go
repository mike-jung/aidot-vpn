package policies

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A real DNS-over-TLS exchange, end to end.
//
// This is the leg that is actually exposed: the controller resolves every
// hostname policy on a five-minute cycle, and doing so in cleartext tells
// anyone on the hospital LAN exactly which internal servers the VPN
// policy cares about. Client-side DoT would encrypt a leg already inside
// a WireGuard tunnel; this encrypts the one that isn't.
func TestDoTResolvesOverTLS(t *testing.T) {
	dir := t.TempDir()
	caPath, srvCert := issueDoTCerts(t, dir)

	addr := startDoTServer(t, srvCert, "emr.hospital.local.", net.IPv4(10, 10, 5, 20))

	lookup, err := NewDoTResolver(DoTConfig{
		Addr:       addr,
		ServerName: "dns.hospital.local",
		CAPath:     caPath,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	addrs, err := lookup(context.Background(), "emr.hospital.local")
	if err != nil {
		t.Fatalf("lookup over DoT: %v", err)
	}
	if len(addrs) != 1 || addrs[0].Unmap().String() != "10.10.5.20" {
		t.Fatalf("got %v, want [10.10.5.20]", addrs)
	}
}

// A resolver presenting a certificate for the wrong name must be refused.
// Without this the encryption is theatre: an attacker who can redirect
// the resolver address terminates the TLS themselves and reads every
// query.
func TestDoTRejectsWrongServerName(t *testing.T) {
	dir := t.TempDir()
	caPath, srvCert := issueDoTCerts(t, dir)
	addr := startDoTServer(t, srvCert, "emr.hospital.local.", net.IPv4(10, 10, 5, 20))

	lookup, err := NewDoTResolver(DoTConfig{
		Addr:       addr,
		ServerName: "attacker.example.com",
		CAPath:     caPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lookup(context.Background(), "emr.hospital.local"); err == nil {
		t.Fatal("a certificate for the wrong name must not be accepted")
	}
}

// An untrusted issuer must be refused too — the internal CA is the point.
func TestDoTRejectsUntrustedIssuer(t *testing.T) {
	dir := t.TempDir()
	_, srvCert := issueDoTCerts(t, dir)
	addr := startDoTServer(t, srvCert, "emr.hospital.local.", net.IPv4(10, 10, 5, 20))

	// No CAPath → system roots, which do not include our test CA.
	lookup, err := NewDoTResolver(DoTConfig{
		Addr:       addr,
		ServerName: "dns.hospital.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lookup(context.Background(), "emr.hospital.local"); err == nil {
		t.Fatal("a certificate from an unknown CA must not be accepted")
	}
}

// Omitting the server name would authenticate an IP against itself.
func TestDoTRequiresServerName(t *testing.T) {
	if _, err := NewDoTResolver(DoTConfig{Addr: "10.10.1.53:853"}); err == nil {
		t.Fatal("server name must be required")
	}
}

// Misconfiguration must fail loudly rather than downgrading. An operator
// who set POLICY_RESOLVER_DOT=true and silently got cleartext would be
// worse off than one who never had the option.
func TestResolverFromEnvRefusesIncompleteDoT(t *testing.T) {
	t.Setenv("POLICY_RESOLVER_DOT", "true")
	t.Setenv("POLICY_RESOLVER_ADDR", "")
	if _, _, err := ResolverFromEnv(); err == nil {
		t.Error("DoT without an address must be refused")
	}

	t.Setenv("POLICY_RESOLVER_ADDR", "10.10.1.53")
	t.Setenv("POLICY_RESOLVER_DOT_NAME", "")
	if _, _, err := ResolverFromEnv(); err == nil {
		t.Error("DoT without a server name must be refused")
	}
}

func TestResolverFromEnvDefaultsToSystem(t *testing.T) {
	t.Setenv("POLICY_RESOLVER_DOT", "")
	t.Setenv("POLICY_RESOLVER_ADDR", "")
	fn, desc, err := ResolverFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if fn != nil {
		t.Error("no configuration should leave the system resolver in place")
	}
	if desc != "system" {
		t.Errorf("describe = %q", desc)
	}
}

// ---- helpers -------------------------------------------------------------

func issueDoTCerts(t *testing.T, dir string) (caPath string, srvCert tls.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Hospital DNS CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCrt, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srvTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dns.hospital.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"dns.hospital.local"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCrt, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return caPath, tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvKey,
	}
}

// startDoTServer runs a minimal RFC 7858 responder answering one A record.
func startDoTServer(t *testing.T, cert tls.Certificate, name string, ip net.IP) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					msg := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, msg); err != nil {
						return
					}
					resp := dnsAnswer(msg, name, ip.To4())
					if resp == nil {
						return
					}
					var out [2]byte
					binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
					_, _ = c.Write(out[:])
					_, _ = c.Write(resp)
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func dnsAnswer(q []byte, name string, ip net.IP) []byte {
	if len(q) < 12 {
		return nil
	}
	qname, off := dnsParseName(q, 12)
	if off+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[off : off+2])
	match := strings.EqualFold(qname, name) && qtype == 1

	r := make([]byte, 0, 128)
	r = append(r, q[0], q[1], 0x81, 0x80, 0x00, 0x01)
	if match {
		r = append(r, 0x00, 0x01)
	} else {
		r = append(r, 0x00, 0x00)
	}
	r = append(r, 0, 0, 0, 0)
	r = append(r, q[12:off+4]...)
	if match {
		r = append(r, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04)
		r = append(r, ip...)
	}
	return r
}

func dnsParseName(b []byte, i int) (string, int) {
	var sb strings.Builder
	for i < len(b) && b[i] != 0 {
		n := int(b[i])
		i++
		if i+n > len(b) {
			break
		}
		sb.Write(b[i : i+n])
		sb.WriteByte('.')
		i += n
	}
	return sb.String(), i + 1
}
