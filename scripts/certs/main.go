// Generates a private CA and a server certificate using only the Go standard library.
// A renewal copies the existing CA into a new bundle; existing files are never changed.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err == nil {
		n.Add(n, big.NewInt(1))
	}
	return n, err
}
func write(dir, name, kind string, data []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{Type: kind, Bytes: data})
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
func read(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid CA PEM")
	}
	return block.Bytes, nil
}
func run() error {
	out := flag.String("out", "", "new empty bundle directory")
	existing := flag.String("ca", "", "existing CA bundle for renewal")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1", "DNS names and IP addresses")
	days := flag.Int("days", 365, "server certificate lifetime (1-365 days)")
	flag.Parse()
	if *out == "" || *days < 1 || *days > 365 || flag.NArg() != 0 {
		return errors.New("invalid certificate arguments")
	}
	now := time.Now()
	until := now.Add(time.Duration(*days) * 24 * time.Hour)
	var ca *x509.Certificate
	var caKey *ecdsa.PrivateKey
	var caDER []byte
	var err error
	if *existing == "" {
		caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		s, err := serial()
		if err != nil {
			return err
		}
		template := &x509.Certificate{SerialNumber: s, Subject: pkix.Name{CommonName: "AidotVPN Local Console CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		caDER, err = x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
		if err != nil {
			return err
		}
		ca, err = x509.ParseCertificate(caDER)
		if err != nil {
			return err
		}
	} else {
		caDER, err = read(*existing, "ca-cert.pem")
		if err != nil {
			return err
		}
		ca, err = x509.ParseCertificate(caDER)
		if err != nil {
			return err
		}
		der, err := read(*existing, "ca-key.pem")
		if err != nil {
			return err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		var ok bool
		caKey, ok = key.(*ecdsa.PrivateKey)
		if !ok || !caKey.PublicKey.Equal(ca.PublicKey) {
			return errors.New("CA key does not match certificate")
		}
		if err = ca.CheckSignatureFrom(ca); err != nil {
			return err
		}
	}
	if !ca.IsCA || now.Before(ca.NotBefore) || !until.Before(ca.NotAfter) {
		return errors.New("CA must be valid throughout the requested server certificate lifetime; choose a new output directory to create a new CA")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	s, err := serial()
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: s, Subject: pkix.Name{CommonName: "AidotVPN Console"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: until, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, host := range strings.Split(*hosts, ",") {
		if host == "" {
			return errors.New("empty certificate hostname")
		}
		if ip := net.ParseIP(host); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	leafDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		name, kind string
		data       []byte
	}{{"ca-cert.pem", "CERTIFICATE", caDER}, {"ca-key.pem", "PRIVATE KEY", keyDER}, {"cert.pem", "CERTIFICATE", der}, {"privkey.pem", "PRIVATE KEY", leafDER}} {
		if err := write(*out, item.name, item.kind, item.data); err != nil {
			return err
		}
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return os.WriteFile(filepath.Join(*out, "fullchain.pem"), chain, 0600)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Certificate generation failed:", err)
		os.Exit(1)
	}
}
