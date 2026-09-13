package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredCAPersistsAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(CAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err = os.WriteFile(certFile, ca.CertPEM(), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AIDOTVPN_ENV_FILE", filepath.Join(dir, "controller.env"))
	t.Setenv("AIDOTVPN_CA_CERT_FILE", certFile)
	t.Setenv("AIDOTVPN_CA_KEY_FILE", keyFile)
	first, err := LoadConfiguredCA()
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadConfiguredCA()
	if err != nil {
		t.Fatal(err)
	}
	if string(first.CertPEM()) != string(second.CertPEM()) {
		t.Fatal("CA changed across load")
	}
	other, err := NewCA(CAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := other.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = LoadCA(ca.CertPEM(), otherKey); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if err = os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadConfiguredCA(); err == nil {
		t.Fatal("missing key silently regenerated")
	}
	t.Setenv("AIDOTVPN_CA_CERT_FILE", "")
	t.Setenv("AIDOTVPN_CA_KEY_FILE", "")
	if _, err = LoadConfiguredCA(); err == nil {
		t.Fatal("installed deployment accepted ephemeral CA")
	}
}
