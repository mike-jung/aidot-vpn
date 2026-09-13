package auth

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadConfiguredCA never regenerates a configured CA when a file is missing or corrupt.
func LoadConfiguredCA() (*CA, error) {
	cert, key := os.Getenv("AIDOTVPN_CA_CERT_FILE"), os.Getenv("AIDOTVPN_CA_KEY_FILE")
	if cert == "" && key == "" && os.Getenv("AIDOTVPN_ENV_FILE") == "" {
		return NewCA(CAOptions{})
	}
	if !filepath.IsAbs(cert) || !filepath.IsAbs(key) {
		return nil, fmt.Errorf("AIDOTVPN_CA_CERT_FILE and AIDOTVPN_CA_KEY_FILE must be absolute paths for installed deployments")
	}
	return LoadCAFiles(cert, key)
}
