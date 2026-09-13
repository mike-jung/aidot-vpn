package playintegrity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The production Decoder: a real call to Google's Play Integrity API.
//
// Until 0.18.0 this package had a verdict policy, a payload schema and
// tests — and no way to obtain a payload. `Decoder` was documented as
// "operators wire this up", which in practice meant nobody did, and the
// package sat unreachable for eleven releases.
//
// Implemented on the standard library rather than google.golang.org/api:
// the project keeps exactly one external dependency (the MySQL driver),
// and the whole interaction is two HTTP calls — a signed JWT exchanged
// for an access token, then a POST to decode the token. Pulling in the
// Google SDK for that would cost more than it saves.

const (
	tokenEndpoint  = "https://oauth2.googleapis.com/token"
	integrityScope = "https://www.googleapis.com/auth/playintegrity"
	integrityAPI   = "https://playintegrity.googleapis.com/v1"
)

// ServiceAccount is the subset of a Google service-account JSON key we
// need.
type ServiceAccount struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

// LoadServiceAccount reads a service-account key file.
func LoadServiceAccount(path string) (*ServiceAccount, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read service account: %w", err)
	}
	var sa ServiceAccount
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, fmt.Errorf("parse service account: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("service account is missing client_email or private_key")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = tokenEndpoint
	}
	return &sa, nil
}

// GoogleDecoder calls decodeIntegrityToken.
type GoogleDecoder struct {
	Account     *ServiceAccount
	PackageName string
	HTTP        *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

// NewGoogleDecoder returns a Decoder backed by Google's API.
func NewGoogleDecoder(sa *ServiceAccount, packageName string) (Decoder, error) {
	if sa == nil {
		return nil, errors.New("service account is required")
	}
	if packageName == "" {
		return nil, errors.New("package name is required")
	}
	if _, err := parsePrivateKey(sa.PrivateKey); err != nil {
		// Fail at construction rather than on the first device
		// registration. A malformed key discovered at 3am during an
		// enrolment is a much worse experience than one discovered at
		// startup.
		return nil, fmt.Errorf("service account private key: %w", err)
	}
	d := &GoogleDecoder{
		Account:     sa,
		PackageName: packageName,
		HTTP:        &http.Client{Timeout: 20 * time.Second},
	}
	return d.Decode, nil
}

// Decode exchanges an integrity token for its payload.
func (d *GoogleDecoder) Decode(ctx context.Context, token string) (*TokenPayload, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("empty integrity token")
	}
	access, err := d.accessTokenFor(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain access token: %w", err)
	}

	body, err := json.Marshal(map[string]string{"integrity_token": token})
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/%s:decodeIntegrityToken",
		integrityAPI, url.PathEscape(d.PackageName))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("decodeIntegrityToken returned %s: %s",
			resp.Status, strings.TrimSpace(string(raw)))
	}

	var wrapper struct {
		TokenPayloadExternal TokenPayload `json:"tokenPayloadExternal"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("parse decode response: %w", err)
	}
	return &wrapper.TokenPayloadExternal, nil
}

// accessTokenFor returns a cached OAuth token, minting one when needed.
func (d *GoogleDecoder) accessTokenFor(ctx context.Context) (string, error) {
	d.mu.Lock()
	// Refresh a minute early: a token that expires between our check and
	// Google's receipt of the request produces a 401 that looks like a
	// credentials problem rather than a clock race.
	if d.accessToken != "" && time.Now().Add(time.Minute).Before(d.expiresAt) {
		tok := d.accessToken
		d.mu.Unlock()
		return tok, nil
	}
	d.mu.Unlock()

	assertion, err := d.signAssertion()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.Account.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %s: %s",
			resp.Status, strings.TrimSpace(string(raw)))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", errors.New("token endpoint returned no access_token")
	}

	d.mu.Lock()
	d.accessToken = tr.AccessToken
	d.expiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	d.mu.Unlock()
	return tr.AccessToken, nil
}

// signAssertion builds the RS256 JWT that Google exchanges for a token.
func (d *GoogleDecoder) signAssertion() (string, error) {
	key, err := parsePrivateKey(d.Account.PrivateKey)
	if err != nil {
		return "", err
	}
	now := time.Now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iss":   d.Account.ClientEmail,
		"scope": integrityScope,
		"aud":   d.Account.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb)

	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	// Service account keys are PKCS#8 in practice, but PKCS#1 shows up in
	// hand-converted files often enough to be worth handling rather than
	// making an operator debug an opaque parse error.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected an RSA key, got %T", key)
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("key is neither PKCS#8 nor PKCS#1")
	}
	return key, nil
}
