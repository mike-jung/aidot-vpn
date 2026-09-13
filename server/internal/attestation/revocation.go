package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Revocation checks an attestation chain against Google's published
// attestation key status list.
//
// Why this is not optional: key attestation proves a key was generated in
// genuine TEE on a Google-provisioned device. It says nothing about
// whether that device's attestation key has since been extracted and
// published. Several have been — most notably the 2022 leak of OEM
// platform keys — and a chain signed by a compromised batch key verifies
// perfectly against the Google root forever.
//
// Google maintains the list at
// https://android.googleapis.com/attestation/status, keyed by certificate
// serial number in lowercase hex. Any certificate in the chain appearing
// there invalidates the whole chain.
//
// Cache-Control on that endpoint is short; we refresh on an interval and
// keep serving the last good copy in between.
type Revocation struct {
	URL      string
	Interval time.Duration
	HTTP     *http.Client
	Logger   *slog.Logger

	// FailOpen decides what happens when the list cannot be fetched and
	// nothing is cached.
	//
	// Defaults to false (fail closed): an unreachable status list means
	// attestation cannot be completed, so registration is refused. That
	// is the correct default for a hospital, but it does couple device
	// enrolment to internet reachability — a controller on a fully
	// air-gapped network must either set FailOpen or pre-seed the cache
	// from a file. We surface the choice rather than picking silently.
	FailOpen bool

	mu        sync.RWMutex
	entries   map[string]StatusEntry
	fetchedAt time.Time
	lastErr   error
}

// StatusEntry is one revoked or suspended attestation key.
type StatusEntry struct {
	Status string `json:"status"` // REVOKED | SUSPENDED
	Reason string `json:"reason"` // KEY_COMPROMISE | CA_COMPROMISE | SUPERSEDED | SOFTWARE_FLAW
}

// DefaultStatusURL is Google's published endpoint.
const DefaultStatusURL = "https://android.googleapis.com/attestation/status"

// NewRevocation returns a checker with sensible defaults.
func NewRevocation(logger *slog.Logger) *Revocation {
	return &Revocation{
		URL:      DefaultStatusURL,
		Interval: time.Hour,
		HTTP:     &http.Client{Timeout: 15 * time.Second},
		Logger:   logger,
		entries:  map[string]StatusEntry{},
	}
}

// Start refreshes the list until ctx is cancelled.
func (r *Revocation) Start(ctx context.Context) {
	if r.Interval <= 0 {
		r.Interval = time.Hour
	}
	if err := r.refresh(ctx); err != nil && r.Logger != nil {
		r.Logger.Warn("initial attestation status fetch failed", "err", err.Error())
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.refresh(ctx); err != nil && r.Logger != nil {
				// Non-fatal: we keep serving the cached list. A stale
				// list still catches every key revoked before the last
				// successful fetch, which is far better than none.
				r.Logger.Warn("attestation status refresh failed",
					"err", err.Error(), "cache_age", time.Since(r.fetchedAt).String())
			}
		}
	}
}

func (r *Revocation) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return err
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		r.setErr(err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("status list returned %s", resp.Status)
		r.setErr(err)
		return err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		r.setErr(err)
		return err
	}
	var parsed struct {
		Entries map[string]StatusEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		r.setErr(err)
		return fmt.Errorf("parse status list: %w", err)
	}

	normalised := make(map[string]StatusEntry, len(parsed.Entries))
	for k, v := range parsed.Entries {
		normalised[normaliseSerial(k)] = v
	}

	r.mu.Lock()
	r.entries = normalised
	r.fetchedAt = time.Now()
	r.lastErr = nil
	r.mu.Unlock()

	if r.Logger != nil {
		r.Logger.Info("attestation status list refreshed", "entries", len(normalised))
	}
	return nil
}

func (r *Revocation) setErr(err error) {
	r.mu.Lock()
	r.lastErr = err
	r.mu.Unlock()
}

// Check reports the first revoked serial in the chain, or "" when clean.
//
// Returns an error only when no verdict can be reached — an empty cache
// with FailOpen unset.
func (r *Revocation) Check(serials []*big.Int) (revokedSerial string, entry StatusEntry, err error) {
	r.mu.RLock()
	entries := r.entries
	loaded := !r.fetchedAt.IsZero()
	lastErr := r.lastErr
	r.mu.RUnlock()

	if !loaded {
		if r.FailOpen {
			if r.Logger != nil {
				r.Logger.Warn("attestation status list unavailable; failing OPEN as configured")
			}
			return "", StatusEntry{}, nil
		}
		return "", StatusEntry{}, fmt.Errorf(
			"attestation status list unavailable (%v); refusing to verify without it "+
				"— set ATTESTATION_REVOCATION_FAIL_OPEN=true for air-gapped deployments",
			lastErr)
	}

	for _, s := range serials {
		if s == nil {
			continue
		}
		key := normaliseSerial(s.Text(16))
		if e, ok := entries[key]; ok {
			return key, e, nil
		}
	}
	return "", StatusEntry{}, nil
}

// Seed installs entries directly. Used by tests and by air-gapped
// deployments that mirror the list out of band.
func (r *Revocation) Seed(entries map[string]StatusEntry) {
	n := make(map[string]StatusEntry, len(entries))
	for k, v := range entries {
		n[normaliseSerial(k)] = v
	}
	r.mu.Lock()
	r.entries = n
	r.fetchedAt = time.Now()
	r.lastErr = nil
	r.mu.Unlock()
}

// normaliseSerial lowercases and strips leading zeros so that the same
// serial written either way compares equal.
//
// Google publishes serials as lowercase hex with no leading zeros, while
// Go's big.Int.Text(16) also drops them — but certificates in the wild
// and hand-mirrored lists do both, and a mismatch here silently means
// "not revoked", which is the wrong way to fail.
func normaliseSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	trimmed := strings.TrimLeft(s, "0")
	if trimmed == "" {
		return "0"
	}
	return trimmed
}
