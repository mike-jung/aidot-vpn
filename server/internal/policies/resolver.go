package policies

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// Resolver keeps hostname-based policy rules current.
//
// An admin writes `emr.hospital.local` instead of `10.10.5.20/32`; this
// loop resolves it and merges the answers into the policy's effective
// CIDR set, from where they reach both the client's AllowedIPs and the
// gateway's nftables ruleset by the existing paths. Neither of those
// components learns anything about hostnames — they keep seeing IPs.
//
// Resolution happens HERE, on the controller, rather than on the gateway
// or the device. One resolver means one answer: if the gateway and the
// client resolved independently they could disagree, and the failure mode
// of that disagreement is a tunnel that routes traffic the gateway then
// drops — the hardest kind of problem to diagnose from a phone.
type Resolver struct {
	DB       *sql.DB
	Logger   *slog.Logger
	Interval time.Duration

	// Grace is how long a previously-resolved address survives after it
	// stops appearing in DNS answers.
	//
	// Not zero, deliberately. DNS answers rotate, and a device with an
	// open session would lose access mid-use on a routine rotation. Worse,
	// a transient resolver failure would revoke every hostname-derived
	// address at once — turning a DNS blip into a site-wide outage. The
	// grace window costs a little staleness and buys a great deal of
	// stability.
	Grace time.Duration

	// LookupIP is injected for tests; defaults to the system resolver.
	//
	// Production deployments usually want this pointed at the hospital's
	// internal resolver, which is what ResolverAddr in the controller
	// config arranges.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
}

const (
	defaultResolveInterval = 5 * time.Minute
	defaultResolveGrace    = 30 * time.Minute
)

// Run resolves on a ticker until ctx is cancelled.
func (r *Resolver) Run(ctx context.Context) {
	if r.Interval <= 0 {
		r.Interval = defaultResolveInterval
	}
	if r.Grace <= 0 {
		r.Grace = defaultResolveGrace
	}
	if r.Logger == nil {
		r.Logger = slog.Default()
	}
	if r.LookupIP == nil {
		r.LookupIP = systemLookup
	}

	// Resolve immediately: a controller restart must not leave hostname
	// rules unresolved for a full interval, because during that window
	// the affected devices reach nothing.
	if err := r.ResolveOnce(ctx); err != nil {
		r.Logger.Warn("initial hostname resolution failed", "err", err.Error())
	}

	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.ResolveOnce(ctx); err != nil {
				r.Logger.Warn("hostname resolution cycle failed", "err", err.Error())
			}
		}
	}
}

type hostnameRow struct {
	id        domain.ID
	hostname  string
	guardCIDR string
}

// ResolveOnce performs one full resolution pass.
func (r *Resolver) ResolveOnce(ctx context.Context) error {
	if r.LookupIP == nil {
		r.LookupIP = systemLookup
	}
	if r.Grace <= 0 {
		r.Grace = defaultResolveGrace
	}
	if r.Logger == nil {
		r.Logger = slog.Default()
	}

	rows, err := r.DB.QueryContext(ctx, `
		SELECT h.id, h.hostname, COALESCE(h.guard_cidr, '')
		  FROM policy_hostnames h
		  JOIN policies p ON p.id = h.policy_id
		 WHERE p.deleted_at IS NULL AND p.enabled = TRUE`)
	if err != nil {
		return fmt.Errorf("list hostnames: %w", err)
	}
	var hosts []hostnameRow
	for rows.Next() {
		var (
			idB []byte
			h   hostnameRow
		)
		if err := rows.Scan(&idB, &h.hostname, &h.guardCIDR); err != nil {
			rows.Close()
			return err
		}
		if err := h.id.Scan(idB); err != nil {
			continue
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	var resolved, rejected, failed int
	for _, h := range hosts {
		addrs, err := r.LookupIP(ctx, h.hostname)
		if err != nil {
			// A failed lookup does NOT prune existing addresses. The
			// grace window handles genuine removals; treating a lookup
			// error as "this name has no addresses" would let a DNS
			// outage revoke access fleet-wide.
			failed++
			r.Logger.Warn("hostname lookup failed; keeping last known addresses",
				"hostname", h.hostname, "err", err.Error())
			continue
		}

		var guard netip.Prefix
		hasGuard := false
		if h.guardCIDR != "" {
			if p, perr := netip.ParsePrefix(h.guardCIDR); perr == nil {
				guard, hasGuard = p.Masked(), true
			} else {
				r.Logger.Error("invalid guard_cidr; treating hostname as unresolvable",
					"hostname", h.hostname, "guard", h.guardCIDR)
				// An unparseable guard must not silently degrade to "no
				// guard" — that is the exact case the guard exists for.
				continue
			}
		}

		for _, a := range addrs {
			a = a.Unmap()
			if hasGuard && !guard.Contains(a) {
				rejected++
				r.Logger.Error("resolution outside guard range — REJECTED",
					"hostname", h.hostname, "addr", a.String(), "guard", guard.String())
				continue
			}
			if err := r.upsert(ctx, h.id, a); err != nil {
				r.Logger.Warn("store resolution failed",
					"hostname", h.hostname, "addr", a.String(), "err", err.Error())
				continue
			}
			resolved++
		}
	}

	pruned, err := r.prune(ctx)
	if err != nil {
		return err
	}

	if resolved > 0 || rejected > 0 || pruned > 0 || failed > 0 {
		r.Logger.Info("hostname resolution pass complete",
			"hostnames", len(hosts), "addresses", resolved,
			"rejected", rejected, "pruned", pruned, "lookup_failures", failed)
	}
	return nil
}

func (r *Resolver) upsert(ctx context.Context, hostnameID domain.ID, a netip.Addr) error {
	bits := 32
	if a.Is6() {
		bits = 128
	}
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO policy_hostname_resolutions (hostname_id, addr, bits)
		VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE last_seen_at = CURRENT_TIMESTAMP(6)`,
		hostnameID.Bytes(), a.AsSlice(), bits)
	return err
}

// prune removes addresses not seen for longer than the grace window.
func (r *Resolver) prune(ctx context.Context) (int64, error) {
	res, err := r.DB.ExecContext(ctx, `
		DELETE FROM policy_hostname_resolutions
		 WHERE last_seen_at < DATE_SUB(NOW(6), INTERVAL ? SECOND)`,
		int(r.Grace.Seconds()))
	if err != nil {
		return 0, fmt.Errorf("prune resolutions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// NewSystemResolverAt returns a LookupIP function bound to a specific DNS
// server, e.g. the hospital's internal resolver.
//
// The controller usually sits inside the hospital network and its system
// resolver already knows internal names, but not always — a controller in
// a DMZ typically has a public resolver configured, and would then fail
// to resolve exactly the names that matter.
func NewSystemResolverAt(dnsAddr string) func(context.Context, string) ([]netip.Addr, error) {
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, dnsAddr)
		},
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return res.LookupNetIP(ctx, "ip", host)
	}
}
