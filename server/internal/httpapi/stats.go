package httpapi

import (
	"database/sql"
	"net/http"
	"time"
)

// 개요 statistics.
//
// The dashboard showed four numbers. Four numbers answer "is anything
// broken right now" and nothing else — not "is usage growing", not
// "which policy is everyone on", not "which phone is moving the most
// traffic". Those are the questions that come up in a review, and every
// one of them was already answerable from data the controller had.
func (a *API) registerStatsRoutes(mux *http.ServeMux) {
	mux.Handle("GET /stats/overview",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.statsOverview))))
}

func (a *API) statsOverview(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	tenant := u.TenantID.Bytes()
	out := map[string]any{}

	// Devices by policy — including the ones with none, which is the
	// group an admin most wants to see: registered but unable to connect.
	if rows, err := a.cfg.DB.QueryContext(r.Context(), `
		SELECT COALESCE(p.name, '(정책 없음)') AS name, COUNT(*) AS n
		  FROM devices d
		  LEFT JOIN device_groups g ON g.id = d.group_id AND g.tenant_id = d.tenant_id AND g.deleted_at IS NULL
		  LEFT JOIN policies p ON p.id = COALESCE(d.policy_id, g.policy_id) AND p.tenant_id = d.tenant_id AND p.deleted_at IS NULL
		 WHERE d.tenant_id = ? AND d.deleted_at IS NULL AND d.status = 'active'
		 GROUP BY name ORDER BY n DESC`, tenant); err == nil {
		defer rows.Close()
		list := []map[string]any{}
		for rows.Next() {
			var name string
			var n int
			if rows.Scan(&name, &n) == nil {
				list = append(list, map[string]any{"name": name, "count": n})
			}
		}
		out["by_policy"] = list
	}

	// Status summary.
	if rows, err := a.cfg.DB.QueryContext(r.Context(), `
		SELECT status, COUNT(*) FROM devices
		 WHERE tenant_id = ? AND deleted_at IS NULL GROUP BY status`, tenant); err == nil {
		defer rows.Close()
		m := map[string]int{}
		for rows.Next() {
			var s string
			var n int
			if rows.Scan(&s, &n) == nil {
				m[s] = n
			}
		}
		out["by_status"] = m
	}

	// Who is moving traffic. Cumulative since the gateway last started,
	// which is what the counters are; labelled as such on the screen.
	if rows, err := a.cfg.DB.QueryContext(r.Context(), `
		SELECT display_name, ipv4_addr, COALESCE(rx_bytes,0), COALESCE(tx_bytes,0)
		  FROM devices
		 WHERE tenant_id = ? AND deleted_at IS NULL
		   AND (rx_bytes > 0 OR tx_bytes > 0)
		 ORDER BY (COALESCE(rx_bytes,0) + COALESCE(tx_bytes,0)) DESC LIMIT 5`, tenant); err == nil {
		defer rows.Close()
		list := []map[string]any{}
		for rows.Next() {
			var name string
			var ipv4 sql.NullString
			var rx, tx int64
			if rows.Scan(&name, &ipv4, &rx, &tx) == nil {
				// The tunnel address, because the name does not identify a
				// device: the app defaults it to Build.MODEL, so ten of the
				// same handset are ten rows all reading SM-F721N.
				list = append(list, map[string]any{
					"name": name, "ipv4": ipv4.String, "rx": rx, "tx": tx,
				})
			}
		}
		out["top_talkers"] = list
	}

	// Seven days of activity, from the audit log — one bar per day.
	if rows, err := a.cfg.DB.QueryContext(r.Context(), `
		SELECT DATE(occurred_at) AS d, COUNT(*) FROM audit_log
		 WHERE tenant_id = ? AND occurred_at >= NOW() - INTERVAL 7 DAY
		 GROUP BY d ORDER BY d`, tenant); err == nil {
		defer rows.Close()
		list := []map[string]any{}
		for rows.Next() {
			var d time.Time
			var n int
			if rows.Scan(&d, &n) == nil {
				list = append(list, map[string]any{"date": d.Format("2006-01-02"), "count": n})
			}
		}
		out["activity"] = list
	}

	// Twenty-four hours of connection samples, if any have been taken.
	if rows, err := a.cfg.DB.QueryContext(r.Context(), `
		SELECT bucket_at, connected, total FROM connection_samples
		 WHERE tenant_id = ? AND bucket_at >= NOW() - INTERVAL 24 HOUR
		 ORDER BY bucket_at`, tenant); err == nil {
		defer rows.Close()
		list := []map[string]any{}
		for rows.Next() {
			var at time.Time
			var c, t int
			if rows.Scan(&at, &c, &t) == nil {
				list = append(list, map[string]any{
					"at": at.UTC().Format(time.RFC3339), "connected": c, "total": t,
				})
			}
		}
		out["connections"] = list
	}

	writeJSON(w, http.StatusOK, out)
}

// sampleConnections folds the current picture into a five-minute
// Called from the node report handler, so it runs at whatever rate the
// gateway reports and needs no scheduler.
//
// Was fifteen minutes, which meant the chart had one point — and so no
// line — for the first quarter of an hour after a fresh start, and the
// card sat empty exactly when someone was looking at it. A bucket is
// one row per tenant, not per device: five minutes is 288 rows a day
// for the whole installation, which is nothing, and the chart becomes
// readable within a quarter of an hour.
func (a *API) sampleConnections(r *http.Request, tenant []byte) {
	_, _ = a.cfg.DB.ExecContext(r.Context(), `
		INSERT INTO connection_samples (tenant_id, bucket_at, connected, total, rx_bytes, tx_bytes)
		SELECT ?,
		       FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(NOW()) / 300) * 300),
		       COALESCE(SUM(CASE WHEN last_handshake_at > NOW(6) - INTERVAL 2 MINUTE THEN 1 ELSE 0 END), 0),
		       COUNT(*),
		       COALESCE(SUM(rx_bytes), 0), COALESCE(SUM(tx_bytes), 0)
		  FROM devices
		 WHERE tenant_id = ? AND deleted_at IS NULL AND status = 'active'
		ON DUPLICATE KEY UPDATE
		  connected = VALUES(connected), total = VALUES(total),
		  rx_bytes = VALUES(rx_bytes), tx_bytes = VALUES(tx_bytes)`,
		tenant, tenant)
}
