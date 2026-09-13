package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aidotvpn/server/internal/domain"
)

// 그룹 — a policy applied to many devices at once.
//
// Attaching a policy one device at a time meant thirty edits to change
// what a ward can reach, and one missed device stayed on the old rules
// with nothing on screen to say so. A group holds the policy; devices
// join the group.
//
// A device's own policy still wins, so an exception stays possible
// without dissolving the group — which is the case that pushes people
// back to per-device assignment in products that do not allow it.
func (a *API) registerGroupRoutes(mux *http.ServeMux) {
	mux.Handle("GET /groups", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.listGroups))))
	mux.Handle("POST /groups", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.createGroup))))
	mux.Handle("PATCH /groups/{id}", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.updateGroup))))
	mux.Handle("DELETE /groups/{id}", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.deleteGroup))))
	mux.Handle("POST /devices/{id}/group", a.requireAuth(a.requireAdmin(http.HandlerFunc(a.assignGroup))))
}

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	rows, err := a.cfg.DB.QueryContext(r.Context(), `
		SELECT g.id, g.name, COALESCE(g.description, ''), g.policy_id, p.name,
		       (SELECT COUNT(*) FROM devices d
		         WHERE d.group_id = g.id AND d.deleted_at IS NULL) AS members
		  FROM device_groups g
		  LEFT JOIN policies p ON p.id = g.policy_id AND p.deleted_at IS NULL
		 WHERE g.tenant_id = ? AND g.deleted_at IS NULL
		 ORDER BY g.name`, u.TenantID.Bytes())
	if err != nil {
		a.serverError(w, "list groups", err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			idB      []byte
			name     string
			desc     string
			policyB  []byte
			policyNm sql.NullString
			members  int
		)
		if err := rows.Scan(&idB, &name, &desc, &policyB, &policyNm, &members); err != nil {
			a.serverError(w, "scan group", err)
			return
		}
		var id domain.ID
		_ = id.Scan(idB)
		row := map[string]any{
			"id": id.String(), "name": name, "description": desc, "members": members,
		}
		if len(policyB) > 0 {
			var pid domain.ID
			_ = pid.Scan(policyB)
			row["policy_id"] = pid.String()
			row["policy_name"] = policyNm.String
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		PolicyID    string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeError(w, http.StatusBadRequest, "그룹 이름이 필요합니다")
		return
	}
	u := userFromContext(r.Context())
	id := domain.NewID()
	var policy any
	if body.PolicyID != "" {
		pid, err := parseHexID(body.PolicyID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid policy id")
			return
		}
		var n int
		if err := a.cfg.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM policies WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`, pid.Bytes(), u.TenantID.Bytes()).Scan(&n); err != nil {
			a.serverError(w, "group policy lookup", err)
			return
		}
		if n == 0 {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		policy = pid.Bytes()
	}
	if _, err := a.cfg.DB.ExecContext(r.Context(), `
		INSERT INTO device_groups (id, tenant_id, name, description, policy_id)
		VALUES (?, ?, ?, ?, ?)`,
		id.Bytes(), u.TenantID.Bytes(), strings.TrimSpace(body.Name),
		nullIfEmptyStr(body.Description), policy); err != nil {
		writeError(w, http.StatusConflict, "같은 이름의 그룹이 이미 있습니다")
		return
	}
	a.audit(r, u.TenantID, &u.ID, "group.create", &id,
		map[string]any{"name": body.Name})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id.String(), "name": body.Name})
}

func (a *API) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid group id")
		return
	}
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		PolicyID    *string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	u := userFromContext(r.Context())
	if body.Name != nil && strings.TrimSpace(*body.Name) == "" {
		writeError(w, http.StatusBadRequest, "그룹 이름이 필요합니다")
		return
	}
	var policy any
	if body.PolicyID != nil && *body.PolicyID != "" {
		pid, err := parseHexID(*body.PolicyID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid policy id")
			return
		}
		var n int
		if err := a.cfg.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM policies WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`, pid.Bytes(), u.TenantID.Bytes()).Scan(&n); err != nil {
			a.serverError(w, "group policy lookup", err)
			return
		}
		if n == 0 {
			writeError(w, http.StatusNotFound, "policy not found")
			return
		}
		policy = pid.Bytes()
	}
	var n int
	if err := a.cfg.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM device_groups WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`, id.Bytes(), u.TenantID.Bytes()).Scan(&n); err != nil {
		a.serverError(w, "group lookup", err)
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	_, err = a.cfg.DB.ExecContext(r.Context(), `UPDATE device_groups SET
     name = IF(?, ?, name), description = IF(?, ?, description), policy_id = IF(?, ?, policy_id)
     WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`,
		body.Name != nil, strings.TrimSpace(derefStr(body.Name)), body.Description != nil, nullIfEmptyStr(derefStr(body.Description)),
		body.PolicyID != nil, policy, id.Bytes(), u.TenantID.Bytes())
	if err != nil {
		a.serverError(w, "update group", err)
		return
	}
	a.audit(r, u.TenantID, &u.ID, "group.update", &id, map[string]any{"policy_changed": body.PolicyID != nil})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid group id")
		return
	}
	u := userFromContext(r.Context())
	tx, err := a.cfg.DB.BeginTx(r.Context(), nil)
	if err != nil {
		a.serverError(w, "delete group transaction", err)
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), `UPDATE device_groups SET deleted_at = ? WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`, time.Now().UTC(), id.Bytes(), u.TenantID.Bytes())
	if err != nil {
		a.serverError(w, "delete group", err)
		return
	}
	n, err := result.RowsAffected()
	if err != nil {
		a.serverError(w, "delete group result", err)
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "group not found")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE devices SET group_id = NULL WHERE group_id = ? AND tenant_id = ?`, id.Bytes(), u.TenantID.Bytes()); err != nil {
		a.serverError(w, "clear group members", err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.serverError(w, "delete group commit", err)
		return
	}
	a.audit(r, u.TenantID, &u.ID, "group.delete", &id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) assignGroup(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	var body struct {
		GroupID string `json:"group_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	u := userFromContext(r.Context())
	var group any
	if body.GroupID != "" {
		gid, gerr := parseHexID(body.GroupID)
		if gerr != nil {
			writeError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		var n int
		if err := a.cfg.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM device_groups WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`, gid.Bytes(), u.TenantID.Bytes()).Scan(&n); err != nil {
			a.serverError(w, "group lookup", err)
			return
		}
		if n == 0 {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		group = gid.Bytes()
	}
	if _, err := a.cfg.DB.ExecContext(r.Context(),
		`UPDATE devices SET group_id = ? WHERE id = ? AND tenant_id = ?`,
		group, id.Bytes(), u.TenantID.Bytes()); err != nil {
		a.serverError(w, "assign group", err)
		return
	}
	a.audit(r, u.TenantID, &u.ID, "group.assign", &id,
		map[string]any{"group_id": body.GroupID})
	w.WriteHeader(http.StatusNoContent)
}

func nullIfEmptyStr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// 접속 기한 — extend or clear one device's deadline.
//
// Separate from 폐기: a phone whose access ran out did nothing wrong,
// and putting it back should be one click rather than a re-enrolment.
func (a *API) registerExpiryRoutes(mux *http.ServeMux) {
	mux.Handle("POST /devices/{id}/expiry",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.setDeviceExpiry))))
	mux.Handle("POST /settings/device-expiry",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.setTenantExpiry))))
	mux.Handle("POST /settings/min-os",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.setMinOS))))
	mux.Handle("GET /settings/access",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.getAccessSettings))))
}

func (a *API) setDeviceExpiry(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	var body struct {
		// Days from now. 0 clears the deadline (never expires).
		Days int `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	u := userFromContext(r.Context())
	var when any
	if body.Days > 0 {
		when = time.Now().UTC().AddDate(0, 0, body.Days)
	}
	if _, err := a.cfg.DB.ExecContext(r.Context(),
		`UPDATE devices SET access_expires_at = ? WHERE id = ? AND tenant_id = ?`,
		when, id.Bytes(), u.TenantID.Bytes()); err != nil {
		a.serverError(w, "set expiry", err)
		return
	}
	a.audit(r, u.TenantID, &u.ID, "device.expiry", &id,
		map[string]any{"days": body.Days})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setTenantExpiry(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Days int `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Days < 0 {
		writeError(w, http.StatusBadRequest, "days must be zero or more")
		return
	}
	u := userFromContext(r.Context())
	if _, err := a.cfg.DB.ExecContext(r.Context(),
		`UPDATE tenants SET device_expiry_days = ? WHERE id = ?`,
		body.Days, u.TenantID.Bytes()); err != nil {
		a.serverError(w, "tenant expiry", err)
		return
	}
	a.audit(r, u.TenantID, &u.ID, "settings.device_expiry", nil,
		map[string]any{"days": body.Days})
	w.WriteHeader(http.StatusNoContent)
}

// 최소 OS — refuse a handset whose Android is too old to be patched.
//
// 0 disables it, which is the default: switching this on for an
// installation that did not ask would cut off whatever is deployed.
func (a *API) setMinOS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Sdk int `json:"sdk"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Sdk < 0 {
		writeError(w, http.StatusBadRequest, "sdk must be zero or more")
		return
	}
	u := userFromContext(r.Context())
	if _, err := a.cfg.DB.ExecContext(r.Context(),
		`UPDATE tenants SET min_os_sdk = ? WHERE id = ?`, body.Sdk, u.TenantID.Bytes()); err != nil {
		a.serverError(w, "min os", err)
		return
	}
	a.audit(r, u.TenantID, &u.ID, "settings.min_os", nil, map[string]any{"sdk": body.Sdk})
	w.WriteHeader(http.StatusNoContent)
}

// The two tenant-wide access rules, so the settings dialog can show
// what is in force rather than an empty form.
func (a *API) getAccessSettings(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	var days, sdk int
	_ = a.cfg.DB.QueryRowContext(r.Context(),
		`SELECT device_expiry_days, min_os_sdk FROM tenants WHERE id = ?`,
		u.TenantID.Bytes()).Scan(&days, &sdk)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_expiry_days": days, "min_os_sdk": sdk,
	})
}
