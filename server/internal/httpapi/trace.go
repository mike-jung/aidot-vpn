package httpapi

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// 추적 — everything known about one device, in time order.
//
// The console can already answer "what devices exist" and "what
// happened across the tenant". What it could not answer is the question
// an admin actually arrives with: *this* phone is not working, what has
// happened to it. That means walking one device's history — enrolment,
// approval, policy, connections — and the pieces were in three places
// with no way to line them up.
//
// Shape borrowed from aidot-express's 추적 tabs (컨트롤러별 / 경로별 /
// 사용자별 → a list, then one subject's events, then one event in
// detail). The subject differs: there the unit is a request, here it is
// a device, because a device is what an admin is asked about.
//
// The four stages are the ones the phone shows its own user — 등록 요청
// → 관리자 승인 → 정책 적용 → 연결 — so both sides describe the same
// thing with the same words.
func (a *API) registerTraceRoutes(mux *http.ServeMux) {
	mux.Handle("GET /devices/{id}/trace",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.deviceTrace))))
	mux.Handle("GET /policies/{id}/trace",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.policyTrace))))
	mux.Handle("GET /audit/actor/{id}/trace",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.actorTrace))))
}

// 정책별 — what changed, and who it reaches.
//
// The question before editing a policy is "who does this touch". The
// device list answers it; the history answers "why is it like this".
// Both were reachable only by reading two screens and matching ids.
func (a *API) policyTrace(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy id")
		return
	}
	u := userFromContext(r.Context())

	events, err := a.auditEventsFor(r, u.TenantID.Bytes(),
		`(target_id = ? OR JSON_EXTRACT(details, '$.policy_id') = ?)`,
		id.Bytes(), id.String())
	if err != nil {
		a.serverError(w, "policy trace", err)
		return
	}

	// Who it reaches now.
	devices := []map[string]any{}
	if rows, qerr := a.cfg.DB.QueryContext(r.Context(), `
		SELECT display_name, status, last_handshake_at FROM devices
		 WHERE tenant_id = ? AND policy_id = ? AND deleted_at IS NULL
		 ORDER BY display_name`, u.TenantID.Bytes(), id.Bytes()); qerr == nil {
		defer rows.Close()
		for rows.Next() {
			var name, status string
			var hs sql.NullTime
			if rows.Scan(&name, &status, &hs) == nil {
				row := map[string]any{"name": name, "status": status}
				if hs.Valid {
					row["last_handshake_at"] = hs.Time.UTC().Format(time.RFC3339)
				}
				devices = append(devices, row)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"policy":  map[string]any{"id": id.String()},
		"devices": devices,
		"events":  events,
	})
}

// 관리자별 — one person's actions.
//
// Accountability: an audit log that cannot be read per actor answers
// "what happened" but never "who has been doing this". Reached by
// clicking the actor in 감사 로그, since that is where the name already
// appears and a separate admin screen would be a second place to look.
func (a *API) actorTrace(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid actor id")
		return
	}
	u := userFromContext(r.Context())
	events, err := a.auditEventsFor(r, u.TenantID.Bytes(), `actor_id = ?`, id.Bytes())
	if err != nil {
		a.serverError(w, "actor trace", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"actor":  map[string]any{"id": id.String()},
		"events": events,
	})
}

// auditEventsFor runs one WHERE clause against the audit log and turns
// the rows into the same traceEvent the device trace returns, so all
// three tabs render through one code path on the console side.
func (a *API) auditEventsFor(r *http.Request, tenant []byte, where string, args ...any) ([]traceEvent, error) {
	q := `SELECT occurred_at, action, actor_kind, details FROM audit_log
	       WHERE tenant_id = ? AND ` + where + ` ORDER BY occurred_at`
	rows, err := a.cfg.DB.QueryContext(r.Context(), q, append([]any{tenant}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]traceEvent, 0, 32)
	for rows.Next() {
		var (
			at        time.Time
			action    string
			actorKind string
			raw       sql.NullString
		)
		if err := rows.Scan(&at, &action, &actorKind, &raw); err != nil {
			return nil, err
		}
		var det map[string]any
		if raw.Valid {
			_ = json.Unmarshal([]byte(raw.String), &det)
		}
		label, tone := traceLabel(action)
		out = append(out, traceEvent{
			At: at.UTC().Format(time.RFC3339), Kind: "audit", Action: action,
			Label: label, Tone: tone, Actor: actorWord(actorKind), Details: det,
		})
	}
	return out, rows.Err()
}

type traceEvent struct {
	At      string         `json:"at"`
	Kind    string         `json:"kind"`   // audit | report | state
	Action  string         `json:"action"` // machine code, or a report kind
	Label   string         `json:"label"`  // Korean, ready to render
	Tone    string         `json:"tone"`   // ok | warn | bad | muted
	Actor   string         `json:"actor,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

func (a *API) deviceTrace(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	u := userFromContext(r.Context())

	dev, err := a.cfg.Devices.ListInventory(r.Context(), u.TenantID)
	if err != nil {
		a.serverError(w, "trace inventory", err)
		return
	}
	var me *devicesInventoryRow
	for i := range dev {
		if dev[i].ID == id {
			me = &devicesInventoryRow{Name: dev[i].DisplayName, Status: string(dev[i].Status)}
			break
		}
	}
	if me == nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	// Audit entries naming this device, either as target or in details.
	// Same helper as the policy and actor tabs, so one change to the
	// event shape reaches all three.
	events, err := a.auditEventsFor(r, u.TenantID.Bytes(),
		`(target_id = ? OR JSON_EXTRACT(details, '$.device_id') = ?)`,
		id.Bytes(), id.String())
	if err != nil {
		a.serverError(w, "trace audit", err)
		return
	}

	// Where the device stands now, from the gateway's own reporting.
	inv, _ := a.cfg.Devices.ListInventory(r.Context(), u.TenantID)
	for i := range inv {
		if inv[i].ID != id {
			continue
		}
		d := inv[i]
		if d.LastHandshakeAt != nil {
			events = append(events, traceEvent{
				At: d.LastHandshakeAt.UTC().Format(time.RFC3339), Kind: "report",
				Action: "handshake", Label: "문지기와 통신했습니다", Tone: "ok",
				Actor: "문지기",
				Details: map[string]any{
					"받은 바이트": derefInt(d.RxBytes), "보낸 바이트": derefInt(d.TxBytes),
					"접속 지점": d.LastEndpoint,
				},
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device": map[string]any{"id": id.String(), "name": me.Name, "status": me.Status},
		"events": events,
	})
}

type devicesInventoryRow struct {
	Name   string
	Status string
}

func derefInt(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func actorWord(kind string) string {
	switch kind {
	case "system":
		return "시스템"
	case "node":
		return "문지기"
	case "device":
		return "단말"
	default:
		return "관리자"
	}
}

// traceLabel turns an action code into the words the console shows.
// Kept beside the trace rather than in the console alone so an export
// or another client gets the same wording.
func traceLabel(action string) (string, string) {
	switch action {
	case "device.register":
		return "등록됨", "ok"
	case "device.revoke":
		return "폐기됨", "bad"
	case "device.rotate_key":
		return "키 교체", "warn"
	case "policy.assign":
		return "정책 적용", "ok"
	case "policy.update":
		return "정책 내용 변경", "warn"
	case "policy.create":
		return "정책 만들기", "ok"
	case "policy.delete":
		return "정책 삭제", "bad"
	case "policy.transport":
		return "접속 방식 변경", "warn"
	case "admin.login":
		return "로그인", "ok"
	case "admin.login_failed":
		return "로그인 실패", "bad"
	case "admin.logout":
		return "로그아웃", "muted"
	case "admin.password_changed":
		return "비밀번호 변경", "warn"
	case "policy.allowed_ip.add":
		return "갈 수 있는 주소 추가", "ok"
	case "policy.allowed_ip.remove":
		return "갈 수 있는 주소 삭제", "warn"
	case "policy.hostname.add":
		return "호스트 이름 추가", "ok"
	case "policy.hostname.remove":
		return "호스트 이름 삭제", "warn"
	case "policy.virtual_host.add":
		return "가상 주소 추가", "ok"
	case "policy.virtual_host.remove":
		return "가상 주소 삭제", "warn"
	case "policy.settings.update":
		return "정책 설정 변경", "warn"
	case "device.app_filter.update":
		return "앱 필터 변경", "warn"
	default:
		return action, "muted"
	}
}
