package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aidotvpn/server/internal/devices"
	"github.com/aidotvpn/server/internal/domain"
)

// Device-initiated enrollment.
//
// The token flow asked someone to move 38 characters onto a phone with
// no channel to do it. This inverts the direction: the phone requests,
// the admin approves after checking six digits match the handset in
// front of them.
//
// The two device-facing routes are unauthenticated by necessity — a
// phone enrolling has no session yet, which is the whole situation. What
// stands in for authentication is the shared password on the way in and
// the admin's comparison on the way out, and of those only the second is
// load-bearing.
func (a *API) registerEnrollmentRequestRoutes(mux *http.ServeMux) {
	// Device-facing. No auth.
	mux.Handle("POST /enrollment-requests", http.HandlerFunc(a.createEnrollmentRequest))
	mux.Handle("GET /enrollment-requests/{id}/status", http.HandlerFunc(a.enrollmentRequestStatus))

	// Admin-facing.
	mux.Handle("GET /enrollment-requests",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.listEnrollmentRequests))))
	mux.Handle("POST /enrollment-requests/{id}/approve",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.approveEnrollmentRequest))))
	mux.Handle("POST /enrollment-requests/{id}/reject",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.rejectEnrollmentRequest))))

	// The shared password, readable and changeable by an admin.
	//
	// Readable because it has to be told to whoever is holding the
	// phone — a secret nobody can look up is one that ends up on a
	// sticky note.
	mux.Handle("GET /enrollment-password",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.getEnrollmentPassword))))
	mux.Handle("PUT /enrollment-password",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.setEnrollmentPassword))))
}

func (a *API) getEnrollmentPassword(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())

	// GetSettingErr rather than the fallback path, so a wrong or missing
	// encryption key is reported instead of quietly looking like "nobody
	// has set one". An operator who restarts with the wrong key would
	// otherwise see the default reappear and conclude their change was
	// lost, then set it again — and now two keys have written rows.
	stored, err := a.cfg.Devices.GetSettingErr(r.Context(), u.TenantID,
		devices.SettingEnrollmentPassword)
	if err != nil {
		writeError(w, http.StatusConflict,
			"저장된 비밀번호를 복호화할 수 없습니다. SETTINGS_ENCRYPTION_KEY 를 확인하세요.")
		return
	}

	pw := stored
	if pw == "" {
		pw = a.enrollmentPassword(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"password": pw,
		// So the console can warn without duplicating the constant.
		"is_default": pw == devices.DefaultEnrollmentPassword,
		"encrypted":  os.Getenv(devices.SettingsKeyEnv) != "",
	})
}

func (a *API) setEnrollmentPassword(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := devices.ValidateEnrollmentPassword(body.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.cfg.Devices.SetSetting(r.Context(), u.TenantID, u.ID,
		devices.SettingEnrollmentPassword, body.Password); err != nil {
		a.serverError(w, "set enrollment password", err)
		return
	}
	// Requests already waiting were made with the old password and are
	// still legitimate — they are approved by comparison, not by the
	// password. Changing it only affects what comes next.
	writeJSON(w, http.StatusOK, map[string]any{"password": body.Password})
}

// enrollmentPassword returns the shared secret a device presents.
//
// From the settings table, falling back to the environment and then to
// the built-in default. 1.2.0 read only the environment, arguing that a
// table "invites a UI for editing it — at which point it becomes a
// password that can be changed by anyone who reaches an admin screen".
//
// That was wrong. Anyone on an admin screen can already approve devices,
// which is strictly more than changing the password that decides who may
// queue for approval. Meanwhile an operator wanting to read the password
// — to tell a nurse — had to ssh in.
func (a *API) enrollmentPassword(ctx context.Context) string {
	fallback := os.Getenv("ENROLLMENT_PASSWORD")
	if fallback == "" {
		fallback = devices.DefaultEnrollmentPassword
	}
	return a.cfg.Devices.GetSetting(ctx, domain.ID{},
		devices.SettingEnrollmentPassword, fallback)
}

type enrollmentRequestJSON struct {
	ID               string `json:"id"`
	DisplayName      string `json:"display_name"`
	Platform         string `json:"platform"`
	VerificationCode string `json:"verification_code"`
	Status           string `json:"status"`
	PolicyID         string `json:"policy_id,omitempty"`
	DeviceID         string `json:"device_id,omitempty"`
	ExpiresAt        string `json:"expires_at"`
	CreatedAt        string `json:"created_at"`
}

func toEnrollmentRequestJSON(r *devices.EnrollmentRequest) enrollmentRequestJSON {
	out := enrollmentRequestJSON{
		ID:               r.ID.String(),
		DisplayName:      r.DisplayName,
		Platform:         r.Platform,
		VerificationCode: r.VerificationCode,
		Status:           r.Status,
		ExpiresAt:        r.ExpiresAt.Format(time.RFC3339),
		CreatedAt:        r.CreatedAt.Format(time.RFC3339),
	}
	// A pending request whose clock has run out reads as "expired" to the
	// console, so the operator is not offered an approve button that the
	// service will refuse.
	if r.Status == "pending" && time.Now().UTC().After(r.ExpiresAt) {
		out.Status = "expired"
	}
	if r.PolicyID != nil {
		out.PolicyID = r.PolicyID.String()
	}
	if r.DeviceID != nil {
		out.DeviceID = r.DeviceID.String()
	}
	return out
}

func (a *API) createEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password        string `json:"password"`
		InstallID       string `json:"install_id"`
		DisplayName     string `json:"display_name"`
		Platform        string `json:"platform"`
		DevicePublicKey string `json:"device_public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if _, err := base64.StdEncoding.DecodeString(body.DevicePublicKey); err != nil {
		writeError(w, http.StatusBadRequest, "device_public_key is not valid base64")
		return
	}

	// domain.ID{} — the service substitutes its configured tenant, the
	// same way Register does. An unauthenticated caller has no tenant to
	// name, and letting it name one would be the bug.
	req, err := a.cfg.Devices.CreateEnrollmentRequest(
		r.Context(), domain.ID{},
		a.enrollmentPassword(r.Context()), body.Password,
		body.InstallID, body.DisplayName, body.Platform, body.DevicePublicKey)
	if err != nil {
		if errors.Is(err, devices.ErrEnrollPassword) {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The id goes back so the phone can poll; the code so it can be
	// displayed. Neither is a credential — approval is a human decision.
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                req.ID.String(),
		"verification_code": req.VerificationCode,
		"expires_at":        req.ExpiresAt.Format(time.RFC3339),
	})
}

// enrollmentRequestStatus answers the phone, holding the connection
// until there is something to say.
//
// `?wait=<seconds>` turns this into a long poll. The device is already
// waiting while an admin decides in front of it, so rather than asking
// every three seconds it asks once and the server answers the moment the
// decision lands — typically within a few milliseconds of the click.
//
// Capped at 60s: past that, proxies and mobile networks start dropping
// idle connections, and a request that dies silently is worse than one
// that returns "pending" and is asked again.
//
// Returns the allocation once approved, so the device never calls
// /devices/register itself — the admin's approval is what created it.
func (a *API) enrollmentRequestStatus(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	req, err := a.cfg.Devices.GetEnrollmentRequest(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "요청을 찾을 수 없습니다")
		return
	}

	// Long poll, when asked for and while still undecided.
	if wait := waitSeconds(r); wait > 0 && req.Status == "pending" {
		signal, release := devices.WatchDecision(id)
		defer release()

		deadline := time.After(wait)
		// The ticker is the correct path; the signal is the fast one. A
		// second controller replica handling the approval never reaches
		// this process's notifier, so the re-read is what makes this
		// work behind a load balancer.
		tick := time.NewTicker(time.Second)
		defer tick.Stop()

	waitLoop:
		for {
			select {
			case <-r.Context().Done():
				// The phone hung up. Nothing to write.
				return
			case <-deadline:
				break waitLoop
			case <-signal:
			case <-tick.C:
			}

			fresh, err := a.cfg.Devices.GetEnrollmentRequest(r.Context(), id)
			if err != nil {
				break waitLoop
			}
			req = fresh
			if req.Status != "pending" || time.Now().UTC().After(req.ExpiresAt) {
				break waitLoop
			}
		}
	}

	out := map[string]any{"status": toEnrollmentRequestJSON(req).Status}
	if req.Status == "approved" {
		// The grant, once. Cleared on read so a request id that leaks
		// after the fact is worth nothing — and the token behind it is
		// single-use and expires in five minutes regardless.
		grant, err := a.cfg.Devices.TakeGrant(r.Context(), id)
		if err == nil && grant != "" {
			out["enrollment_token"] = grant
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// waitSeconds reads ?wait=, clamped to a minute.
func waitSeconds(r *http.Request) time.Duration {
	raw := r.URL.Query().Get("wait")
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	if n > 60 {
		n = 60
	}
	return time.Duration(n) * time.Second
}

func (a *API) listEnrollmentRequests(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	reqs, err := a.cfg.Devices.ListEnrollmentRequests(r.Context(), u.TenantID)
	if err != nil {
		a.serverError(w, "list enrollment requests", err)
		return
	}
	out := make([]enrollmentRequestJSON, 0, len(reqs))
	for i := range reqs {
		out = append(out, toEnrollmentRequestJSON(&reqs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (a *API) approveEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}

	var body struct {
		PolicyID string `json:"policy_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	req, err := a.cfg.Devices.GetEnrollmentRequest(r.Context(), id)
	if err != nil || req.TenantID != u.TenantID || !req.Pending(time.Now().UTC()) {
		writeError(w, http.StatusConflict, "처리할 수 없는 등록 요청입니다")
		return
	}

	// Approval issues permission to register; it does not register.
	//
	// The alternative was to create the device here and hand the
	// allocation back through the unauthenticated status endpoint — which
	// would mean an unauthenticated route returning a PSK and a client
	// certificate. Too much to give out on the strength of a request id.
	//
	// A single-use enrollment token, expiring in five minutes, keeps
	// registration on the one path it already had. The device calls
	// /devices/register exactly as it always did; approval just decides
	// whether it may.
	var policyID *domain.ID
	if body.PolicyID != "" {
		p, err := parseHexID(body.PolicyID)
		if err == nil {
			policyID = &p
		}
	}

	_, secret, err := a.cfg.Devices.CreateEnrollmentToken(
		r.Context(), u.TenantID, u.ID,
		"승인: "+req.DisplayName, policyID, 1, 5*time.Minute)
	if err != nil {
		a.serverError(w, "issue token on approval", err)
		return
	}

	if err := a.cfg.Devices.MarkApprovedWithGrant(r.Context(), id, u.ID, policyID, secret); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	// Wake the phone that is holding a connection open for this.
	devices.AnnounceDecision(id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *API) rejectEnrollmentRequest(w http.ResponseWriter, r *http.Request) {
	u := userFromContext(r.Context())
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := a.cfg.Devices.RejectEnrollmentRequest(r.Context(), u.TenantID, id, u.ID); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	devices.AnnounceDecision(id)
	w.WriteHeader(http.StatusNoContent)
}
