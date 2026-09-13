package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/aidotvpn/server/internal/audit"
	"github.com/aidotvpn/server/internal/domain"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aidotvpn/server/internal/adminauth"
)

// Console login, without an identity server. See internal/adminauth.
func (a *API) registerAdminAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/login", a.authLogin)
	mux.Handle("POST /auth/logout", a.requireAuth(http.HandlerFunc(a.authLogout)))
	mux.Handle("GET /auth/me", a.requireAuth(http.HandlerFunc(a.authMe)))
	mux.Handle("POST /auth/password", a.requireAuth(http.HandlerFunc(a.authChangePassword)))
	mux.Handle("GET /auth/sessions", a.requireAuth(http.HandlerFunc(a.authSessions)))
	mux.Handle("DELETE /auth/sessions/{id}", a.requireAuth(http.HandlerFunc(a.authRevokeSession)))
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		return strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// audit writes one entry; failures are logged, never surfaced to the
// login flow.
func (a *API) audit(r *http.Request, tenant domain.ID, actor *domain.ID, action string, target *domain.ID, details map[string]any) {
	if a.cfg.Audit == nil {
		return
	}
	kind := audit.ActorSystem
	if actor != nil {
		kind = audit.ActorUser
	}
	_ = a.cfg.Audit.Append(r.Context(), audit.Entry{
		TenantID: tenant, ActorKind: kind, ActorID: actor, Action: action,
		TargetKind: "admin", TargetID: target, Details: details, OccurredAt: time.Now().UTC(),
	})
}

// usersRowFor maps an admin to the users row the rest of the audit log
// keys on, falling back to the admin id if the lookup fails — a missing
// actor would be worse than an inconsistent one.
func (a *API) usersRowFor(r *http.Request, ad *adminauth.Admin) *domain.ID {
	if u, err := a.cfg.Users.FindOrCreate(r.Context(), ad.TenantID,
		ad.ID.String(), ad.Email, ad.DisplayName); err == nil {
		return &u.ID
	}
	return &ad.ID
}

func adminJSON(ad *adminauth.Admin) map[string]any {
	return map[string]any{
		"id": ad.ID.String(), "email": ad.Email, "display_name": ad.DisplayName,
		"role": ad.Role, "must_change_password": ad.MustChange,
	}
}

func (a *API) authLogin(w http.ResponseWriter, r *http.Request) {
	// JSON only. A form-encoded body could be posted cross-site by a
	// plain HTML form; JSON cannot, which with SameSite=Strict on the
	// cookie is the CSRF story.
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "application/json 만 받습니다")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "이메일과 비밀번호가 필요합니다")
		return
	}
	// Address-level throttle, checked before the password is looked at.
	//
	// admins.failed_logins locks one account after five tries, which
	// does nothing about the shape an attack takes: one address trying
	// admin@, it@, root@ and a dozen more, five each, never tripping a
	// lock. Checked first so a throttled address cannot learn from
	// response timing which accounts exist.
	ip := clientIP(r)
	if a.cfg.Admins.IPLocked(r.Context(), ip) {
		writeError(w, http.StatusTooManyRequests,
			"로그인 시도가 너무 많습니다. 15분 뒤에 다시 시도하세요.")
		return
	}

	ad, token, err := a.cfg.Admins.Login(r.Context(), body.Email, body.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		a.cfg.Admins.NoteLoginFailure(r.Context(), ip)
		switch {
		case errors.Is(err, adminauth.ErrBadCredentials):
			writeError(w, http.StatusUnauthorized, err.Error())
		case errors.Is(err, adminauth.ErrLocked):
			writeError(w, http.StatusTooManyRequests, err.Error())
		case errors.Is(err, adminauth.ErrDisabled):
			writeError(w, http.StatusForbidden, err.Error())
		default:
			a.serverError(w, "login", err)
		}
		// Audit failures too; a burst of them is worth seeing.
		a.audit(r, a.cfg.DefaultTenant, nil, "admin.login_failed", nil,
			map[string]any{"email": strings.ToLower(body.Email), "ip": clientIP(r)})
		return
	}
	// Second factor, after the password and before the session.
	//
	// The order matters: checking the code first would tell an attacker
	// which accounts have TOTP enabled without knowing any password.
	if need, secret := a.cfg.Admins.TOTPRequired(r.Context(), body.Email); need {
		code := strings.TrimSpace(body.Code)
		ok := code != "" &&
			(adminauth.VerifyTOTP(secret, code, time.Now()) ||
				a.cfg.Admins.ConsumeRecoveryCode(r.Context(), body.Email, code))
		if !ok {
			a.cfg.Admins.NoteLoginFailure(r.Context(), ip)
			// 428, not 401: the password was right and the client has
			// something more to do. A 401 would send the console back to
			// "wrong password", which is both wrong and alarming.
			writeError(w, http.StatusPreconditionRequired,
				"인증 앱의 6자리 숫자를 입력하세요.")
			return
		}
	}

	a.cfg.Admins.NoteLoginSuccess(r.Context(), ip)

	// Read the previous login before overwriting it: the point is to
	// tell this person what happened last time, not what is happening
	// now.
	var prevAt sql.NullTime
	var prevIP sql.NullString
	_ = a.cfg.DB.QueryRowContext(r.Context(),
		`SELECT last_login_at, last_login_ip FROM admins WHERE id = ?`,
		ad.ID.Bytes()).Scan(&prevAt, &prevIP)
	_, _ = a.cfg.DB.ExecContext(r.Context(),
		`UPDATE admins SET last_login_at = ?, last_login_ip = ? WHERE id = ?`,
		time.Now().UTC(), clientIP(r), ad.ID.Bytes())

	setSessionCookie(w, r, token)

	// Audit the login against the *users* row, not admins.id.
	//
	// Every other action is recorded by the users row that requireAuth
	// resolves, so recording the login by admins.id split one person
	// into two actors: 관리자별 추적 showed seven logins and none of the
	// work done between them. Resolving the row here costs one upsert
	// per login and makes the trail continuous.
	actor := &ad.ID
	if u, uerr := a.cfg.Users.FindOrCreate(r.Context(), ad.TenantID,
		ad.ID.String(), ad.Email, ad.DisplayName); uerr == nil {
		actor = &u.ID
	}
	a.audit(r, ad.TenantID, actor, "admin.login", actor,
		map[string]any{"ip": clientIP(r), "user_agent": r.UserAgent()})
	writeJSON(w, http.StatusOK, map[string]any{"admin": adminJSON(ad)})
}

func (a *API) authLogout(w http.ResponseWriter, r *http.Request) {
	ad := adminFromContext(r.Context())
	_ = a.cfg.Admins.Logout(r.Context(), sessionTokenFromContext(r.Context()))
	clearSessionCookie(w, r)
	if ad != nil {
		actor := a.usersRowFor(r, ad)
		a.audit(r, ad.TenantID, actor, "admin.logout", actor, nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) authMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"admin": adminJSON(adminFromContext(r.Context()))})
}

func (a *API) authChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Current == "" || body.New == "" {
		writeError(w, http.StatusBadRequest, "현재 비밀번호와 새 비밀번호가 필요합니다")
		return
	}
	if len(body.New) < 8 {
		writeError(w, http.StatusBadRequest, "새 비밀번호는 8자 이상이어야 합니다")
		return
	}
	if body.New == body.Current {
		writeError(w, http.StatusBadRequest, "새 비밀번호가 현재 비밀번호와 같습니다")
		return
	}
	ad := adminFromContext(r.Context())
	err := a.cfg.Admins.ChangePassword(r.Context(), ad.ID, body.Current, body.New, sessionTokenFromContext(r.Context()))
	if errors.Is(err, adminauth.ErrBadCredentials) {
		writeError(w, http.StatusForbidden, "현재 비밀번호가 맞지 않습니다")
		return
	}
	if err != nil {
		a.serverError(w, "change password", err)
		return
	}
	pactor := a.usersRowFor(r, ad)
	a.audit(r, ad.TenantID, pactor, "admin.password_changed", pactor, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) authSessions(w http.ResponseWriter, r *http.Request) {
	ad := adminFromContext(r.Context())
	ss, err := a.cfg.Admins.Sessions(r.Context(), ad.ID)
	if err != nil {
		a.serverError(w, "sessions", err)
		return
	}
	out := make([]map[string]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, map[string]any{
			"id": s.ID.String(), "created_at": s.CreatedAt.Format(time.RFC3339),
			"last_used_at": s.LastUsedAt.Format(time.RFC3339), "user_agent": s.UserAgent, "ip": s.IP,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (a *API) authRevokeSession(w http.ResponseWriter, r *http.Request) {
	id, err := parseHexID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	ad := adminFromContext(r.Context())
	if err := a.cfg.Admins.RevokeSession(r.Context(), ad.ID, id); err != nil {
		a.serverError(w, "revoke session", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// 2단계 인증 설정.
//
// Three steps, because handing someone a secret and enabling it in one
// call means an admin whose scan silently failed is locked out on their
// next login. Setup returns the secret; enable proves a code from it
// works; only then does it apply.
func (a *API) registerTOTPRoutes(mux *http.ServeMux) {
	mux.Handle("POST /auth/totp/setup",
		a.requireAuth(http.HandlerFunc(a.totpSetup)))
	mux.Handle("POST /auth/totp/enable",
		a.requireAuth(http.HandlerFunc(a.totpEnable)))
	mux.Handle("POST /auth/totp/disable",
		a.requireAuth(http.HandlerFunc(a.totpDisable)))
}

func (a *API) totpSetup(w http.ResponseWriter, r *http.Request) {
	ad := adminFromContext(r.Context())
	if ad == nil {
		writeError(w, http.StatusUnauthorized, "로그인이 필요합니다")
		return
	}
	secret, err := adminauth.NewTOTPSecret()
	if err != nil {
		a.serverError(w, "totp secret", err)
		return
	}
	// Stored but not enabled: totp_enabled_at stays null until a code
	// from it verifies, so an abandoned setup leaves logins untouched.
	if _, err := a.cfg.DB.ExecContext(r.Context(),
		`UPDATE admins SET totp_secret = ?, totp_enabled_at = NULL WHERE id = ?`,
		secret, ad.ID.Bytes()); err != nil {
		a.serverError(w, "totp store", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    adminauth.TOTPURI(secret, "AidotVpn", ad.Email),
	})
}

func (a *API) totpEnable(w http.ResponseWriter, r *http.Request) {
	ad := adminFromContext(r.Context())
	if ad == nil {
		writeError(w, http.StatusUnauthorized, "로그인이 필요합니다")
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	var secret sql.NullString
	if err := a.cfg.DB.QueryRowContext(r.Context(),
		`SELECT totp_secret FROM admins WHERE id = ?`, ad.ID.Bytes()).
		Scan(&secret); err != nil || !secret.Valid {
		writeError(w, http.StatusBadRequest, "먼저 설정을 시작하세요")
		return
	}
	if !adminauth.VerifyTOTP(secret.String, body.Code, time.Now()) {
		writeError(w, http.StatusBadRequest, "숫자가 맞지 않습니다. 다시 확인하세요.")
		return
	}

	// Recovery codes, generated here and shown once.
	//
	// A lost phone must not mean a locked-out administrator and a
	// hospital that cannot revoke a stolen handset. Hashed like
	// passwords, so the database does not hold a way in.
	codes := make([]string, 8)
	for i := range codes {
		c, err := adminauth.NewTOTPSecret()
		if err != nil {
			a.serverError(w, "recovery code", err)
			return
		}
		codes[i] = strings.ToLower(c[:10])
		hash, herr := adminauth.HashPassword(codes[i])
		if herr != nil {
			a.serverError(w, "recovery hash", herr)
			return
		}
		id := domain.NewID()
		if _, err := a.cfg.DB.ExecContext(r.Context(),
			`INSERT INTO admin_recovery_codes (id, admin_id, code_hash) VALUES (?, ?, ?)`,
			id.Bytes(), ad.ID.Bytes(), hash); err != nil {
			a.serverError(w, "recovery store", err)
			return
		}
	}

	if _, err := a.cfg.DB.ExecContext(r.Context(),
		`UPDATE admins SET totp_enabled_at = ? WHERE id = ?`,
		time.Now().UTC(), ad.ID.Bytes()); err != nil {
		a.serverError(w, "totp enable", err)
		return
	}
	actor := a.usersRowFor(r, ad)
	a.audit(r, ad.TenantID, actor, "admin.totp_enabled", actor, nil)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (a *API) totpDisable(w http.ResponseWriter, r *http.Request) {
	ad := adminFromContext(r.Context())
	if ad == nil {
		writeError(w, http.StatusUnauthorized, "로그인이 필요합니다")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// The password again, because turning the second factor off is the
	// one action that undoes everything it protects, and a session
	// borrowed from an unlocked screen should not be enough.
	var hash string
	if err := a.cfg.DB.QueryRowContext(r.Context(),
		`SELECT password_hash FROM admins WHERE id = ?`, ad.ID.Bytes()).
		Scan(&hash); err != nil {
		a.serverError(w, "totp disable lookup", err)
		return
	}
	if !adminauth.VerifyPassword(hash, body.Password) {
		writeError(w, http.StatusForbidden, "비밀번호가 맞지 않습니다")
		return
	}
	if _, err := a.cfg.DB.ExecContext(r.Context(),
		`UPDATE admins SET totp_secret = NULL, totp_enabled_at = NULL WHERE id = ?`,
		ad.ID.Bytes()); err != nil {
		a.serverError(w, "totp disable", err)
		return
	}
	_, _ = a.cfg.DB.ExecContext(r.Context(),
		`DELETE FROM admin_recovery_codes WHERE admin_id = ?`, ad.ID.Bytes())
	actor := a.usersRowFor(r, ad)
	a.audit(r, ad.TenantID, actor, "admin.totp_disabled", actor, nil)
	w.WriteHeader(http.StatusNoContent)
}
