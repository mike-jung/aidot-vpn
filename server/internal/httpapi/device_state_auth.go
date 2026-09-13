package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

func (a *API) requireDeviceStateAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Authorization")
		deny := func() {
			w.Header().Set("WWW-Authenticate", `Bearer realm="device-state"`)
			writeError(w, http.StatusUnauthorized, "device state authentication required; update client and re-enroll")
		}
		id, err := parseHexID(r.PathValue("id"))
		if err != nil {
			deny()
			return
		}
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(r.Header.Values("Authorization")) != 1 || len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			deny()
			return
		}
		token := fields[1]
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(raw) != 32 || len(token) != 43 {
			deny()
			return
		}
		var expected []byte
		err = a.cfg.DB.QueryRowContext(r.Context(), "SELECT token_hash FROM device_state_tokens WHERE device_id = ?", id.Bytes()).Scan(&expected)
		if errors.Is(err, sql.ErrNoRows) {
			deny()
			return
		}
		if err != nil {
			a.serverError(w, "state credential lookup", err)
			return
		}
		digest := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(expected, digest[:]) != 1 {
			deny()
			return
		}
		next.ServeHTTP(w, r)
	})
}
