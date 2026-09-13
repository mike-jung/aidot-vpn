package httpapi

import (
	"net/http"
	"os"
	"strings"
)

// The port map, as the running stack sees it.
//
// Every port is a variable in .env, and `npm run ports` prints the
// resolved map at the terminal. An admin looking at the console should
// see the same table without a terminal — and should see the values
// the controller actually read, not a copy of the defaults.
//
// Read from the environment at request time. The controller is
// started by npm start with the .env loaded, so these are the numbers
// in effect; a stale .env that has been edited but not restarted will
// still show the old values here, which is correct — those are the
// ports that are open.
func (a *API) registerPortsRoute(mux *http.ServeMux) {
	mux.Handle("GET /settings/ports",
		a.requireAuth(a.requireAdmin(http.HandlerFunc(a.settingsPorts))))
}

func (a *API) settingsPorts(w http.ResponseWriter, r *http.Request) {
	port := func(key, dflt string) string {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			return dflt
		}
		// LISTEN values are host:port; keep the port.
		if i := strings.LastIndex(v, ":"); i >= 0 {
			v = v[i+1:]
		}
		return v
	}
	type row struct {
		Name   string `json:"name"`
		Env    string `json:"env"`
		Port   string `json:"port"`
		Proto  string `json:"proto"`
		Scope  string `json:"scope"` // external | admin | local
		Reason string `json:"reason"`
	}
	rows := []row{
		{"WireGuard", "WG_DATAPLANE_PORT", port("WG_DATAPLANE_PORT", "52840"), "UDP", "external", "폰 → 문지기. 터널 자체"},
		{"컨트롤러 API", "CONTROLLER_HTTP_LISTEN", port("CONTROLLER_HTTP_LISTEN", "10030"), "TCP", "external", "등록·정책·폐기 통보"},
		{"관리실 화면", "CONSOLE_PORT", port("CONSOLE_PORT", "6193"), "TCP", "admin", "관리자 브라우저"},
		{"컨트롤러 gRPC", "CONTROLLER_GRPC_LISTEN", port("CONTROLLER_GRPC_LISTEN", "10021"), "TCP", "local", "내부"},
		{"MariaDB", "MARIADB_HOST_PORT", port("MARIADB_HOST_PORT", "4336"), "TCP", "local", "컨트롤러만"},
		{"문지기 상태", "GATEWAY_HEALTH_PORT", port("GATEWAY_HEALTH_PORT", "10140"), "TCP", "local", "컨테이너 안"},
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ports": rows,
		"note":  ".env 의 변수를 고치고 npm start 를 다시 실행하면 바뀝니다",
	})
}
