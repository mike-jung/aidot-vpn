package ha

import (
	"github.com/aidotvpn/server/internal/config"
	"strings"
	"testing"
)

func TestPublicRejectsHAEnablement(t *testing.T) {
	for _, value := range []string{"true", "1", "TRUE"} {
		t.Setenv("AIDOTVPN_HA_ENABLED", value)
		if _, err := New(nil, config.DBConfig{}); err == nil || !strings.Contains(err.Error(), "enterprise_feature_required") {
			t.Fatalf("HA enabled with %q: %v", value, err)
		}
	}
}
func TestPublicStandaloneNeedsNoReplica(t *testing.T) {
	for _, value := range []string{"", "false", "0"} {
		t.Setenv("AIDOTVPN_HA_ENABLED", value)
		g, err := New(nil, config.DBConfig{})
		if err != nil || g.Enabled {
			t.Fatalf("standalone %q: %v", value, err)
		}
	}
	t.Setenv("AIDOTVPN_HA_ENABLED", "typo")
	if _, err := New(nil, config.DBConfig{}); err == nil {
		t.Fatal("invalid flag accepted")
	}
}
