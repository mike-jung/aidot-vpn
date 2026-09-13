package gateway

import (
	"testing"
	"time"
)

func TestReadinessExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &Syncer{}
	if s.Ready(now, 30*time.Second) {
		t.Fatal("never synced")
	}
	s.stats.LastSyncUnix = 990
	if !s.Ready(now, 30*time.Second) {
		t.Fatal("fresh sync not ready")
	}
	if s.Ready(time.Unix(1021, 0), 30*time.Second) {
		t.Fatal("stale sync ready")
	}
	if s.Ready(time.Unix(980, 0), 30*time.Second) {
		t.Fatal("clock rollback ready")
	}
}
