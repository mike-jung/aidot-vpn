// SPDX-License-Identifier: Apache-2.0
// Package ha is the Public edition's standalone integration adapter.
// No replication, election, fencing or cluster operations are implemented here.
package ha

import (
	"context"
	"database/sql"
	"errors"
	"github.com/aidotvpn/server/internal/config"
	"net/http"
	"os"
	"strings"
)

type Guard struct {
	Enabled bool
	primary *sql.DB
}

func New(primary *sql.DB, _ config.DBConfig) (*Guard, error) {
	switch strings.ToLower(os.Getenv("AIDOTVPN_HA_ENABLED")) {
	case "", "0", "false":
		return &Guard{primary: primary}, nil
	case "1", "true":
		return nil, errors.New("enterprise_feature_required: HA requires AidotVPN Enterprise; contact mike.jung.global@gmail.com")
	default:
		return nil, errors.New("AIDOTVPN_HA_ENABLED must be true or false")
	}
}
func (g *Guard) Close()                                {}
func (g *Guard) CheckWriter(ctx context.Context) error { return g.primary.PingContext(ctx) }
func (g *Guard) Wrap(next http.Handler) http.Handler   { return next }
func (g *Guard) Status(ctx context.Context) map[string]any {
	ready := g.CheckWriter(ctx) == nil
	return map[string]any{"edition": "public", "enabled": false, "mode": "standalone", "active": ready, "writes_available": ready, "enterprise_required": true, "contact": "mike.jung.global@gmail.com"}
}
