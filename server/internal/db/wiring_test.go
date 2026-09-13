package db

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryMigratedColumnIsReachable is a guard against this project's
// most persistent failure mode.
//
// Five times now a release has added a column, written the enforcement
// logic around it, tested that logic, and shipped without the one line
// that connects it to anything:
//
//	0.10.0  allowed_ips hardcoded to []; GetEffectiveAllowedIPs dead code
//	0.13.0  attestation_chain_pem decoded, then discarded
//	0.13.0  the attestation gate itself, never installed
//	0.15.0  route_scope / dns_servers, no API — DB edits only
//	0.11.0  deployment_mode / host_package, unread for six releases
//
// Each survived review because everything *looked* implemented. Code
// review does not catch a missing connection; only asking "does anything
// read this?" does. So this test asks, mechanically.
//
// It is deliberately crude: a grep for each column name across the Go
// tree. That yields false negatives (a column read through `SELECT *`
// would pass without being used) and it cannot tell reading from wiring.
// What it does catch is the exact shape that has bitten repeatedly — a
// column that no source file mentions at all.
//
// When this fails, the fix is usually not to add the column to the
// exemption list.
func TestEveryMigratedColumnIsReachable(t *testing.T) {
	root := findRepoRoot(t)

	columns := columnsFromMigrations(t, filepath.Join(root, "internal", "db", "migrations"))
	if len(columns) == 0 {
		t.Fatal("no columns parsed from migrations; the parser is broken, not the schema")
	}

	sources := goSources(t, root)

	// Columns that legitimately have no Go reader.
	exempt := map[string]string{
		// Written by DEFAULT / ON UPDATE, read only by operators in SQL.
		"created_at":    "timestamp maintained by the database",
		"updated_at":    "timestamp maintained by the database",
		"first_seen_at": "timestamp maintained by the database",
		// Bookkeeping the resolver writes but nothing reads back.
		"agent_token_set_at": "diagnostic timestamp, surfaced via SQL only",
	}

	// Known unwired columns, recorded as debt rather than dismissed.
	//
	// These predate the test. Introducing the check with them failing
	// would make it permanently red and therefore ignored, so they are
	// baselined — but listed individually, with what each was for, so the
	// list is a work queue and not a silencer.
	//
	// The rule going forward: this map shrinks. Adding an entry to it
	// means writing down why a column you just added has no reader, which
	// is a question worth having to answer out loud.
	// This map has shrunk from 14 entries in 0.17.0 to two.
	//
	//   0.20.0  secret_key, rotated_at      — pqc.Store reads them
	//   0.23.0  fingerprint_sha256, not_before, not_after,
	//           revocation_reason, last_login_at — finally written
	//   0.24.0  added_at, endpoint_id, started_at — dropped by
	//           migration 0013 rather than wired
	//
	// The two that remain were misreadings, not dead columns, and both
	// are worth keeping documented so nobody drops them on a second
	// pass: this check reads only Go, so a column populated from SQL or
	// by a column DEFAULT looks unreferenced to it.
	baseline := map[string]string{
		// 0001 — schema drafted ahead of the features that would use it.
		"slug":        "tenant slug; tenants are addressed by ID everywhere",
		"verified_at": "audit chain verification timestamp; verify runs on demand and returns its result",

		// 0002 — tenant_kem_keys entries removed in 0.20.0, when
		// pqc.Store finally read them. The baseline shrank as intended:
		// mislabelled in 0.17.0, corrected in 0.18.0, cleared in 0.20.0.
	}

	var missing []string
	for col, file := range columns {
		if reason, ok := exempt[col]; ok {
			t.Logf("skipping %s (%s): %s", col, file, reason)
			continue
		}
		if reason, ok := baseline[col]; ok {
			if mentionedIn(sources, col) {
				// Good news that should not stay silent: something now
				// reads a column the baseline says is unused. Remove the
				// entry so the list keeps shrinking.
				t.Errorf("%s is now referenced in Go — remove it from the baseline", col)
			} else {
				t.Logf("known debt: %s (%s) — %s", col, file, reason)
			}
			continue
		}
		if !mentionedIn(sources, col) {
			missing = append(missing, col+"  (added by "+file+")")
		}
	}

	if len(missing) > 0 {
		t.Errorf("these columns exist in the schema but no Go source mentions them — "+
			"they were probably added without their wiring:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

var addColumnRe = regexp.MustCompile(`(?i)ADD\s+COLUMN\s+` + "`?" + `([a-z0-9_]+)` + "`?")
var dropColumnRe = regexp.MustCompile(`(?i)DROP\s+COLUMN\s+` + "`?" + `([a-z0-9_]+)` + "`?")
var dropTableRe = regexp.MustCompile(`(?i)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?` + "`?" + `([a-z0-9_]+)` + "`?")
var createColRe = regexp.MustCompile(`(?im)^\s+` + "`?" + `([a-z][a-z0-9_]*)` + "`?" + `\s+(BINARY|VARBINARY|VARCHAR|TINYINT|INT|BOOLEAN|TIMESTAMP|ENUM|TEXT|BIGINT)`)

// columnsFromMigrations returns column name → the migration that added it.
func columnsFromMigrations(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		// Strip comments so prose mentioning a column name doesn't count
		// as a declaration.
		clean := regexp.MustCompile(`(?m)--[^\n]*`).ReplaceAllString(string(body), "")

		for _, m := range addColumnRe.FindAllStringSubmatch(clean, -1) {
			if _, seen := out[m[1]]; !seen {
				out[m[1]] = e.Name()
			}
		}
		for _, m := range createColRe.FindAllStringSubmatch(clean, -1) {
			if _, seen := out[m[1]]; !seen {
				out[m[1]] = e.Name()
			}
		}

		// Columns a later migration removes are no longer in the schema,
		// so they must leave this set.
		//
		// Missing this made the check fail after migration 0013 dropped
		// three columns: it read every `ADD COLUMN` and `CREATE TABLE`
		// ever written and none of the removals, so it was reporting the
		// schema as of 0001 rather than as of now. Entries are processed
		// in filename order, which is migration order, so a drop only
		// removes something an earlier file added.
		for _, m := range dropColumnRe.FindAllStringSubmatch(clean, -1) {
			delete(out, m[1])
		}
	}
	return out
}

func goSources(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Test files are excluded, and not only because this file lists
		// every baselined column as a string literal and would otherwise
		// count itself as a reader. The question being asked is whether
		// PRODUCTION code reads the column; a name that appears only in
		// tests is exactly as unwired as one that appears nowhere.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		out = append(out, string(b))
		return nil
	})
	if err != nil {
		t.Fatalf("walk sources: %v", err)
	}
	return out
}

func mentionedIn(sources []string, column string) bool {
	for _, src := range sources {
		if strings.Contains(src, column) {
			return true
		}
	}
	return false
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate go.mod")
	return ""
}
