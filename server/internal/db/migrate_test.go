package db

import (
	"testing"
)

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"one statement", "SELECT 1;", []string{"SELECT 1"}},
		{"two statements",
			"SELECT 1;\nSELECT 2;",
			[]string{"SELECT 1", "SELECT 2"}},
		{"trailing semicolon optional",
			"SELECT 1",
			[]string{"SELECT 1"}},
		{"line comments stripped",
			"-- comment\nSELECT 1; -- inline\nSELECT 2;",
			[]string{"SELECT 1", "SELECT 2"}},
		{"empty statements skipped",
			";; SELECT 1; ;",
			[]string{"SELECT 1"}},
		{"multiline statement",
			"CREATE TABLE x (\n  id INT\n);\nINSERT INTO x VALUES (1);",
			[]string{"CREATE TABLE x (\n  id INT\n)", "INSERT INTO x VALUES (1)"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitStatements(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("%d statements, want %d: %#v", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d]: %q\n  want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestLoadMigrations_Embedded(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("expected at least one migration")
	}
	// Versions must be strictly increasing.
	for i := 1; i < len(migs); i++ {
		if migs[i].version <= migs[i-1].version {
			t.Errorf("non-monotonic version at i=%d: %d after %d",
				i, migs[i].version, migs[i-1].version)
		}
	}
	// Both directions must be non-empty.
	for _, m := range migs {
		if m.up == "" || m.down == "" {
			t.Errorf("version %d (%s) missing direction", m.version, m.name)
		}
	}
}
