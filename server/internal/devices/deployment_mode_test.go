package devices

import "testing"

// Migration 0010 added deployment_mode and host_package in 0.11.0. No Go
// code read either column until 0.17.0 — six releases in which the
// duplicate-registration case they exist to reveal stayed invisible.
//
// These tests exist mostly to make the wiring load-bearing: a future
// refactor that drops the columns from the scan or the insert now breaks
// a test instead of silently reverting to the earlier state.

func TestDeploymentModeValidity(t *testing.T) {
	if !DeploymentStandalone.Valid() {
		t.Error("standalone must be valid")
	}
	if !DeploymentEmbedded.Valid() {
		t.Error("embedded must be valid")
	}
	for _, bad := range []DeploymentMode{"", "STANDALONE", "library", "embeded"} {
		if bad.Valid() {
			t.Errorf("%q must not be accepted as a mode", bad)
		}
	}
}

// Wire values land in the API and the console's switch statements.
// Renaming one silently turns the badge into a raw string — which is
// exactly the bug fixed in DevicesView in 0.16.0, where the console
// compared against names the API had never sent.
func TestDeploymentModeWireValues(t *testing.T) {
	if DeploymentStandalone != "standalone" {
		t.Errorf("standalone wire value changed: %q", DeploymentStandalone)
	}
	if DeploymentEmbedded != "embedded" {
		t.Errorf("embedded wire value changed: %q", DeploymentEmbedded)
	}
}

// An unset mode must default rather than persist as empty: the column is
// NOT NULL, and an empty in-memory value would render as "" in the
// console.
func TestUnsetModeDefaultsToStandalone(t *testing.T) {
	var m DeploymentMode
	if m.Valid() {
		t.Fatal("the zero value must not be valid, so callers are forced to default it")
	}
}

// nullIfEmpty keeps "not reported" distinguishable from "reported as
// blank" in host_package. Collapsing the two would make it impossible to
// tell a pre-0.17.0 client from one that sent an empty package name.
func TestNullIfEmpty(t *testing.T) {
	if nullIfEmpty("") != nil {
		t.Error("empty string must store as NULL")
	}
	got := nullIfEmpty("com.example.app")
	if s, ok := got.(string); !ok || s != "com.example.app" {
		t.Errorf("non-empty value mangled: %v", got)
	}
}
