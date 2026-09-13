package httpapi

import (
	"errors"
	"fmt"
	"testing"
)

// End-to-end testing in 0.22.0 surfaced a registration failing with the
// raw driver text echoed to the client:
//
//	register failed: insertDeviceKey: Error 1062 (23000): Duplicate
//	entry '\xE5\xB6...' for key 'uq_device_keys_pubkey'
//
// That leaks the table, the index name and a fragment of another
// device's key material to whoever triggered it.
func TestConstraintViolationsAreRecognised(t *testing.T) {
	cases := map[string]bool{
		"insertDeviceKey: Error 1062 (23000): Duplicate entry 'x' for key 'uq_device_keys_pubkey'": true,
		"Error 1452 (23000): Cannot add or update a child row":                                     true,
		"Error 1451 (23000): Cannot delete or update a parent row":                                 true,
		"Error 1048 (23000): Column 'tenant_id' cannot be null":                                    true,
		// Not constraint failures — these must keep their existing
		// handling rather than being flattened into a 409.
		"dial tcp 127.0.0.1:3306: connect: connection refused": false,
		"context deadline exceeded":                            false,
		"invalid device public key":                            false,
	}
	for msg, want := range cases {
		if got := isConstraintViolation(errors.New(msg)); got != want {
			t.Errorf("isConstraintViolation(%q) = %v, want %v", msg, got, want)
		}
	}
	if isConstraintViolation(nil) {
		t.Error("nil must not be a constraint violation")
	}
}

// Wrapped errors are the normal shape here — the repo layer prefixes its
// operation name before the driver's text.
func TestWrappedConstraintIsRecognised(t *testing.T) {
	inner := errors.New("Error 1062 (23000): Duplicate entry")
	wrapped := fmt.Errorf("insertDeviceKey: %w", inner)
	if !isConstraintViolation(wrapped) {
		t.Error("a wrapped constraint error must still be recognised")
	}
}
