package pqc

import (
	"bytes"
	"testing"
)

// End-to-end exercise of the construction the Store enables: generate a
// tenant keypair, encapsulate as a client would, decapsulate as the
// server does, and confirm both ends derive the same hybrid PSK.
//
// This is what was never verified before 0.20.0 — the primitives had
// tests, but nothing checked that the two halves of the protocol agree,
// because there were no two halves.
func TestHybridPSKRoundTrip(t *testing.T) {
	encap, decap, err := GenerateTenantKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if len(encap) != EncapKeySize {
		t.Fatalf("encap key %d bytes, want %d", len(encap), EncapKeySize)
	}

	// Client side.
	clientShared, ciphertext, err := Encapsulate(encap)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	if len(ciphertext) != CiphertextSize {
		t.Fatalf("ciphertext %d bytes, want %d", len(ciphertext), CiphertextSize)
	}

	// Server side.
	serverShared, err := Decapsulate(decap, ciphertext)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(clientShared, serverShared) {
		t.Fatal("the two ends derived different shared secrets")
	}

	classical := bytes.Repeat([]byte{0x42}, 32)
	deviceID := bytes.Repeat([]byte{0x01}, 16)

	a, err := HybridPSK(classical, clientShared, deviceID)
	if err != nil {
		t.Fatalf("client hybrid: %v", err)
	}
	b, err := HybridPSK(classical, serverShared, deviceID)
	if err != nil {
		t.Fatalf("server hybrid: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("hybrid PSKs differ — the tunnel would handshake and drop every packet")
	}
	if len(a) != 32 {
		t.Fatalf("hybrid PSK %d bytes, want 32", len(a))
	}
}

// The hybrid PSK must differ from the classical one, or mixing in the
// KEM secret achieved nothing.
func TestHybridDiffersFromClassical(t *testing.T) {
	encap, decap, _ := GenerateTenantKeypair()
	_, ct, _ := Encapsulate(encap)
	shared, _ := Decapsulate(decap, ct)

	classical := bytes.Repeat([]byte{0x42}, 32)
	hybrid, err := HybridPSK(classical, shared, bytes.Repeat([]byte{0x01}, 16))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hybrid, classical) {
		t.Fatal("hybrid PSK equals the classical PSK; the KEM contributed nothing")
	}
}

// Binding to the device ID means two devices sharing a tenant keypair and
// (hypothetically) a classical PSK still get distinct final PSKs.
func TestHybridIsBoundToDeviceID(t *testing.T) {
	encap, decap, _ := GenerateTenantKeypair()
	_, ct, _ := Encapsulate(encap)
	shared, _ := Decapsulate(decap, ct)
	classical := bytes.Repeat([]byte{0x42}, 32)

	a, _ := HybridPSK(classical, shared, bytes.Repeat([]byte{0x01}, 16))
	b, _ := HybridPSK(classical, shared, bytes.Repeat([]byte{0x02}, 16))
	if bytes.Equal(a, b) {
		t.Fatal("different devices must derive different PSKs")
	}
}

// A ciphertext from a different tenant's key must not decapsulate to the
// client's secret. ML-KEM is designed to return a pseudorandom value
// rather than an error here, so the check is that the secrets differ.
func TestWrongKeyYieldsDifferentSecret(t *testing.T) {
	encapA, _, _ := GenerateTenantKeypair()
	_, decapB, _ := GenerateTenantKeypair()

	clientShared, ct, _ := Encapsulate(encapA)
	otherShared, err := Decapsulate(decapB, ct)
	if err != nil {
		// Also acceptable — either way the wrong key does not recover
		// the secret.
		return
	}
	if bytes.Equal(clientShared, otherShared) {
		t.Fatal("a foreign decap key recovered the shared secret")
	}
}

func TestHybridRejectsWrongSizes(t *testing.T) {
	if _, err := HybridPSK(make([]byte, 16), make([]byte, 32), nil); err == nil {
		t.Error("a short classical PSK must be rejected")
	}
	if _, err := HybridPSK(make([]byte, 32), make([]byte, 16), nil); err == nil {
		t.Error("a short KEM secret must be rejected")
	}
}
