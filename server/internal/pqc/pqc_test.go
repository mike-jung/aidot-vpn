package pqc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	encapKey, decapKey, err := GenerateTenantKeypair()
	if err != nil {
		t.Fatalf("GenerateTenantKeypair: %v", err)
	}
	if len(encapKey) != EncapKeySize {
		t.Errorf("encap key size: %d", len(encapKey))
	}

	clientSS, ct, err := Encapsulate(encapKey)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) != CiphertextSize {
		t.Errorf("ciphertext size: %d", len(ct))
	}

	serverSS, err := Decapsulate(decapKey, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(clientSS, serverSS) {
		t.Error("client and server derived different shared secrets")
	}
	if len(clientSS) != SharedSecretSize {
		t.Errorf("shared secret size: %d", len(clientSS))
	}
}

func TestDecapsulate_RejectsCorruptedCiphertext(t *testing.T) {
	encapKey, decapKey, _ := GenerateTenantKeypair()
	_, ct, _ := Encapsulate(encapKey)
	// Flip a byte; ML-KEM is implicit-rejection so it returns a deterministic
	// fake secret, NOT an error. But we expect the secret to differ from
	// what a fresh encapsulation would yield. ML-KEM's implicit rejection
	// is a security feature: an attacker who feeds garbage ciphertext gets
	// pseudorandom output that's unlinkable to anything they could
	// independently compute.
	corrupted := make([]byte, len(ct))
	copy(corrupted, ct)
	corrupted[0] ^= 0xFF
	ss1, err := Decapsulate(decapKey, corrupted)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	// Rerun with a different corruption — should yield a *different* fake
	// secret each time but still no error.
	corrupted2 := make([]byte, len(ct))
	copy(corrupted2, ct)
	corrupted2[10] ^= 0xFF
	ss2, _ := Decapsulate(decapKey, corrupted2)

	if bytes.Equal(ss1, ss2) {
		t.Error("two different corruptions yielded same fake secret (suspect)")
	}
}

func TestHybridPSK_DeterministicAcrossSides(t *testing.T) {
	classical := make([]byte, 32)
	_, _ = rand.Read(classical)
	kemSS := make([]byte, 32)
	_, _ = rand.Read(kemSS)
	deviceID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	psk1, err := HybridPSK(classical, kemSS, deviceID)
	if err != nil {
		t.Fatalf("HybridPSK: %v", err)
	}
	psk2, _ := HybridPSK(classical, kemSS, deviceID)
	if !bytes.Equal(psk1, psk2) {
		t.Error("HybridPSK is not deterministic")
	}
	if len(psk1) != 32 {
		t.Errorf("PSK length %d", len(psk1))
	}

	// Different device id -> different PSK (info parameter binds to device).
	deviceID2 := []byte{99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99}
	psk3, _ := HybridPSK(classical, kemSS, deviceID2)
	if bytes.Equal(psk1, psk3) {
		t.Error("different device id should produce different PSK")
	}
}

func TestHybridPSK_RejectsBadInput(t *testing.T) {
	_, err := HybridPSK(make([]byte, 16), make([]byte, 32), []byte{1})
	if err == nil {
		t.Error("expected reject for short classical PSK")
	}
	_, err = HybridPSK(make([]byte, 32), make([]byte, 16), []byte{1})
	if err == nil {
		t.Error("expected reject for short KEM secret")
	}
}
