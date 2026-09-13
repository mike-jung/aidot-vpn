package pqc

import (
	"encoding/base64"
	"testing"
)

// Wire-format constants shared with the Android client
// (core/PqcKemClient.kt). These are FIPS 203 fixed sizes, so a mismatch
// means one side is on a pre-final Kyber draft.
//
// That failure is the dangerous kind: encapsulation succeeds,
// decapsulation succeeds, and the two ends derive DIFFERENT secrets. The
// tunnel completes its handshake and drops every packet, with no error
// on either side. Pinning the sizes here is the cheapest place to catch
// a library upgrade that changes them.
func TestWireSizesMatchFIPS203(t *testing.T) {
	if EncapKeySize != 1184 {
		t.Errorf("encap key size %d; PqcKemClient.ENCAP_KEY_SIZE expects 1184", EncapKeySize)
	}
	if CiphertextSize != 1088 {
		t.Errorf("ciphertext size %d; PqcKemClient.CIPHERTEXT_SIZE expects 1088", CiphertextSize)
	}
	if SharedSecretSize != 32 {
		t.Errorf("shared secret size %d; PqcKemClient.SHARED_SECRET_SIZE expects 32", SharedSecretSize)
	}
	if AlgorithmMLKEM768 != "ml-kem-768" {
		t.Errorf("algorithm id %q; PqcKemClient.ALGORITHM expects ml-kem-768", AlgorithmMLKEM768)
	}
}

// Generated keys and ciphertexts must survive the base64 hop the API
// uses in both directions.
func TestBase64RoundTripPreservesSizes(t *testing.T) {
	encap, decap, err := GenerateTenantKeypair()
	if err != nil {
		t.Fatal(err)
	}

	encapB64 := base64.StdEncoding.EncodeToString(encap)
	decodedEncap, err := base64.StdEncoding.DecodeString(encapB64)
	if err != nil {
		t.Fatalf("encap key base64: %v", err)
	}
	if len(decodedEncap) != EncapKeySize {
		t.Fatalf("encap key survived base64 as %d bytes", len(decodedEncap))
	}

	_, ct, err := Encapsulate(decodedEncap)
	if err != nil {
		t.Fatalf("encapsulate against a base64 round-tripped key: %v", err)
	}

	// The client sends NO_WRAP; the server decodes with StdEncoding.
	// Kotlin's Base64.NO_WRAP produces the same alphabet without
	// newlines, which StdEncoding accepts — this asserts the property
	// rather than assuming it.
	ctB64 := base64.StdEncoding.EncodeToString(ct)
	decodedCT, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		t.Fatalf("ciphertext base64: %v", err)
	}
	if len(decodedCT) != CiphertextSize {
		t.Fatalf("ciphertext survived base64 as %d bytes", len(decodedCT))
	}

	if _, err := Decapsulate(decap, decodedCT); err != nil {
		t.Fatalf("decapsulate after a full base64 round trip: %v", err)
	}
}

// A ciphertext of the wrong length must be refused rather than fed to
// the KEM, so a truncated upload reads as a bad request instead of a
// silently wrong shared secret.
func TestDecapsulateRejectsWrongLength(t *testing.T) {
	_, decap, err := GenerateTenantKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, CiphertextSize - 1, CiphertextSize + 1} {
		if _, err := Decapsulate(decap, make([]byte, n)); err == nil {
			t.Errorf("a %d-byte ciphertext was accepted", n)
		}
	}
}
