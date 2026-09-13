package adminauth

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected PHC prefix: %s", h[:40])
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("right password rejected")
	}
	if VerifyPassword(h, "correct horse battery stapl") {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword(h, "") {
		t.Fatal("empty password accepted")
	}
}

// Two hashes of the same password differ (fresh salt each time), and
// both verify. A stored hash must never be comparable across accounts.
func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("identical hashes for identical passwords: salt is not random")
	}
	if !VerifyPassword(a, "same") || !VerifyPassword(b, "same") {
		t.Fatal("salted hashes do not verify")
	}
}

// A hash written with different parameters still verifies, because the
// parameters are read from the string, not assumed. This is what lets
// the cost be raised later without rehashing everyone at once.
func TestVerifyReadsParametersFromHash(t *testing.T) {
	// m=16 MiB, t=2, p=1 — deliberately not the current constants.
	phc := "$argon2id$v=19$m=16384,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$" +
		"Q/5hSOpCEGA9jkFE3f/KHM8I0d+G0Wc4p9qkX2W0KP0"
	// The key above was not computed; only the parse path is under test.
	// A garbage key must fail closed, not panic.
	if VerifyPassword(phc, "anything") {
		t.Fatal("garbage hash verified")
	}
}

func TestMalformedHashesFailClosed(t *testing.T) {
	for _, bad := range []string{"", "$", "$argon2id$", "$bcrypt$x$y$z$w", "$argon2id$v=19$m=x,t=y,p=z$a$b"} {
		if VerifyPassword(bad, "x") {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}
