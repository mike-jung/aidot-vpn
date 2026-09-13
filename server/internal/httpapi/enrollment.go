package httpapi

import "net/http"

// Enrollment token admin surface.
//
// Exists so enrolling a phone is a click rather than a curl. The
// tutorial previously instructed the reader to mint an OIDC access
// token from a terminal and paste it into the app — which needs the
// realm's client id, a user's password, and a shell, none of which the
// person enrolling a handset should have to hold.
//
// Admin-only. A token grants enrolment into a policy, so being able to
// mint one is being able to decide what a new device reaches.
// Admin-issued enrolment tokens were removed in 1.8.4.
//
// 1.2.0 replaced them with request-and-approve because there was no way
// to get a 38-character secret onto a handset: "create a token in the
// console, then how do you get it to the phone?" The console kept
// minting them anyway, and in 1.8.3 I mistook that for a gap and added
// a client flag to consume them — reviving the very thing that had been
// retired. Removing the screen and these routes closes the loop.
//
// The table and internal grant machinery stay: approving an enrolment
// request mints a single-use grant through the same code. What is gone
// is the path where an *admin* creates a secret for a human to carry.
//
// When to bring it back: an MDM or imaging pipeline that pushes
// configuration to machines, where nobody types anything. Then the
// 38 characters are not a problem and this is the right shape. Until
// then it is a credential with no delivery channel.
func (a *API) registerEnrollmentRoutes(mux *http.ServeMux) {}
