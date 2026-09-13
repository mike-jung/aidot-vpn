# Release notes

## v1.20.2 — Console HTTPS and Public edition

- Generate a local HTTPS certificate and configure the console with `npm run https:cert`.
- Resolve source certificate paths consistently on Windows and Linux, including custom env files and directories containing spaces.
- Show an actionable message when certificates are missing; continue to validate expiry, hostname and the matching private key.
- Provide a standalone Public edition under Apache-2.0, with HA and cluster operations supplied separately through Enterprise.
- Present device management capabilities, setup instructions and Enterprise contact information in English-first product documentation.

Private CAs require explicit trust on each accessing computer. Console HTTPS is separate from the mobile controller API's TLS configuration.
