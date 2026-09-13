# aidot-vpn

**Mobile device access management for Android fleets.**

aidot-vpn helps teams enroll mobile devices, approve access, apply network policies and monitor secure connections to business systems. It combines an administration console, a self-hosted controller, Linux WireGuard gateways and an Android VPN library that can be embedded in a business app.

The **Public edition** provides a usable standalone deployment under Apache-2.0. **Enterprise** adds coordinated high availability and cluster operations through a separate commercial agreement.

## What you can manage

- **Device enrollment and approval:** review enrollment requests, approve devices, inspect device identity and connection state, set access expiry and revoke access.
- **Groups and access policies:** organize devices, assign policies and control reachable networks, hosts and ports. Gateway enforcement applies the permitted scope.
- **Secure mobile connectivity:** WireGuard tunnels, per-app routing, DNS and routing configuration, key rotation and authenticated device communication.
- **Device checks:** configurable Android key attestation and Play Integrity checks, plus device admission controls. These checks require the corresponding platform configuration.
- **Operations and accountability:** connection statistics, gateway health, reachability diagnostics, trace views and audit events.
- **Administrator security:** authenticated sessions, administrator permissions, initial password change, TOTP MFA and an HTTPS console.
- **Application integration:** Android `core` and `vpnlib`, a standalone sample app, an embedded business-app demo, and a Node-based Windows/Linux client.
- **Desktop administration:** an Electron-based Windows installer and native Windows/Linux server packaging. The console supports English and Korean.

aidot-vpn's current MDM scope is device enrollment and managed access to business networks. OS-level remote wipe/lock, kiosk mode, application distribution, Apple enrollment and iOS management are not implemented features of this release.

## Editions

| Capability | Public | Enterprise |
| --- | --- | --- |
| Standalone controller, console and Linux gateway | Included | Included |
| Android enrollment, approval, expiry and revocation | Included | Included |
| Groups, network policies, VPN library and clients | Included | Included |
| HTTPS, MFA, permissions and audit events | Included | Included |
| Active–Standby HA with shared service identity | — | Included in the Enterprise deployment package |
| Replica acknowledgement protecting enrollment and policy changes | — | Enterprise |
| Fencing integration and expiring gateway forwarding leases | — | Enterprise |
| Coordinated cluster startup, shutdown and health checks | — | Enterprise |
| Deployment engineering and contractual support | Community support | By agreement |

Public does not impose an artificial device-count or expiry limit. Enterprise implementation is absent from the public source and public installers. See [edition details](docs/editions.md).

**Enterprise inquiries:** [mike.jung.global@gmail.com](mailto:mike.jung.global@gmail.com?subject=aidot-vpn%20Enterprise%20inquiry). Tell us your device count, deployment environment and availability requirements.

## Get started

For a source-based evaluation, prepare **Node.js 24.19.0**, **Go 1.27.1** and **Docker with Linux containers**. Windows Docker Desktop uses WSL2. Android builds additionally require JDK 17 and Android SDK 36.

```bash
git clone https://github.com/mike-jung/aidot-vpn.git
cd aidot-vpn
```

Copy `.env.example` to `.env`, set unique database and initial administrator passwords, and review the endpoint settings in the [setup guide](docs/getting-started.md). Then run:

```bash
npm run https:cert
npm run check:https
npm run start:https
```

Open **https://localhost:6193**, sign in with your configured initial administrator account and complete the required password change. The generated private CA must be explicitly trusted on each computer that accesses the console; see [HTTPS setup](docs/https.md). Existing company-issued certificates can be configured instead.

The console HTTPS certificate covers the browser-to-console connection. Android/controller API TLS and gateway connectivity have their own endpoint and certificate configuration.

## Common commands

| Command | Purpose |
| --- | --- |
| `npm run https:cert` | Generate a private CA/server certificate and configure `.env` |
| `npm run check:https` | Validate console URL, certificate, key and file paths |
| `npm run start:https` | Start the source stack with HTTPS enabled |
| `npm run status` / `npm run logs` / `npm stop` | Inspect or stop the source stack |
| `npm run dist:win` | Build the Public Electron Windows installer |
| `npm run dist:windows` | Build the Public native Windows service installer |
| `npm run dist:linux` | Build the Public Debian/Ubuntu server package |

Public installer builds use only the Public source snapshot. Build requirements and output locations are in [installation and builds](docs/installation.md).

## Documentation and support

[Setup](docs/getting-started.md) · [HTTPS](docs/https.md) · [Android integration](docs/android.md) · [Editions](docs/editions.md) · [Release notes](RELEASE_NOTES.md) · [Security reporting](SECURITY.md)

Use [GitHub issues](https://github.com/mike-jung/aidot-vpn/issues) for reproducible Public-edition defects with sensitive data removed. Send security reports and Enterprise inquiries to [mike.jung.global@gmail.com](mailto:mike.jung.global@gmail.com).

## License

The Public edition is licensed under the **[Apache License 2.0](LICENSE)**, matching aidot-express. Enterprise is separately licensed. See [license scope](LICENSE-SCOPE.md) and [third-party notices](THIRD-PARTY.md).
