<div align="center">

# aidot-vpn

**Enroll the device. Approve the access. Let the gateway enforce it.**

Mobile device access management for Android fleets.

A self-hosted controller and console, Linux WireGuard gateways, and an Android VPN
library that embeds in your business app.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%3E%3D22.19-brightgreen)
![Version](https://img.shields.io/github/package-json/v/mike-jung/aidot-vpn?label=version&color=orange)
[![Public validation](https://github.com/mike-jung/aidot-vpn/actions/workflows/ci.yml/badge.svg)](https://github.com/mike-jung/aidot-vpn/actions/workflows/ci.yml)

</div>

---

## Why aidot-vpn?

Business apps on company phones need to reach internal systems, and only those
systems. Someone has to approve each device, decide what it may reach, take the
access away again, and be able to show afterwards what happened. A general VPN
gives every connected device the same network; an MDM platform manages the
device but not the path into your servers.

**aidot-vpn** ties the two together. A device enrolls through your app, an
administrator approves it in the console, and a Linux gateway builds a WireGuard
tunnel that carries only the destinations its policy allows — enforced per device
with nftables, not on the phone. The **Public edition** is a complete standalone
deployment under Apache-2.0; **Enterprise** adds coordinated high availability
and cluster operations under a separate agreement.

## What you get

| Feature | What it does |
|---|---|
| **Enrollment and approval** | Review enrollment requests, approve devices, inspect device identity and connection state, set access expiry and revoke access. |
| **Groups and access policies** | Organize devices, assign policies and control reachable networks, hosts and ports. The gateway applies the permitted scope; nothing else is routed. |
| **Secure mobile connectivity** | WireGuard tunnels, per-app routing, DNS and routing configuration, key rotation and authenticated device communication. |
| **Device checks** | Configurable Android key attestation and Play Integrity checks, plus device admission controls. These require the corresponding platform configuration. |
| **Operations and accountability** | Connection statistics, gateway health, reachability diagnostics, trace views and audit events. |
| **Administrator security** | Authenticated sessions, administrator permissions, initial password change, TOTP MFA and an HTTPS console in English and Korean. |
| **Application integration** | Android `core` and `vpnlib` modules, a standalone sample app, an embedded business-app demo and a Node-based Windows/Linux client. |
| **Installers** | A native Windows service installer, an Electron desktop app for Windows and a Debian/Ubuntu server package, each with the pinned Node runtime and Go binaries bundled. |

The current MDM scope is device enrollment and managed access to business
networks. OS-level remote wipe/lock, kiosk mode, application distribution, Apple
enrollment and iOS management are not implemented features of this release.

## Public and Enterprise

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

Public imposes no artificial device-count or expiry limit, and the Enterprise
implementation is absent from the public source and installers: setting
`AIDOTVPN_HA_ENABLED=true` in a Public build fails with
`enterprise_feature_required`. See the [edition details](docs/editions.md).

**Enterprise inquiries:** [mike.jung.global@gmail.com](mailto:mike.jung.global@gmail.com?subject=aidot-vpn%20Enterprise%20inquiry).
Tell us your device count, deployment environment and availability requirements.

## Quick start

Requires **Node.js 22.19.0 or later**, **Go 1.27.1** and **Docker with Linux
containers** (Docker Desktop with WSL2 on Windows) on the source host. Installer
builds fetch and verify their own pinned tools, so a build machine needs nothing
beyond a recent Node.

```bash
git clone https://github.com/mike-jung/aidot-vpn.git
cd aidot-vpn
cp .env.example .env        # PowerShell: Copy-Item .env.example .env
```

Set unique `MARIADB_ROOT_PASSWORD`, `AIDOTVPN_DB_PASSWORD` and the initial
administrator account (`AIDOTVPN_ADMIN_EMAIL`, `AIDOTVPN_ADMIN_PASSWORD`) in `.env`;
the account is created only when no administrator exists yet. Then:

```bash
npm run https:cert          # private CA and console certificate, written into .env
npm run check:https         # URL, certificate, key and path validation
npm run start:https         # evaluation database, controller, console and gateway
```

Open **[https://localhost:6193](https://localhost:6193)**, sign in with the
configured initial administrator and complete the required password change.
The generated private CA must be trusted explicitly on each computer that opens
the console; company-issued certificates can be configured instead. See
[console HTTPS](docs/https.md). `npm run status`, `npm run logs` and `npm stop`
inspect or stop the source stack.

The evaluation stack uses a documented demo WireGuard identity: use test devices
and test traffic only. The console certificate covers the browser connection;
the Android controller API and the gateway endpoint have their own address, TLS
and firewall configuration, described in the [setup guide](docs/getting-started.md).

### Your first device

1. Build the Android sample app (JDK 17, Android SDK 36, minimum API 26):

   ```bash
   cd client-android
   ./gradlew :sample-app:assembleDebug     # Windows: .\gradlew.bat
   ```

2. Set the controller API address in the app and submit an enrollment request.
   A real phone cannot reach your host through its own `localhost`; the emulator
   alias is `10.0.2.2`.
3. Open **Enrollment requests** in the console, verify the device details and
   approve.
4. Assign a group and a policy that grants only the required business
   destinations, then connect the device and check its connection, gateway
   health and reachability.
5. Revoke the test device and confirm it no longer reaches the protected
   destination.

The Node client does the same from a Linux or Windows machine:
`node client-node/aidot-client.mjs enroll <controller-url> <ENROLLMENT_PASSWORD> "<device name>"`
prints the six-digit code for the administrator to compare, and `wg-config`
writes a WireGuard configuration once the request is approved.

## Integrate the VPN library

| Module | Purpose |
| --- | --- |
| `core` | Device identity, controller communication and shared models |
| `vpnlib` | Embeddable VPN service and tunnel lifecycle |
| `sample-app` | Standalone VPN app with enrollment and settings |
| `demo-app` | Embedding the VPN engine in a business app |

Depend on `core` and `vpnlib` and follow `demo-app` for the service permission,
enrollment and tunnel lifecycle integration. Android grants VPN permission to
your app; the library does not grant device-owner privileges or OS-level
management. Policies decide reachable destinations and per-app routing on the
server side. Debug APKs are for evaluation; sign release builds with your own
credentials and keep keystores out of Git. See [Android integration](docs/android.md)
and the [client API contract](docs/client-api.md).

## Deploy a gateway

Device traffic terminates on a Linux host with WireGuard and nftables. The
gateway agent authenticates to the controller with a node token issued by the
management API, reconciles WireGuard peers and rewrites its nftables table on
every policy change: each device gets exactly the destinations, protocols and
ports its policy names, and a revoked device loses them at the next
reconciliation. The evaluation stack runs one gateway in Docker; the Debian
package installs the same agent as the `aidotvpn-gateway` service. For
production, provision a unique gateway keypair and persistent key storage, and
publish an endpoint devices can actually reach (`AIDOTVPN_PUBLIC_ENDPOINT_HOST`,
UDP `WG_DATAPLANE_PORT`, default `52840`).

The Windows service installer and the desktop app run the controller and console
only; they still need a Linux gateway for device traffic.

## Build installers

Run these commands from the repository root, each on its native operating system:

| Target | Command | Output |
|---|---|---|
| Windows service installer | `npm run dist:windows` | `AidotVPN-Server-<version>-public-windows-x64-setup.exe` — controller and console as Windows services, with a tray program |
| Windows desktop app | `npm run dist:win` | `AidotVPN-Desktop-<version>-public-windows-x64-setup.exe` — Electron + NSIS, installed per user, bundled or remote server |
| Debian/Ubuntu server | `npm run dist:linux` | `aidotvpn-server_<version>-public_amd64.deb` — controller, console and gateway systemd units |

Installers bundle the runtime, so the target machine needs no Node, Go or source
checkout. The build downloads each pinned tool from its official location,
checks it against a published SHA-256 and caches it under
`packaging/.build-tools/`; a digest that does not match stops the build, and
nothing falls back to another version.

| Tool | Pinned in | Digest checked against |
| --- | --- | --- |
| Node runtime embedded in the installer | `.node-version` | nodejs.org `SHASUMS256.txt` |
| Go toolchain for the service binaries | `toolchain` directive in `server/go.mod` | go.dev release index |
| Inno Setup compiler (Windows) | `packaging/build-tools.json` | digest recorded there, from Microsoft's winget-pkgs manifest |

A build machine needs Node.js at the floor in `package.json` `engines.node`;
Windows additionally needs the .NET Framework C# compiler that ships with
Windows, Linux needs Python 3 and `dpkg-deb`. Inno Setup is installed in
portable mode and writes nothing machine-wide. Behind a firewall, point
`AIDOT_BUILD_NODE_MIRROR` / `AIDOT_BUILD_GO_MIRROR` at a mirror or
`AIDOT_BUILD_*_ARCHIVE` at pre-downloaded files; verification still applies.
Artifacts and their manifest land in `dist/<version>/public/`. A locally built
installer is unsigned. See [installation and builds](docs/installation.md).

## GitHub releases

Each [release](https://github.com/mike-jung/aidot-vpn/releases) attaches the
Public installers above and a `SHA256SUMS.txt` covering them, and its description
says what every attached file is for. Verify a download before running it:

```bash
sha256sum -c SHA256SUMS.txt                       # Linux
Get-FileHash .\AidotVPN-Server-*-setup.exe -Algorithm SHA256   # PowerShell
```

Windows installers are unsigned unless a release records a separate signing
step. Before anything is drafted, the release command compares the published
`PUBLIC_MANIFEST.json` with the source snapshot the installers were built from
and stops if they differ, so the commit a release is tagged from is the source
that produced its binaries. Releases are drafted from the Full project with
`npm run release:github`, reviewed on GitHub and published by hand; the Public
source contains the installer builds, not the publishing tools.

## Configuration and operation

Use [.env.example](.env.example) to configure the database, the initial
administrator, the console listener (`CONSOLE_PORT`, default `6193`;
`CONSOLE_BIND_HOST`), the gateway endpoint and HTTPS. Source runs keep their
evaluation database in Docker; installed packages use their own locations:

| | Windows service | Debian/Ubuntu |
|---|---|---|
| Program files | `%ProgramFiles%\AidotVPN` | `/opt/aidotvpn` |
| Console configuration | `%ProgramData%\AidotVPN\console\config` | `/etc/aidotvpn` |
| Controller configuration | `%ProgramData%\AidotVPN\controller\controller.env` | `/etc/aidotvpn/controller.env` |
| Saved settings and state | `%ProgramData%\AidotVPN\console\console-settings.json` | `/var/lib/aidotvpn` |
| Installed console address | `http://127.0.0.1:9111` | `http://127.0.0.1:9111` |

Configure the controller database, the persistent device CA and the settings
encryption key before enabling an installed service, and keep them — with
`.env`, certificates and database backups — separate from program files.
Upgrades and removal preserve them. The console's private CA is separate from
the device enrollment CA; do not regenerate either on an existing installation.
Console HTTPS for installed packages is enabled with `CONSOLE_HTTPS_ENABLED=true`
and absolute certificate paths readable by the service account.

## Verification and contributing

Every push to the public repository runs **Public validation** on Ubuntu and
Windows: the HTTPS certificate tests, the console sign-in tests and
`go test ./...` for the controller, gateway and relay packages. The Ubuntu job
additionally checks the generated nftables ruleset against the real `nft`
parser, which needs privileges the ordinary test run does not have. Locally:

```bash
npm --prefix console ci
npm run test:https          # console listener and private CA generation
npm run test:login          # console sign-in regression
cd server && go test ./...
```

Use [GitHub issues](https://github.com/mike-jung/aidot-vpn/issues) for
reproducible Public-edition defects with sensitive data removed. Read
[SECURITY](SECURITY.md) to report a vulnerability privately, and
[RELEASE_NOTES](RELEASE_NOTES.md) for what changed in each version and what was
verified.

## License

**Apache License 2.0** for the Public edition, matching aidot-express — see
[LICENSE](LICENSE), [NOTICE](NOTICE) and [third-party notices](THIRD-PARTY.md).
Enterprise is licensed separately; [LICENSE-SCOPE](LICENSE-SCOPE.md) states the
boundary. AidotVPN names and logos are not licensed as trademarks.

© 2026 Aidot Link Co., Ltd. · mike.jung.global@gmail.com
