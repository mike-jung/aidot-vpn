# Getting started

AidotVPN Public runs a standalone management controller and console with an authenticated Linux VPN gateway. The Compose setup is for a local evaluation; provision production network endpoints, persistent keys, database storage and TLS deliberately.

## Prerequisites

- Node.js 22.19.0 or newer and Go 1.27.1 on the source host. Installer builds fetch and verify their own pinned Node runtime, Go toolchain and Inno Setup compiler, so those do not have to be installed.
- Docker with Linux containers; Docker Desktop with WSL2 on Windows.
- A Linux gateway with WireGuard and nftables for real tunnel traffic.
- JDK 17 and Android SDK 36 to build Android apps (minimum Android API 26).

The evaluation gateway uses a documented, deterministic demo WireGuard identity. Use test devices and test traffic only. For production, provision a unique gateway keypair, register its public key with the controller and use persistent protected key storage.

## Configure the server

Clone the Public repository and copy the environment template:

```powershell
Copy-Item .env.example .env
```

On Linux use `cp .env.example .env`. Edit `.env` before startup:

| Setting | Purpose |
| --- | --- |
| `MARIADB_ROOT_PASSWORD` | Unique database administrator password |
| `AIDOTVPN_DB_PASSWORD` | Unique application database password |
| `AIDOTVPN_ADMIN_EMAIL`, `AIDOTVPN_ADMIN_PASSWORD` | Initial console account, created only when no administrator exists |
| `CONSOLE_PORT` | Browser console port, default `6193` |
| `CONSOLE_BIND_HOST` | `127.0.0.1` for local access; select the intended interface for remote access |
| `AIDOTVPN_PUBLIC_ENDPOINT_HOST` | Address devices can reach for the gateway |
| `WG_DATAPLANE_PORT` | WireGuard UDP port, default `52840` |

The controller, console and WireGuard gateway have different addresses and ports. A real phone cannot reach the host through the phone's own `localhost`. Configure a reachable controller API address with TLS and a gateway endpoint appropriate for your network. The Android emulator's host alias is `10.0.2.2`; that alias is not a physical-device address.

## Start and enroll a device

```bash
npm run https:cert
npm run check:https
npm run start:https
```

The launcher prepares dependencies, the evaluation database, controller, console and gateway components. Open the URL it prints. Trust the generated CA as described in [HTTPS](https.md), sign in with the configured initial administrator and change the password.

1. Start the Android sample app or integrate the VPN library into your app.
2. Set the controller API address in the app and submit an enrollment request.
3. Review the request in **Enrollment requests**, verify the device details and approve it.
4. Assign a group and policy that grants only the required business destinations.
5. Connect the device and check its connection, gateway health and reachability.
6. Revoke a test device and confirm it no longer reaches the protected destination.

Basic security, MFA, access policies and audit logs are available in Public. [Enterprise](editions.md) supplies coordinated HA when a standalone server does not meet availability requirements.

```bash
npm run status
npm run logs
npm stop
```

Changing the source directory does not move an existing database or regenerate its credentials. Preserve your database, `.env`, device CA and settings-encryption key during upgrades. The local console CA is separate from the device enrollment CA.
