# Release notes

## v1.20.8 — Public validation and release notes

- Public validation no longer fails on GitHub-hosted runners. The nftables syntax test skips when `nft -c` cannot reach the kernel — even a check-only run needs CAP_NET_ADMIN — and the Linux job now runs that test as root, so the generated ruleset is still validated by the real parser on every push.
- A draft GitHub Release describes what is attached: the Public edition, what each installer is for, what is deliberately absent and how to verify a download, followed by the changes of the version. When a draft is completed from a second machine, the description and SHA256SUMS.txt cover every installer on it.
- Verified on Linux with nftables 1.0.9: the gateway test package passes as root, skips the nft check as an unprivileged user, and fails it only when `AIDOTVPN_TEST_REQUIRE_NFT=1` demands the check. No installer, server or console code changed, and installers were not rebuilt for this entry.

## v1.20.7 — Release before build

- Running `npm run release:github` before building the current version's installer now names the build command to run first.

## v1.20.6 — GitHub release without the CLI

- Publishing a draft Release needs only the token already configured in `.env`; installing the GitHub CLI is optional.
- When no credential is configured, the message says so and explains how to set the token.

## v1.20.5 — Build toolchain provisioning

- Building an installer no longer asks you to install a runtime or compiler first. The pinned Node, Go and Inno Setup are downloaded, checked against their published SHA-256 and cached under `packaging/.build-tools/`.
- A build machine needs only a Node new enough to run the build scripts, stated in `package.json` `engines.node`.
- Inno Setup is installed in portable mode and writes nothing machine-wide.
- Public validation now reports each operating system separately, so a failure shows which job and which step actually failed.

## v1.20.4 — Windows service tray repair

- Update the installed Windows service tray separately from source or Electron Desktop.
- Exit immediately when services are absent/stopped and request administrator approval only when Windows denies service control.
- View the running tray version from its menu and compare the installation with `npm run status:windows`.

## 1.20.3

- Open the dashboard immediately after sign-in and accept both usernames and email addresses.
- Keep the sign-in button busy until navigation finishes and handle outdated screen files without repeated reloads.

## v1.20.2 — Console HTTPS and Public edition

- Generate a local HTTPS certificate and configure the console with `npm run https:cert`.
- Resolve source certificate paths consistently on Windows and Linux, including custom env files and directories containing spaces.
- Show an actionable message when certificates are missing; continue to validate expiry, hostname and the matching private key.
- Provide a standalone Public edition under Apache-2.0, with HA and cluster operations supplied separately through Enterprise.
- Present device management capabilities, setup instructions and Enterprise contact information in English-first product documentation.

Private CAs require explicit trust on each accessing computer. Console HTTPS is separate from the mobile controller API's TLS configuration.
