# Installation and builds

Use the source quick start for evaluation, or build a platform installer on its native operating system. All public installer commands use the Public source snapshot. Full/Enterprise builds have explicit `:full` commands and remain internal.

| Command | Host and prerequisites | Result |
| --- | --- | --- |
| `npm run dist:win` | Windows x64, Node 22.19.0+, .NET Framework C# compiler | Electron + NSIS desktop installer |
| `npm run dist:windows` | Windows x64, the same prerequisites | Native Windows service installer |
| `npm run dist:linux` | Debian/Ubuntu x64, Node 22.19.0+, Python 3 and dpkg-deb | Native server `.deb` |

Installer builds provision their own pinned tools instead of requiring them on the build machine. Each is downloaded from its official location, checked against a published SHA-256 and cached under `packaging/.build-tools/`; a digest that does not match stops the build, and nothing falls back to another version.

| Tool | Pinned in | Digest checked against |
| --- | --- | --- |
| Node runtime embedded in the installer | `.node-version` | nodejs.org `SHASUMS256.txt` |
| Go toolchain for the service binaries | `toolchain` directive in `server/go.mod` | go.dev release index |
| Inno Setup compiler (Windows) | `packaging/build-tools.json` | digest recorded there, from Microsoft's winget-pkgs manifest |

Inno Setup is installed with `/PORTABLE=1`, so it writes no uninstall entry, Start Menu group or file association. Where a build machine cannot reach those hosts, set `AIDOT_BUILD_NODE_MIRROR` or `AIDOT_BUILD_GO_MIRROR`, or point `AIDOT_BUILD_NODE_ARCHIVE`, `AIDOT_BUILD_GO_ARCHIVE` or `AIDOT_BUILD_ISCC_ARCHIVE` at pre-downloaded files; verification still applies. `AIDOT_BUILD_GO` and `AIDOT_BUILD_ISCC` use an existing installation as-is.

Artifacts and an edition-specific manifest are copied to `dist/<version>/public/`. Installer signatures and third-party notices belong to the distribution; inspect the manifest and platform signature before rollout. A locally built unsigned installer is not presented as a signed release.

The Electron app can connect to an existing console or run the bundled server components. Its bundled console uses a loopback listener inside the desktop application. It does not install a Linux VPN gateway or configure an HA cluster. A remote HTTPS console must have a certificate trusted by the Windows account running Electron.

Native service packages use their own persistent config/data locations and a default console port of `9111`; source runs use `6193`. Provision the controller database, gateway and certificate paths for the installed service account. User settings and data should be backed up separately from program binaries.

[Source setup](getting-started.md) · [HTTPS certificates](https.md) · [Edition comparison](editions.md)
