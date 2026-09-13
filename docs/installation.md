# Installation and builds

Use the source quick start for evaluation, or build a platform installer on its native operating system. All public installer commands use the Public source snapshot. Full/Enterprise builds have explicit `:full` commands and remain internal.

| Command | Host and prerequisites | Result |
| --- | --- | --- |
| `npm run dist:win` | Windows x64, Node 24.19.0, Go 1.27.1, .NET Framework C# compiler | Electron + NSIS desktop installer |
| `npm run dist:windows` | Windows x64, the same toolchain and Inno Setup 6 | Native Windows service installer |
| `npm run dist:linux` | Debian/Ubuntu x64, Node 24.19.0, Go 1.27.1, Python 3 and dpkg-deb | Native server `.deb` |

Artifacts and an edition-specific manifest are copied to `dist/<version>/public/`. Installer signatures and third-party notices belong to the distribution; inspect the manifest and platform signature before rollout. A locally built unsigned installer is not presented as a signed release.

The Electron app can connect to an existing console or run the bundled server components. Its bundled console uses a loopback listener inside the desktop application. It does not install a Linux VPN gateway or configure an HA cluster. A remote HTTPS console must have a certificate trusted by the Windows account running Electron.

Native service packages use their own persistent config/data locations and a default console port of `9111`; source runs use `6193`. Provision the controller database, gateway and certificate paths for the installed service account. User settings and data should be backed up separately from program binaries.

[Source setup](getting-started.md) · [HTTPS certificates](https.md) · [Edition comparison](editions.md)
