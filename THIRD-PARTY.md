# Third-party components

AidotVPN dependencies retain their own licenses. The project's Apache-2.0 license does not relicense third-party code.

| Component | Where it is used | License information |
| --- | --- | --- |
| WireGuard Android tunnel library | Android VPN integration | Upstream Apache-2.0 notices |
| Go, Go dependencies | Controller, relay and gateway | Go LICENSE and each module's LICENSE/COPYING/NOTICE |
| Node.js, Vue, Vite, Express and dependencies | Console and build tooling | Node LICENSE and npm package notices |
| Electron and electron-builder | Windows desktop installer | Bundled Electron notices and package licenses |
| Gradle wrapper | Android build | Wrapper distribution and upstream notices |
| MariaDB, Linux, WireGuard tools, nftables | Database and Linux gateway | Each distribution/component's license and source obligations |

Native server builds write `THIRD-PARTY-NOTICES.txt` alongside the binaries. Electron distributions also carry their runtime notices. Preserve these files when redistributing an installer. Container images and operating-system packages have additional component notices and corresponding-source requirements; review the components actually shipped in your distribution.

The source repository references dependencies through package manifests and lockfiles. It does not claim that all dependencies share one license or that a package manifest is a complete binary SBOM.
