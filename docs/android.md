# Android integration

AidotVPN supports Android API 26 and newer. Build with JDK 17 and Android SDK 36 using the included Gradle wrapper.

| Module | Purpose |
| --- | --- |
| `core` | Device identity, controller communication and shared models |
| `vpnlib` | Embeddable VPN service and tunnel lifecycle |
| `sample-app` | Standalone VPN app with enrollment and settings |
| `demo-app` | Example of embedding the VPN engine in a business app |

```powershell
cd client-android
.\gradlew.bat :sample-app:assembleDebug :demo-app:assembleDebug
```

On Linux run `./gradlew` with the same tasks. Set the controller address in the app, submit an enrollment request and approve it in the console. Use a controller HTTPS endpoint trusted by the device for a real deployment; console port `6193` is not the mobile API port. Policies determine reachable destinations and per-app routing.

For a business app, depend on `core` and `vpnlib` and follow `demo-app`'s service permission, enrollment and tunnel lifecycle integration. Android grants VPN permission to the app; distributing this library does not grant Android device-owner privileges or OS-level management features.

Debug APKs are for evaluation. Configure organization-owned signing credentials for release builds, retain dependency notices and keep keystores out of Git. See the [client API](client-api.md) for enrollment and authenticated state handling.
