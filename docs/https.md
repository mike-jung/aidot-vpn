# Console HTTPS

From the project root, run:

```bash
npm run https:cert
npm run check:https
npm run start:https
```

`npm run cert:https` is an alias for `https:cert`, matching the certificate command naming used in aidot-express. Go must be available (`go version`; recommended Go 1.27.1). OpenSSL is not required for certificate generation.

The command generates a private root CA and a server certificate, then updates only `CONSOLE_HTTPS_ENABLED`, `CONSOLE_PUBLIC_URL`, `CONSOLE_TLS_CERT_FILE` and `CONSOLE_TLS_KEY_FILE` in `.env`. Existing unrelated values and comments are preserved. An existing `.env` is backed up inside the private certificate directory before a change. The root CA is valid for five years and server certificates for 365 days by default.

Generated bundles are stored in `.local/https/` beside the selected env file. Private files are restricted to the creating account and SYSTEM on Windows, or owner access on Unix. Run the console as that account. Installed services running under another account need explicitly provisioned certificate files and read permissions.

## Addresses and renewal

The default URL is `https://localhost:6193`, or the configured console port. Certificates include `localhost`, `127.0.0.1`, `::1` and the hostname in the requested URL.

For access from another computer, use the server's real DNS name or LAN IP:

```bash
npm run https:cert -- --url https://vpn.example.internal:6193 --host 192.168.1.20 --renew
```

Set `CONSOLE_BIND_HOST=0.0.0.0` in `.env` only when LAN access is intended, and allow the console TCP port in the host firewall. The URL and `--host` options add certificate names; they do not change network binding or firewall rules. Set `CONSOLE_PORT` before choosing a different URL port.

Running the command again reuses a valid matching certificate. `--renew` creates a new leaf certificate and key under the same CA. The old bundle remains available for rollback. Restart the console after renewal. To replace an expired CA, select a **new empty** `--out-dir` and explicitly trust the new CA on the client computers.

Other options:

```bash
npm run https:cert -- --env-file config/console.env --out-dir certificates --days 90
npm run https:cert -- --help
```

`--out-dir` is relative to the selected env file unless absolute. When using a non-default env file for startup, also set `AIDOTVPN_CONSOLE_ENV_FILE` to that file. Existing process environment variables take precedence over env files; conflicting TLS overrides must be cleared before generation can update `.env`.

## Trust the private CA

Generation does not modify any trust store. A browser warning is expected until the generated CA is explicitly trusted. Only share `ca-cert.pem`; keep `ca-key.pem` and `privkey.pem` private.

The generator prints `caFile` and `caFingerprint`. Inspect the certificate and compare that fingerprint before importing it. On Windows PowerShell, an operator can import the local CA into the **current user's** root store:

```powershell
$meta = Get-Content .local/https/current.json | ConvertFrom-Json
$caFile = Join-Path (Join-Path .local/https $meta.bundle) 'ca-cert.pem'
certutil -dump $caFile
Import-Certificate -FilePath $caFile -CertStoreLocation Cert:\CurrentUser\Root
```

For a custom env/output directory, use the printed `caFile` path instead. Import on every client that should trust this CA; restart the browser if needed. Some browsers use a separate certificate store. Use the organization's managed trust deployment for a fleet. [Microsoft Import-Certificate documentation](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate).

Do not disable certificate verification. Company-issued or publicly trusted certificates can be used by setting the following values directly:

```dotenv
CONSOLE_HTTPS_ENABLED=true
CONSOLE_PUBLIC_URL=https://vpn.example.com:6193
CONSOLE_TLS_CERT_FILE="D:/Aidot VPN/certificates/fullchain.pem"
CONSOLE_TLS_KEY_FILE="D:/Aidot VPN/certificates/privkey.pem"
```

Source runs accept full OS paths or paths relative to the selected `.env` file, independent of the terminal's working directory. A Windows path such as `D:cert.pem` is drive-relative and is rejected. Installed service configuration continues to require absolute paths.

## Troubleshooting

| Error | Action |
| --- | --- |
| `certificate_paths_missing` | Configure both files, or run `npm run https:cert` |
| `certificate_paths_must_be_absolute` | Use a full OS path or a valid source-relative path; avoid `D:cert.pem` |
| `certificate_file_not_found` | Check the resolved paths and whether the project was moved |
| `certificate_file_not_readable` | Check that both files are regular files readable by the console account |
| `certificate_hostname_mismatch` | Match `CONSOLE_PUBLIC_URL` to a certificate SAN, or renew with `--url`/`--host` |
| `certificate_or_key_invalid` | Use a valid PEM certificate chain and its matching private key |
| `certificate_expired_or_not_yet_valid` | Check the clock and renew the certificate |
| Browser certificate warning | Explicitly trust the intended CA or use a certificate from an already trusted issuer |

An empty certificate setting previously reported `certificate_paths_must_be_absolute`. Missing paths now have their own error and generation command guidance. `check:https` validates files, validity dates, hostname and key matching without starting the database or changing browser trust.

This setup protects the browser-to-console connection. It does not automatically enable TLS on the controller's mobile API, replace the device enrollment CA or configure WireGuard.
