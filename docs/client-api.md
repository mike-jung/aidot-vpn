# Client API contract

These are the existing HTTP paths used by the shipped clients. Use HTTPS outside the isolated development lab. JSON field names use snake_case. An enrollment request ID and its one-time grant must be treated as credentials and must not be logged publicly.

| Step | Request | Result |
| --- | --- | --- |
| Request approval | `POST /enrollment-requests` with `password`, UUID `install_id`, `display_name`, `platform`, `device_public_key` | Request `id`, six-digit `verification_code`, expiry |
| Wait for approval | `GET /enrollment-requests/{id}/status` | Pending/rejected/approved state; approved grant is returned once |
| Request attestation challenge | `POST /devices/attestation-challenge`, Bearer enrollment grant | Challenge for supported attestation flows |
| Register | `POST /devices/register`, Bearer enrollment grant | Device, allocation and gateway endpoints |
| Read own state | `GET /devices/{id}/state`, Bearer allocation `state_token` | Current approval, routes, endpoints and policy state |

Use a UUID with at most 36 characters for `install_id`; do not append a hostname. Keep the private key on the client. `device_public_key` is the base64 WireGuard public key. The registration allocation contains the client addresses, PSK, allowed routes and state token. Store these securely.

The reference Node client tolerates 404/501 for an unsupported attestation challenge, but registration still requires an approved grant. It does not disable the server's configured attestation policy.


The concrete request/response models are in `core/Models.kt`, `EnrollmentRequestClient.kt`, `RegistrationFlow.kt` and `client-node/aidot-client.mjs`. The public contract excludes database schemas and administrator APIs.
