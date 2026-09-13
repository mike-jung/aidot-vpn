# AidotVPN Server

Configure the controller database and persistent device CA before enabling the service. The default installed console address is http://localhost:9111. The source launcher uses port 6193.

Set CONSOLE_HTTPS_ENABLED=true, CONSOLE_PUBLIC_URL and absolute CONSOLE_TLS_CERT_FILE / CONSOLE_TLS_KEY_FILE paths in console.env to use HTTPS. The service account must be able to read the certificate and private key. Trust your private CA explicitly on the client computer.

Keep customer configuration, database backups and private keys separate from program files. See the online Public README and docs/installation.md for supported build and deployment options.

Public is licensed under Apache-2.0. HA and coordinated cluster operations require the separately supplied Enterprise edition. Contact mike.jung.global@gmail.com.
