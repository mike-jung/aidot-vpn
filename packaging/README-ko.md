# AidotVPN Server

> Windows 트레이 버전 확인: `npm run status:windows`. 소스 ZIP과 Electron Desktop 설치는 기존 Windows 서비스 설치본을 갱신하지 않습니다. 서비스 설치본은 `npm run dist:windows`로 만들고, 구버전이 설치된 PC에서 새 EXE를 실행하세요. 트레이 메뉴 첫 항목에서 실제 실행 버전·경로·서비스 상태를 확인할 수 있습니다. 1.20.4는 서비스가 없거나 중지돼 있으면 바로 종료하며 실제 권한 부족일 때만 UAC를 요청합니다.


Configure the controller database and persistent device CA before enabling the service. The default installed console address is http://localhost:9111. The source launcher uses port 6193.

Set CONSOLE_HTTPS_ENABLED=true, CONSOLE_PUBLIC_URL and absolute CONSOLE_TLS_CERT_FILE / CONSOLE_TLS_KEY_FILE paths in console.env to use HTTPS. The service account must be able to read the certificate and private key. Trust your private CA explicitly on the client computer.

Keep customer configuration, database backups and private keys separate from program files. See the online Public README and docs/installation.md for supported build and deployment options.

Public is licensed under Apache-2.0. HA and coordinated cluster operations require the separately supplied Enterprise edition. Contact mike.jung.global@gmail.com.
