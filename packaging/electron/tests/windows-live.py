#!/usr/bin/env python3
"""Test packaged Electron with a disposable DB and optional isolated NSIS install.

Requires Windows, Python 3, Docker Desktop and aidot-vpn-ha-lab:1.19.0.
The installer test refuses to replace an existing AidotVPN Desktop installation.
"""
import argparse
import base64
import hashlib
import http.cookiejar
import http.server
import json
import os
import pathlib
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default=str(pathlib.Path(__file__).resolve().parents[3]))
    parser.add_argument('--work-dir', required=True)
    parser.add_argument('--installer', help='Also install, reinstall and uninstall this NSIS EXE')
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('Run on Windows')
    import winreg
    root = pathlib.Path(args.root).resolve()
    version = (root / 'VERSION').read_text().strip()
    work = pathlib.Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=False)
    built = root / 'dist' / version / 'electron'
    exe = built / 'win-unpacked' / 'AidotVPN-Desktop.exe'
    install = work / 'Install 한글' / 'AidotVPN Desktop'
    profile = work / '프로필 with spaces'
    default_profile = pathlib.Path(os.environ['APPDATA']) / 'AidotVPN Desktop'
    container = 'aidot-vpn-electron-' + secrets.token_hex(6)
    label = 'electron-' + version
    checks, children = [], []
    owned_profile = False
    installed = False
    external = None
    success = False

    def save():
        (work / 'results.json').write_text(json.dumps({
            'success': success, 'version': version, 'passed': len(checks), 'checks': checks,
            'scope': 'Real Windows Electron, bundled SEA/Go, disposable MariaDB; optional NSIS lifecycle. No visual GUI or cross-version upgrade test.'
        }, indent=2), encoding='utf-8')

    def record(name):
        checks.append(name)
        print(name, flush=True)
        save()

    def run(command, **kwargs):
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=180, **kwargs)
        if result.returncode:
            # DB passwords may appear in SQL error messages; keep subprocess output private.
            raise RuntimeError('Verification command failed: ' + pathlib.Path(command[0]).name
                               if isinstance(command, list) else 'Installer command failed')
        return result

    def wait_for(predicate, message, seconds=60):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if predicate():
                return
            time.sleep(.2)
        raise RuntimeError(message)

    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    def open_port(number):
        with socket.socket() as sock:
            sock.settimeout(.2)
            return sock.connect_ex(('127.0.0.1', number)) == 0

    def registrations():
        found = []
        for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
            for view in [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY]:
                try:
                    with winreg.OpenKey(hive, r'Software\Microsoft\Windows\CurrentVersion\Uninstall',
                                        0, winreg.KEY_READ | view) as parent:
                        for index in range(winreg.QueryInfoKey(parent)[0]):
                            with winreg.OpenKey(parent, winreg.EnumKey(parent, index), 0, winreg.KEY_READ | view) as child:
                                try:
                                    display = winreg.QueryValueEx(child, 'DisplayName')[0]
                                    if display.replace(' ', '').replace('-', '').lower().startswith('aidotvpndesktop'):
                                        # electron-builder stores the location under its app GUID,
                                        # separately from the Windows uninstall entry.
                                        try:
                                            with winreg.OpenKey(hive, r'Software\f1d0fa3a-1c4e-4a9f-99e3-9a02f035c81c',
                                                                0, winreg.KEY_READ | view) as app_key:
                                                found.append(winreg.QueryValueEx(app_key, 'InstallLocation')[0])
                                        except FileNotFoundError:
                                            found.append('')  # An orphan entry must still block installation.
                                except FileNotFoundError:
                                    pass
                except FileNotFoundError:
                    pass
        return found

    def install_once():
        # NSIS requires /D to be the final, unquoted parameter (including spaces).
        run('"' + str(pathlib.Path(args.installer).resolve()) + '" /S /currentuser /D=' + str(install))
        wait_for(lambda: (install / 'AidotVPN-Desktop.exe').exists(), 'NSIS did not install the executable')
        assert any(pathlib.Path(p).resolve() == install for p in registrations())

    def uninstall():
        uninstallers = list(install.glob('Uninstall*.exe'))
        if uninstallers:
            run([str(uninstallers[0]), '/S', '/currentuser'])
            wait_for(lambda: not (install / 'AidotVPN-Desktop.exe').exists(), 'NSIS did not remove the executable')
            wait_for(lambda: not registrations(), 'NSIS registration was not removed')
            wait_for(lambda: not any((folder / 'AidotVPN Desktop.lnk').exists() for folder in [desktop, programs]),
                     'NSIS shortcuts were not removed')

    def launch(config, name):
        config_file = work / (name + '-config.json')
        config_file.write_text(json.dumps(config), encoding='utf-8')
        output = work / (name + '-diagnostics.json')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('NODE_', 'ELECTRON_', 'AIDOTVPN_', 'CONTROLLER_'))}
        env['AIDOTVPN_DESKTOP_PROFILE'] = str(profile)
        profile.mkdir(exist_ok=True)
        with (work / (name + '-electron.log')).open('wb') as log:
            child = subprocess.Popen([str(exe), '--diagnostics', str(output), '--runtime-config', str(config_file)],
                                     cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        children.append(child)
        wait_for(lambda: output.exists() or child.poll() is not None, 'Electron did not report readiness')
        if not output.exists():
            raise RuntimeError('Electron exited without diagnostics')
        result = json.loads(output.read_text(encoding='utf-8'))
        child.shutdown_file = result.get('shutdownFile')
        return child, result

    def stop(child):
        if child.poll() is None:
            if not child.shutdown_file:
                raise RuntimeError('Electron did not provide a shutdown signal path')
            pathlib.Path(child.shutdown_file).write_text('shutdown\n', encoding='utf-8')
        assert child.wait(timeout=45) == 0

    dbport, httpport, grpcport, consoleport = [port() for _ in range(4)]
    assert len({dbport, httpport, grpcport, consoleport}) == 4
    dbpw, adminpw = secrets.token_hex(24), secrets.token_hex(24) + 'A9!'
    env_file = work / 'controller.env'
    try:
        if args.installer:
            if registrations() or default_profile.exists():
                raise RuntimeError('Existing AidotVPN Desktop installation or profile: use the unpacked test instead')
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders') as key:
                desktop = pathlib.Path(winreg.QueryValueEx(key, 'Desktop')[0])
                programs = pathlib.Path(winreg.QueryValueEx(key, 'Programs')[0])
            if any((folder / 'AidotVPN Desktop.lnk').exists() for folder in [desktop, programs]):
                raise RuntimeError('Existing AidotVPN Desktop shortcut: refusing to replace it')
            default_profile.mkdir()
            owned_profile = True
            canary = default_profile / 'desktop.json'
            canary.write_text(json.dumps({'mode': 'connect', 'locale': 'ko', 'autoStart': False}), encoding='utf-8')
            original = canary.read_bytes()
            installed = True
            install_once()
            record('NSIS per-user clean install in a Unicode path')
            assert canary.read_bytes() == original
            install_once()
            assert canary.read_bytes() == original
            record('NSIS same-version reinstall preserves desktop settings')
            exe = install / 'AidotVPN-Desktop.exe'
        run(['docker', 'run', '-d', '--name', container, '--label', 'com.aidotvpn.verification=' + label,
             '--memory', '512m', '--cpus', '1', '--tmpfs', '/var/lib/mysql:rw',
             '-p', f'127.0.0.1:{dbport}:3306', 'aidot-vpn-ha-lab:1.19.0', '-c', 'exec sleep infinity'])
        run(['docker', 'exec', container, 'bash', '-ec', 'chown mysql:mysql /var/lib/mysql /run/mysqld; mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=socket >/var/log/init.log 2>&1'])
        run(['docker', 'exec', '-d', container, 'mariadbd', '--user=mysql', '--bind-address=0.0.0.0', '--skip-name-resolve'])
        wait_for(lambda: subprocess.run(['docker', 'exec', container, 'mariadb-admin', 'ping'], capture_output=True).returncode == 0, 'Disposable database did not start')
        run(['docker', 'exec', '-i', container, 'mariadb'], input=f"CREATE DATABASE aidotvpn; CREATE USER 'aidot'@'%' IDENTIFIED BY '{dbpw}'; GRANT ALL ON aidotvpn.* TO 'aidot'@'%';")
        run(['docker', 'exec', container, 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-keyout', '/tmp/ca.key', '-out', '/tmp/ca.crt', '-days', '1', '-subj', '/CN=AidotVPN Electron verification'])
        for name in ['ca.key', 'ca.crt']:
            run(['docker', 'cp', container + ':/tmp/' + name, str(work / name)])
        values = dict(AIDOTVPN_DB_HOST='127.0.0.1', AIDOTVPN_DB_PORT=str(dbport), AIDOTVPN_DB_USER='aidot',
                      AIDOTVPN_DB_PASSWORD=dbpw, AIDOTVPN_DB_NAME='aidotvpn', AIDOTVPN_DB_TLS='disable',
                      AIDOTVPN_HA_ENABLED='false', AIDOTVPN_ADMIN_EMAIL='electron-test@aidot.invalid', AIDOTVPN_ADMIN_PASSWORD=adminpw,
                      CONTROLLER_HTTP_LISTEN='127.0.0.1:' + str(httpport), CONTROLLER_GRPC_LISTEN='127.0.0.1:' + str(grpcport),
                      AIDOTVPN_CA_CERT_FILE=str(work / 'ca.crt'), AIDOTVPN_CA_KEY_FILE=str(work / 'ca.key'),
                      SETTINGS_ENCRYPTION_KEY=base64.b64encode(secrets.token_bytes(32)).decode())
        env_file.write_text(''.join(key + '=' + value + '\n' for key, value in values.items()), encoding='utf-8')
        config = dict(mode='bundled', controllerURL=f'http://127.0.0.1:{httpport}', startController=True,
                      controllerEnv=str(env_file), localPort=consoleport, locale='ko', autoStart=False)
        child, result = launch(config, 'bundled')
        assert result['success'] and result['version'] == version and len(result['childPids']) == 2
        assert result['packaged'] and result['renderer']['sandbox']
        base = result['url']
        record('Packaged Electron launches its SEA console and Go controller against a fresh database')
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

        def request(method, path, body=None):
            data = None if body is None else json.dumps(body).encode()
            with opener.open(urllib.request.Request(base + '/api' + path, data=data, headers={'Content-Type': 'application/json'}, method=method), timeout=10) as response:
                payload = response.read()
                return json.loads(payload) if payload else None

        try:
            urllib.request.urlopen(base + '/api/ha/status', timeout=3)
            raise AssertionError('Unauthenticated request was allowed')
        except urllib.error.HTTPError as error:
            assert error.code == 401
        record('Unauthenticated HA status is rejected')
        login = request('POST', '/auth/login', {'email': 'electron-test@aidot.invalid', 'password': adminpw})
        assert login['admin']['role'] == 'admin' and any(cookie.has_nonstandard_attr('HttpOnly') for cookie in jar)
        if login['admin']['must_change_password']:
            request('POST', '/auth/password', {'current': adminpw, 'new': adminpw + 'Change1!'})
        record('Real login, HttpOnly session and required password change succeed')
        status = request('GET', '/ha/status')
        assert status['mode'] == 'standalone' and status['writes_available']
        policy = request('POST', '/policies', {'name': 'Electron 설치 검증', 'description': '한글 저장 확인'})
        assert request('GET', '/policies/' + policy['id'])['name'] == 'Electron 설치 검증'
        record('Standalone controller saves and reads Korean policy data')
        stop(child)
        wait_for(lambda: not any(open_port(number) for number in [consoleport, httpport, grpcport]), 'Owned server ports stayed open')
        record('Electron shutdown closes both owned servers and their listeners')

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ready')

            def log_message(self, *_args):
                pass

        external = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=external.serve_forever, daemon=True).start()
        external_port = external.server_port
        config['localPort'] = external_port
        child, result = launch(config, 'occupied')
        assert not result['success'] and 'already in use' in result['error']
        assert child.wait(timeout=15) == 1
        assert open_port(external_port) and not open_port(httpport)
        record('Occupied Windows loopback port is rejected without starting a controller or stopping its owner')
        child, result = launch({'mode': 'connect', 'consoleURL': f'http://127.0.0.1:{external_port}'}, 'external')
        assert result['success'] and result['childPids'] == []
        stop(child)
        with urllib.request.urlopen(f'http://127.0.0.1:{external_port}/healthz') as response:
            assert response.status == 200
        record('Existing-server mode quits while leaving the external server running')
        if installed:
            uninstall()
            installed = False
            assert canary.read_bytes() == original
            assert not any((folder / 'AidotVPN Desktop.lnk').exists() for folder in [desktop, programs])
            record('NSIS removal clears application, registration and shortcuts while preserving desktop settings')
        success = True
        save()
    finally:
        for child in reversed(children):
            if child.poll() is None:
                try:
                    stop(child)
                except (OSError, AssertionError, subprocess.TimeoutExpired):
                    child.terminate()
                    child.wait(timeout=15)
        if external:
            external.shutdown()
            external.server_close()
        if installed:
            uninstall()
        info = subprocess.run(['docker', 'inspect', container], capture_output=True, text=True)
        if info.returncode == 0 and json.loads(info.stdout)[0]['Config']['Labels'].get('com.aidotvpn.verification') == label:
            run(['docker', 'rm', '-f', container])
        for name in ['controller.env', 'ca.key', 'ca.crt']:
            (work / name).unlink(missing_ok=True)
        if owned_profile:
            (default_profile / 'desktop.json').unlink(missing_ok=True)
            if not any(default_profile.iterdir()):
                default_profile.rmdir()
        save()


if __name__ == '__main__':
    main()
