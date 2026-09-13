#!/usr/bin/env python3
"""Build a Debian service package from a verified native Linux build."""
from pathlib import Path
import hashlib,json,shutil,subprocess,tempfile
here=Path(__file__).resolve().parent
root=here.parent.parent
src=here.parent/'out/linux-x64'
m=json.loads((src/'build-manifest.json').read_text())
assert m['platform']=='linux' and m['arch']=='x64'
for name,sha in m['hashes'].items():
 assert hashlib.sha256((src/name).read_bytes()).hexdigest()==sha, name
out=here.parent/'installers';out.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='aidotvpn-deb-') as tmp:
 stage=Path(tmp);deb=stage/'DEBIAN';deb.mkdir()
 dst=stage/'opt/aidotvpn';shutil.copytree(src,dst)
 units=stage/'lib/systemd/system';units.mkdir(parents=True)
 for f in here.glob('*.service'):shutil.copy2(f,units/f.name)
 docs=stage/'usr/share/doc/aidotvpn-server';docs.mkdir(parents=True)
 shutil.copy2(here.parent/'controller.env.example',docs/'controller.env.example')
 shutil.copy2(here.parent/'console.env.example',docs/'console.env.example')
 shutil.copy2(here.parent/'README-ko.md',docs/'README-ko.md')
 (deb/'control').write_text(f'''Package: aidotvpn-server
Version: {m['version']}
Architecture: amd64
Maintainer: AidotVPN Release Engineering
Depends: libc6 (>= 2.28), libstdc++6, ca-certificates, adduser, systemd, wireguard-tools, nftables, iproute2
Section: net
Priority: optional
Description: AidotVPN controller, console and Linux policy agent
 Compiled distribution. Existing MariaDB and explicit gateway provisioning required.
''')
 (deb/'postinst').write_text('''#!/bin/sh
set -eu
if [ "$1" = configure ]; then
 getent passwd aidotvpn >/dev/null || adduser --system --group --home /var/lib/aidotvpn --no-create-home aidotvpn
 install -d -m 0750 -o root -g aidotvpn /etc/aidotvpn
 install -d -m 0700 -o aidotvpn -g aidotvpn /var/lib/aidotvpn
 if [ ! -e /etc/aidotvpn/console.json ]; then
  AIDOTVPN_SCOPE=system /opt/aidotvpn/aidotvpn-console --init
  chown root:aidotvpn /etc/aidotvpn/console.json
  chmod 0640 /etc/aidotvpn/console.json
 fi
 chown -R aidotvpn:aidotvpn /var/lib/aidotvpn
 if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
 echo 'Configure /etc/aidotvpn before enabling services. Existing data is preserved.'
fi
''')
 (deb/'prerm').write_text('''#!/bin/sh
set -eu
case "$1" in
 remove|upgrade|deconfigure)
 if [ -d /run/systemd/system ]; then
  for service in aidotvpn-console aidotvpn-controller aidotvpn-gateway; do
   systemctl stop "$service.service" || true
  done
 fi;;
esac
''')
 (deb/'postrm').write_text('''#!/bin/sh
set -eu
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
# Deliberately retain customer config, database, keys and backups even on purge.
''')
 for f in deb.iterdir(): f.chmod(0o755 if f.name!='control' else 0o644)
 dest=out/f'aidotvpn-server_{m["version"]}_amd64.deb'
 subprocess.run(['dpkg-deb','--root-owner-group','-Zxz','--build',str(stage),str(dest)],check=True)
 print(dest)
