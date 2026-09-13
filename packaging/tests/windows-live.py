#!/usr/bin/env python3
"""Exercise native Windows binaries against a disposable, labeled MariaDB.
Does not install services or touch Program Files/ProgramData.
"""
import argparse,pathlib,os,subprocess,socket,time,secrets,json,urllib.request,urllib.error,http.cookiejar,shutil

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--root',default=str(pathlib.Path(__file__).resolve().parents[2]));ap.add_argument('--work-dir',required=True);a=ap.parse_args()
 if os.name!='nt':raise RuntimeError('Run on Windows')
 root=pathlib.Path(a.root);work=pathlib.Path(a.work_dir);work.mkdir(parents=True,exist_ok=False)
 binaries=root/'packaging/out/win32-x64';container='aidot-vpn-win1190-'+secrets.token_hex(4);label='com.aidotvpn.verification=windows-1.19.0'
 def run(cmd,**kw):return subprocess.run(cmd,check=True,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90,**kw)
 def port():
  with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
 dbport,httpport,grpcport,consoleport=[port() for _ in range(4)]
 pw=secrets.token_hex(24);adminpw=secrets.token_hex(24)+'N9!';children=[];checks=[]
 def record(name):checks.append(name);print(name,flush=True)
 def wait_ready(url):
  for _ in range(100):
   try:
    with urllib.request.urlopen(url,timeout=1) as r:
     if r.status==200:return
   except (OSError,urllib.error.URLError):pass
   time.sleep(.2)
  raise RuntimeError('Native executable did not become ready')
 env={k:v for k,v in os.environ.items() if not k.startswith(('AIDOTVPN_','CONTROLLER_')) and k!='SETTINGS_ENCRYPTION_KEY'}
 env.update(AIDOTVPN_DB_HOST='127.0.0.1',AIDOTVPN_DB_PORT=str(dbport),AIDOTVPN_DB_USER='aidot',AIDOTVPN_DB_PASSWORD=pw,AIDOTVPN_DB_NAME='aidotvpn',AIDOTVPN_DB_TLS='disable',AIDOTVPN_HA_ENABLED='false',AIDOTVPN_ADMIN_EMAIL='windows-test@aidot.invalid',AIDOTVPN_ADMIN_PASSWORD=adminpw,CONTROLLER_HTTP_LISTEN='127.0.0.1:'+str(httpport),CONTROLLER_GRPC_LISTEN='127.0.0.1:'+str(grpcport))
 try:
  run(['docker','run','-d','--name',container,'--label',label,'--memory','512m','--cpus','1','--tmpfs','/var/lib/mysql:rw','-p',f'127.0.0.1:{dbport}:3306','aidot-vpn-ha-lab:1.19.0','-c','exec sleep infinity'])
  run(['docker','exec',container,'bash','-ec','chown mysql:mysql /var/lib/mysql /run/mysqld; mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=socket >/var/log/init.log 2>&1'])
  run(['docker','exec','-d',container,'mariadbd','--user=mysql','--bind-address=0.0.0.0','--skip-name-resolve'])
  for _ in range(60):
   if subprocess.run(['docker','exec',container,'mariadb-admin','ping'],capture_output=True).returncode==0:break
   time.sleep(.2)
  else:raise RuntimeError('Isolated database did not start')
  run(['docker','exec','-i',container,'mariadb'],input=f"CREATE DATABASE aidotvpn; CREATE USER 'aidot'@'%' IDENTIFIED BY '{pw}'; GRANT ALL ON aidotvpn.* TO 'aidot'@'%';")
  migration=run([str(binaries/'aidotvpn-migrate.exe'),'up'],cwd=work,env=env);assert '37' in migration.stdout;record('Native Windows migration reaches schema 37')
  with (work/'controller.log').open('w') as log:
   p=subprocess.Popen([str(binaries/'aidotvpn-controller.exe')],cwd=work,env=env,stdout=log,stderr=subprocess.STDOUT);children.append(p)
  wait_ready(f'http://127.0.0.1:{httpport}/readyz');record('Native Windows controller is ready')
  consoleenv=dict(env,AIDOTVPN_DATA_DIR=str(work/'console'),AIDOTVPN_CONFIG_DIR=str(work/'console/config'),AIDOTVPN_SCOPE='user')
  run([str(binaries/'aidotvpn-console.exe'),'--init'],env=consoleenv,cwd=work)
  cfgfile=work/'console/config/console.json';cfg=json.loads(cfgfile.read_text());cfg.update(port=consoleport,controllerURL=f'http://127.0.0.1:{httpport}');cfgfile.write_text(json.dumps(cfg))
  with (work/'console.log').open('w') as log:
   p=subprocess.Popen([str(binaries/'aidotvpn-console.exe')],cwd=work,env=consoleenv,stdout=log,stderr=subprocess.STDOUT);children.append(p)
  base=f'http://127.0.0.1:{consoleport}';wait_ready(base+'/healthz');record('SEA console runs with real controller')
  jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
  def req(method,path,body=None):
   r=opener.open(urllib.request.Request(base+'/api'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'},method=method),timeout=10)
   body=r.read()
   return json.loads(body) if body else None
  try:urllib.request.urlopen(base+'/api/ha/status',timeout=3);raise AssertionError('Unauthenticated HA access')
  except urllib.error.HTTPError as e:assert e.code==401
  record('Real controller rejects unauthenticated HA status')
  login=req('POST','/auth/login',{'email':'windows-test@aidot.invalid','password':adminpw});assert login['admin']['role']=='admin' and any(c.has_nonstandard_attr('HttpOnly') for c in jar);record('Native binary login and HttpOnly session proxy succeed')
  if login['admin']['must_change_password']:req('POST','/auth/password',{'current':adminpw,'new':adminpw+'Change1!'})
  status=req('GET','/ha/status');assert status['mode']=='standalone' and status['writes_available'];record('Standalone mode permits writes without an HA replica')
  policy=req('POST','/policies',{'name':'Windows 실제 검증','description':'한글 저장 확인'});fetched=req('GET','/policies/'+policy['id']);assert fetched['name']=='Windows 실제 검증';record('Korean policy is saved and read through real Windows binaries')
  html=urllib.request.urlopen(base+'/ha').read().decode();assert '<html' in html;record('Embedded HA SPA deep link is served')
  (work/'results.json').write_text(json.dumps({'success':True,'passed':len(checks),'checks':checks,'scope':'Native Windows SEA and Go executables, real disposable MariaDB, no service installation'},indent=2))
 finally:
  for p in reversed(children):
   if p.poll() is None:p.terminate();p.wait(timeout=15)
  info=subprocess.run(['docker','inspect',container],capture_output=True,text=True)
  if info.returncode==0 and json.loads(info.stdout)[0]['Config']['Labels'].get('com.aidotvpn.verification')=='windows-1.19.0':subprocess.run(['docker','rm','-f',container],capture_output=True,check=True)
if __name__=='__main__':main()
