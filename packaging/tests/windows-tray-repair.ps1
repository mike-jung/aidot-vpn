param([Parameter(Mandatory=$true)][string]$Installer,[Parameter(Mandatory=$true)][string]$ResultDir)
$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Windows administrator elevation is required'}
New-Item -ItemType Directory -Path $ResultDir -Force | Out-Null
$checks=New-Object Collections.Generic.List[string]
$root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'AidotVPN'
$data=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'AidotVPN'
$tray=Join-Path $root 'aidotvpn-tray.exe'
function Check([bool]$Ok,[string]$Name){if(-not $Ok){throw $Name};$checks.Add($Name);[IO.File]::WriteAllText((Join-Path $ResultDir 'progress.txt'),($checks -join "`n"))}
function Setup([string]$Name){$p=Start-Process $Installer -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $ResultDir ($Name+'.log'))+'"')) -PassThru -Wait;Check ($p.ExitCode -eq 0) $Name}
function Control([string]$Action){$p=Start-Process $tray -ArgumentList $Action -Wait -PassThru;Check ($p.ExitCode -eq 0) ('tray helper '+$Action)}
function Ready(){for($i=0;$i -lt 50;$i++){try {if((Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:9111/healthz' -TimeoutSec 2).StatusCode -eq 200){return $true}}catch{};Start-Sleep -Milliseconds 200};return $false}
try {
 $env:ProgramW6432=$null
 Setup 'repair-install-without-ProgramW6432'
 $services=@(Get-CimInstance Win32_Service -Filter "Name='AidotVpnConsole' OR Name='AidotVpnController'")
 Check ($services.Count -eq 2) 'both product services are registered'
 $console=$services | Where-Object {$_.Name -eq 'AidotVpnConsole'}
 Check ($console.StartName -eq 'NT SERVICE\AidotVpnConsole') 'console runs under its virtual service account'
 Check ($console.PathName.StartsWith('"'+$root+'\aidotvpn-service.exe"')) 'SCM executable path retains Program Files quotes'
 Check (Ready) 'installed console responds on loopback'
 Check ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AidotVpnConsole').DelayedAutoStart -eq 1) 'console delayed automatic startup is configured'
 $acl=Get-Acl (Join-Path $data 'console')
 Check ($acl.AreAccessRulesProtected) 'console data ACL inheritance is protected'
 $untrustedWrite=@($acl.Access | Where-Object {($_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')) -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)})
 Check ($untrustedWrite.Count -eq 0) 'ordinary users have no service data write permission'
 $watch=[Diagnostics.Stopwatch]::StartNew();Control '--stop-server';$watch.Stop()
 Check ($watch.Elapsed.TotalSeconds -lt 12) 'tray helper completes graceful service stop within 12 seconds'
 Check ((Get-Service AidotVpnConsole).Status -eq 'Stopped' -and (Get-Service AidotVpnController).Status -eq 'Stopped') 'both services are stopped'
 $children=@(Get-CimInstance Win32_Process -Filter "Name='aidotvpn-console.exe'" | Where-Object {$_.ExecutablePath -eq (Join-Path $root 'aidotvpn-console.exe')})
 Check ($children.Count -eq 0) 'service stop leaves no console child'
 Control '--stop-server'
 Check ((Get-Service AidotVpnConsole).Status -eq 'Stopped') 'repeated stop is successful'
 Control '--start-server';Check (Ready) 'tray helper restarts the console'
 $parent=Get-CimInstance Win32_Service -Filter "Name='AidotVpnConsole'"
 $child=@(Get-CimInstance Win32_Process -Filter ("ParentProcessId="+$parent.ProcessId) | Where-Object {$_.Name -eq 'aidotvpn-console.exe'})
 Check ($child.Count -eq 1) 'service owns one scoped console child'
 Stop-Process -Id $child[0].ProcessId -Force
 Start-Sleep -Milliseconds 700
 Check (Ready) 'SCM recovers the console after its child crashes'
 $cfg=Join-Path $data 'console\config\console.json';$before=(Get-FileHash $cfg -Algorithm SHA256).Hash
 Setup 'upgrade-reinstall'
 Check ((Get-FileHash $cfg -Algorithm SHA256).Hash -eq $before) 'reinstallation preserves the exact console configuration'
 Check (Ready) 'final installed console is running'
 [IO.File]::WriteAllText((Join-Path $ResultDir 'results.json'),(@{success=$true;passed=$checks.Count;checks=$checks;scope='Real installed services and compiled tray control helper; no uninstall or reboot';stopSeconds=$watch.Elapsed.TotalSeconds}|ConvertTo-Json -Depth 6))
}catch {
 [IO.File]::WriteAllText((Join-Path $ResultDir 'results.json'),(@{success=$false;passed=$checks.Count;checks=$checks;error=$_.Exception.Message}|ConvertTo-Json -Depth 6));throw
}
