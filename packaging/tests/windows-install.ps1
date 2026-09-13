# Destructive to the AidotVPN installation on a test PC only. Customer data is retained.
param([Parameter(Mandatory=$true)][string]$Installer,[Parameter(Mandatory=$true)][string]$ResultDir,[switch]$TestMachine)
$ErrorActionPreference='Stop'
if(-not $TestMachine){throw 'Use only on an isolated test PC and pass -TestMachine'}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Windows administrator elevation is required'}
New-Item -ItemType Directory -Path $ResultDir -Force | Out-Null
$checks=New-Object Collections.Generic.List[string]
$program=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'AidotVPN'
$data=Join-Path $env:ProgramData 'AidotVPN\console'
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw $Name};$checks.Add($Name);[IO.File]::WriteAllText((Join-Path $ResultDir 'service-progress.txt'),($checks -join "`n"))}
function Setup([string]$Name){$p=Start-Process -FilePath $Installer -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $ResultDir ($Name+'.log'))+'"')) -PassThru -Wait;Check ($p.ExitCode -eq 0) $Name}
function Health(){(Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:9111/healthz' -TimeoutSec 5).StatusCode -eq 200}
try {
 Setup 'fresh-install'
 $service=Get-CimInstance Win32_Service -Filter "Name='AidotVpnConsole'"
 Check ($service.State -eq 'Running') 'console service running'
 Check ($service.StartName -eq 'NT SERVICE\AidotVpnConsole') 'dedicated virtual service account'
 Check ($service.PathName.StartsWith('"'+$program+'\aidotvpn-service.exe"')) 'quoted Program Files service executable'
 Check (Health) 'installed console HTTP health'
 Check ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AidotVpnConsole').DelayedAutoStart -eq 1) 'delayed automatic start'
 Check ((Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run').AidotVPN -eq ('"'+$program+'\aidotvpn-tray.exe"')) 'tray starts at user login'
 $acl=Get-Acl $data
 Check ($acl.AreAccessRulesProtected) 'service data ACL inheritance disabled'
 $usersWrite=@($acl.Access | Where-Object { $_.IdentityReference.Value -match 'Users|Everyone|Authenticated Users' -and ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) })
 Check ($usersWrite.Count -eq 0) 'ordinary users cannot write service data'
 $watch=[Diagnostics.Stopwatch]::StartNew();Stop-Service AidotVpnConsole;(Get-Service AidotVpnConsole).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30));$watch.Stop()
 Check ($watch.Elapsed.TotalSeconds -lt 12) 'graceful stdin stop within 12 seconds'
 Start-Service AidotVpnConsole
 $ready=$false;for($i=0;$i -lt 30;$i++){try {if(Health){$ready=$true;break}}catch{};Start-Sleep -Milliseconds 200}
 Check $ready 'service restarts'
 $parent=Get-CimInstance Win32_Service -Filter "Name='AidotVpnConsole'"
 $child=Get-CimInstance Win32_Process -Filter ("ParentProcessId="+$parent.ProcessId) | Where-Object {$_.Name -eq 'aidotvpn-console.exe'}
 Check (@($child).Count -eq 1) 'service owns exactly scoped console child'
 Stop-Process -Id $child.ProcessId -Force
 $recovered=$false
 for($i=0;$i -lt 30;$i++){Start-Sleep -Milliseconds 500;try {if(Health){$recovered=$true;break}}catch{}}
 Check $recovered 'SCM recovers after child crash'
 $file=Join-Path $data 'config\console.json';$cfg=Get-Content $file -Raw|ConvertFrom-Json
 $cfg | Add-Member -NotePropertyName verificationMarker -NotePropertyValue 'preserve-1180' -Force
 [IO.File]::WriteAllText($file,($cfg|ConvertTo-Json -Depth 8))
 Setup 'upgrade-reinstall'
 Check ((Get-Content $file -Raw|ConvertFrom-Json).verificationMarker -eq 'preserve-1180') 'configuration preserved on reinstall'
 $u=Start-Process -FilePath (Join-Path $program 'unins000.exe') -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $ResultDir 'uninstall.log')+'"')) -Wait -PassThru
 Check ($u.ExitCode -eq 0) 'uninstaller succeeds'
 Check (-not (Get-Service AidotVpnConsole -ErrorAction SilentlyContinue)) 'uninstaller removes services'
 Check (Test-Path $file) 'uninstaller retains customer configuration'
 Setup 'final-reinstall';Check (Health) 'final installation is running'
 $cfg=Get-Content $file -Raw|ConvertFrom-Json;$cfg.PSObject.Properties.Remove('verificationMarker');[IO.File]::WriteAllText($file,($cfg|ConvertTo-Json -Depth 8))
 [IO.File]::WriteAllText((Join-Path $ResultDir 'service-results.json'),(@{passed=$checks.Count;checks=$checks;success=$true}|ConvertTo-Json -Depth 8))
} catch {
 [IO.File]::WriteAllText((Join-Path $ResultDir 'service-results.json'),(@{passed=$checks.Count;checks=$checks;success=$false;error=$_.Exception.Message}|ConvertTo-Json -Depth 8))
 throw
}
