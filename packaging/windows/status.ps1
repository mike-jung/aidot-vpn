# Read-only diagnostics. No environment values, credentials or server configuration are exported.
$ErrorActionPreference='Stop'
$sourceRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$sourceVersion=(Get-Content (Join-Path $sourceRoot 'VERSION') -Raw).Trim()
$registry=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
try {$key=$registry.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion');try {$programFiles=[string]$key.GetValue('ProgramFilesDir')}finally {$key.Dispose()}}finally {$registry.Dispose()}
$installRoot=Join-Path $programFiles 'AidotVPN'
$manifestFile=Join-Path $installRoot 'build-manifest.json'
$installedVersion=$null
if(Test-Path $manifestFile){$installedVersion=(Get-Content $manifestFile -Raw | ConvertFrom-Json).version}
$running=@(Get-CimInstance Win32_Process -Filter "Name='aidotvpn-tray.exe'" | ForEach-Object {
 $version=$null
 if($_.ExecutablePath -and (Test-Path $_.ExecutablePath)){$version=[Diagnostics.FileVersionInfo]::GetVersionInfo($_.ExecutablePath).ProductVersion}
 [pscustomobject]@{pid=$_.ProcessId;executable=$_.ExecutablePath;productVersion=$version}
})
$services=@('AidotVpnConsole','AidotVpnController' | ForEach-Object {
 $service=Get-CimInstance Win32_Service -Filter ("Name='"+$_+"'")
 [pscustomobject]@{name=$_;installed=($null -ne $service);state=$service.State;startMode=$service.StartMode;executable=$service.PathName}
})
[pscustomobject]@{
 sourceVersion=$sourceVersion
 installedServiceVersion=$installedVersion
 serviceInstallDirectory=$installRoot
 sourceMatchesInstalled=($sourceVersion -eq $installedVersion)
 runningTrays=$running
 services=$services
 repairCommand='npm run dist:windows'
 note='Source updates and Electron Desktop installs do not replace this Windows service installation.'
} | ConvertTo-Json -Depth 5
