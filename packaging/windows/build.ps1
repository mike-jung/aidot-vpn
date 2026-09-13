param([string]$Iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe')
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
function Invoke-Checked([string]$File, [string[]]$Arguments) {
 # Windows PowerShell 5.1 wraps redirected native stderr (including npm
 # warnings) as ErrorRecords. Use the exit code to decide native success.
 $savedPreference = $ErrorActionPreference
 try {
  $ErrorActionPreference = 'Continue'
  & $File @Arguments
  $nativeExitCode = $LASTEXITCODE
 } finally { $ErrorActionPreference = $savedPreference }
 if ($nativeExitCode -ne 0) { throw "$File failed ($nativeExitCode)" }
}
if ((& node --version) -ne 'v24.19.0') { throw 'Node 24.19.0 is required on the build machine' }
if (-not (Test-Path $Iscc)) { throw 'Install Inno Setup 6 on the build machine' }
$env:AIDOT_BUILD_NODE_LICENSE = Join-Path $root 'packaging\node-LICENSE.txt'
Invoke-Checked 'npm.cmd' @('--prefix', (Join-Path $root 'console'), 'ci')
Invoke-Checked 'npm.cmd' @('--prefix', (Join-Path $root 'packaging'), 'ci', '--ignore-scripts')
Invoke-Checked 'node' @((Join-Path $root 'packaging\build.mjs'))
Invoke-Checked 'node' @('--test', (Join-Path $root 'packaging\tests\paths.test.mjs'))
Invoke-Checked 'node' @('--test', (Join-Path $root 'console\tests\i18n.test.mjs'))
Invoke-Checked 'node' @((Join-Path $root 'packaging\tests\smoke.mjs'))
Invoke-Checked 'powershell.exe' @('-NoProfile', '-File', (Join-Path $root 'packaging\tests\windows-packaging.ps1'))
$version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
Invoke-Checked $Iscc @("/DBuildVersion=$version", (Join-Path $PSScriptRoot 'aidotvpn.iss'))
Write-Output 'Unsigned installer built. Authenticode signing and clean Windows install/upgrade/uninstall verification are release gates.'
