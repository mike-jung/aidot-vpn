param([string]$Iscc = '')
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
# The Node the installer embeds is downloaded and checksum-verified by packaging/node-runtime.mjs.
# This machine only needs a Node new enough to run the build scripts, so check the floor from engines.node.
$minimumNode = ((Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).engines.node) -replace '^>=\s*',''
$foundNode = ((& node --version) -replace '^v','')
if ([version]$foundNode -lt [version]$minimumNode) { throw "These build scripts need Node $minimumNode or newer; 'node --version' reports v$foundNode. / 빌드 스크립트 실행에는 Node $minimumNode 이상이 필요합니다." }
# The Inno Setup compiler is pinned like every other build tool: packaging/resolve-tool.mjs downloads
# the release named in packaging/build-tools.json, verifies its SHA-256 and unpacks a portable copy
# under packaging/.build-tools. Pass -Iscc, or set AIDOT_BUILD_ISCC, to use an existing installation.
if (-not $Iscc) {
 $isccPathFile = Join-Path $root 'packaging\.build-tools\iscc-path.txt'
 Invoke-Checked 'node' @((Join-Path $root 'packaging\resolve-tool.mjs'), 'iscc', '--out', $isccPathFile)
 $Iscc = (Get-Content $isccPathFile -Raw).Trim()
}
if (-not (Test-Path $Iscc)) { throw "The Inno Setup compiler was not found at $Iscc" }
Invoke-Checked 'npm.cmd' @('--prefix', (Join-Path $root 'console'), 'ci')
Invoke-Checked 'npm.cmd' @('--prefix', (Join-Path $root 'packaging'), 'ci', '--ignore-scripts')
Invoke-Checked 'node' @((Join-Path $root 'packaging\build.mjs'))
Invoke-Checked 'node' @('--test', (Join-Path $root 'packaging\tests\paths.test.mjs'))
Invoke-Checked 'node' @('--test', (Join-Path $root 'packaging\tests\node-runtime.test.mjs'))
Invoke-Checked 'node' @('--test', (Join-Path $root 'packaging\tests\build-tools.test.mjs'))
Invoke-Checked 'node' @('--test', (Join-Path $root 'console\tests\i18n.test.mjs'))
Invoke-Checked 'node' @((Join-Path $root 'packaging\tests\smoke.mjs'))
Invoke-Checked 'powershell.exe' @('-NoProfile', '-File', (Join-Path $root 'packaging\tests\windows-packaging.ps1'))
$version = (Get-Content (Join-Path $root 'VERSION') -Raw).Trim()
Invoke-Checked $Iscc @("/DBuildVersion=$version", (Join-Path $PSScriptRoot 'aidotvpn.iss'))
Write-Output 'Unsigned installer built. Authenticode signing and clean Windows install/upgrade/uninstall verification are release gates.'
