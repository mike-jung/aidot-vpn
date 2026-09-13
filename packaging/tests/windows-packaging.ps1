param([string]$Root=(Split-Path (Split-Path $PSScriptRoot -Parent) -Parent))
$ErrorActionPreference='Stop'
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('Aidot packaging '+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$savedProgramW6432=$env:ProgramW6432
try {
 $csc=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
 $exe=Join-Path $scratch 'service-control-tests.exe'
 & $csc /nologo /target:exe /platform:x64 /r:System.ServiceProcess.dll ('/out:'+$exe) (Join-Path $Root 'packaging\windows\ServiceControl.cs') (Join-Path $Root 'packaging\tests\ServiceControlTests.cs')
 if($LASTEXITCODE -ne 0){throw 'Service control test compilation failed'}
 & $exe
 if($LASTEXITCODE -ne 0){throw 'Service control regressions failed'}
 $env:ProgramW6432=$null
 $reg=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
 try {$key=$reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion');try {$install=Join-Path ([string]$key.GetValue('ProgramFilesDir')) 'AidotVPN'}finally {$key.Dispose()}}finally {$reg.Dispose()}
 $raw=& powershell.exe -NoProfile -NonInteractive -File (Join-Path $Root 'packaging\windows\install-services.ps1') -InstallDir $install -ValidateOnly
 if($LASTEXITCODE -ne 0){throw 'Installer path validation failed without ProgramW6432'}
 $result=$raw|ConvertFrom-Json
 if($result.serviceControlCommand -ne 'Function' -or $result.installDir -ne $install){throw 'Service helper name or directory resolution is incorrect'}
 Write-Output 'Installer path and command resolution: passed with ProgramW6432 absent and default sc alias retained'
} finally {$env:ProgramW6432=$savedProgramW6432;Remove-Item -LiteralPath $scratch -Recurse -Force}
