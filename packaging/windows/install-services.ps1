param([Parameter(Mandatory=$true)][string]$InstallDir, [switch]$Remove, [switch]$StopOnly, [switch]$ValidateOnly)
$ErrorActionPreference='Stop'
function Invoke-AidotServiceControl([string[]]$Arguments) {
 # Windows PowerShell 5.1 strips embedded quotes in native arguments.
 # Keep the quoted Program Files path intact in the SCM ImagePath value.
 $nativeArgs=$Arguments
 if($PSVersionTable.PSVersion.Major -le 5){$nativeArgs=@($Arguments | ForEach-Object {$_.Replace('"','\"')})}
 & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') @nativeArgs
 if($LASTEXITCODE -ne 0){throw ('Service configuration failed: '+$Arguments[0]+' '+$Arguments[1]+' (Windows error '+$LASTEXITCODE+')')}
}
# Read the machine's 64-bit installation path, independently of inherited environment variables.
$registry=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
try {$versionKey=$registry.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion');try {$programFiles=[string]$versionKey.GetValue('ProgramFilesDir')}finally {$versionKey.Dispose()}}finally {$registry.Dispose()}
if(-not $programFiles){throw 'The Windows Program Files directory could not be resolved'}
$expected=Join-Path $programFiles 'AidotVPN'
if([IO.Path]::GetFullPath($InstallDir).TrimEnd('\') -ne $expected){throw 'Services must be installed in Program Files\AidotVPN'}
if($ValidateOnly){@{installDir=$expected;serviceControlCommand=(Get-Command Invoke-AidotServiceControl).CommandType.ToString()}|ConvertTo-Json -Compress;return}
$root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'AidotVPN'
function Protect-Directory([string]$Path, [string]$Service, [switch]$Public) {
 if((Test-Path $Path) -and ((Get-Item $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Service paths cannot be reparse points'}
 New-Item -ItemType Directory -Path $Path -Force | Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
 foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
  $identity=New-Object Security.Principal.SecurityIdentifier($sid)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
 }
 if($Public){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))}
 if($Service){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("NT SERVICE\$Service",'Modify','ContainerInherit,ObjectInherit','None','Allow')))}
 Set-Acl -Path $Path -AclObject $acl
}
if(-not $Remove -and -not $StopOnly){Protect-Directory $root '' -Public}
$services=@{console='AidotVpnConsole';controller='AidotVpnController'}
foreach($component in @('console','controller')) {
 $name=$services[$component]
 $service=Get-Service -Name $name -ErrorAction SilentlyContinue
 if($service -and $service.Status -ne 'Stopped'){Stop-Service -Name $name; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
 if($StopOnly){continue}
 if($Remove){if($service){Invoke-AidotServiceControl -Arguments @('delete',$name)};continue}
 $binary='"'+(Join-Path $InstallDir 'aidotvpn-service.exe')+'" '+$component
 if($service){Invoke-AidotServiceControl -Arguments @('config',$name,'binPath=',$binary,'start=','delayed-auto','obj=',"NT SERVICE\$name")}
 else {Invoke-AidotServiceControl -Arguments @('create',$name,'binPath=',$binary,'start=','delayed-auto','obj=',"NT SERVICE\$name",'DisplayName=',"AidotVPN $component")}
 Invoke-AidotServiceControl -Arguments @('sidtype',$name,'unrestricted')
 Invoke-AidotServiceControl -Arguments @('failure',$name,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000')
 Invoke-AidotServiceControl -Arguments @('failureflag',$name,'1')
 $data=Join-Path $root $component
 Protect-Directory $data $name
 if($component -eq 'console') {
  $env:AIDOTVPN_SCOPE='system';$env:AIDOTVPN_DATA_DIR=$data;$env:AIDOTVPN_CONFIG_DIR=Join-Path $data 'config'
  & (Join-Path $InstallDir 'aidotvpn-console.exe') --init
  if($LASTEXITCODE -ne 0){throw 'Console initialization failed'}
 }
}
if(-not $Remove -and -not $StopOnly) {
 $public=Join-Path $root 'public'
 Protect-Directory $public 'AidotVpnConsole' -Public
 if(Test-Path (Join-Path $root 'controller\controller.env')){Start-Service AidotVpnController}
 Start-Service AidotVpnConsole
 (Get-Service AidotVpnConsole).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
 foreach($name in $services.Values){if(-not (Get-Service $name -ErrorAction SilentlyContinue)){throw ('Service registration did not persist: '+$name)}}
}
