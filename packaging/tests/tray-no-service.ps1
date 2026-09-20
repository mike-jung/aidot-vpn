param([Parameter(Mandatory=$true)][string]$Executable,[Parameter(Mandatory=$true)][string]$ResultFile)
$ErrorActionPreference='Stop'
if(Get-Service AidotVpnConsole,AidotVpnController -ErrorAction SilentlyContinue){throw 'This regression requires both AidotVPN services to be absent; it does not modify services'}
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.ServiceProcess,System.Web.Extensions
$assembly=[Reflection.Assembly]::LoadFrom($Executable)
$type=$assembly.GetType('Tray',$true)
$flags=[Reflection.BindingFlags]'Instance,NonPublic'
$context=$type.GetConstructor($flags,$null,[Type[]]@(),$null).Invoke([object[]]@())
try {
 $icon=$type.GetField('icon',$flags).GetValue($context)
 $menu=$type.GetField('menu',$flags).GetValue($context)
 $operation=$type.GetMethod('ControlServer',$flags).Invoke($context,[object[]]@($true))
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not $operation.IsCompleted -and $watch.Elapsed.TotalSeconds -lt 10){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 20}
 if(-not $operation.IsCompleted -or -not $operation.GetAwaiter().GetResult()){throw 'Tray stop failed or requested elevation despite absent services'}
 if(-not $menu.Enabled){throw 'Tray menu was left disabled after the operation'}
 # Execute the actual menu handler as well: it must not open a confirmation or UAC dialog.
 $menu.Items[$menu.Items.Count-1].PerformClick()
 $watch.Restart()
 while($icon.Visible -and $watch.Elapsed.TotalSeconds -lt 10){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 20}
 if($icon.Visible){throw 'Exit menu did not remove the notification icon'}
 [IO.File]::WriteAllText($ResultFile,(@{passed=3;checks=@('Actual WinForms async stop completes without UAC when services are absent','Menu is re-enabled after asynchronous control','Actual Exit menu handler closes the notification icon without confirmation or UAC');seconds=$watch.Elapsed.TotalSeconds;scope='Real compiled Tray.ControlServer and Exit menu handler with Windows SCM; no registered services; no UAC automation'}|ConvertTo-Json -Depth 5))
}finally {$context.Dispose()}
