param([Parameter(Mandatory=$true)][string]$Executable,[Parameter(Mandatory=$true)][string]$ResultFile)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing,System.ServiceProcess,System.Web.Extensions
$assembly=[Reflection.Assembly]::LoadFrom($Executable)
$type=$assembly.GetType('Tray',$true)
$flags=[Reflection.BindingFlags]'Instance,NonPublic'
$context=$type.GetConstructor($flags,$null,[Type[]]@(),$null).Invoke([object[]]@())
$checks=New-Object Collections.Generic.List[string]
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw $Name};$checks.Add($Name)}
try {
 $icon=$type.GetField('icon',$flags).GetValue($context)
 $menu=$type.GetField('menu',$flags).GetValue($context)
 Check ($icon.Visible) 'NotifyIcon initialized and enabled on Windows'
 Check ($icon.Icon.Handle -ne [IntPtr]::Zero) 'embedded icon loads as a native icon'
 $type.GetField('korean',$flags).SetValue($context,$false)
 $type.GetMethod('Rebuild',$flags).Invoke($context,[object[]]@()) | Out-Null
 $english=@($menu.Items | ForEach-Object {$_.Text})
 Check (($english -contains 'Open console') -and ($english -contains 'Settings') -and ($english -contains 'Exit (stop server)')) 'English console, settings and exit menu items'
 $type.GetField('korean',$flags).SetValue($context,$true)
 $type.GetMethod('Rebuild',$flags).Invoke($context,[object[]]@()) | Out-Null
 $korean=@($menu.Items | ForEach-Object {$_.Text})
 Check (($korean -contains ([string][char]0xC124+[char]0xC815)) -and $menu.Items.Count -eq 8) 'Korean menu rebuild retains all eight entries'
 $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Executable).ProductVersion
 Check ($version -match '^\d+\.\d+\.\d+$' -and $menu.Items[0].Text -eq ('aidot-vpn '+$version)) 'menu identifies the actual compiled product version'
 $menu.Show(100,100);[Windows.Forms.Application]::DoEvents()
 Check ($menu.Visible) 'native popup menu opens'
 $menu.Close();[Windows.Forms.Application]::DoEvents()
 Check (-not $menu.Visible) 'native popup menu closes'
 $context.ExitThread();[Windows.Forms.Application]::DoEvents()
 Check (-not $icon.Visible) 'tray exit removes its notification icon'
 [IO.File]::WriteAllText($ResultFile,(@{passed=$checks.Count;checks=$checks;success=$true;scope='Compiled WinForms runtime; user clicks, browser launch and elevated service control are separate tests'}|ConvertTo-Json -Depth 5))
} finally {$context.Dispose()}
