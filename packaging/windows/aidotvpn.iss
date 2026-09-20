#ifndef BuildVersion
 #error BuildVersion must be supplied from VERSION
#endif
[Setup]
AppId={{B48157B2-3B58-4E84-AEB3-96DFBB162DB5}
AppName=aidot-vpn Server
AppVersion={#BuildVersion}
AppPublisher=Aidot Link Co., Ltd.
DefaultDirName={autopf}\AidotVPN
UsePreviousAppDir=no
DisableDirPage=yes
DefaultGroupName=AidotVPN
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\installers
OutputBaseFilename=AidotVPN-Server-{#BuildVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupIconFile=aidotvpn.ico
UninstallDisplayIcon={app}\aidotvpn-tray.exe
[Files]
Source: "..\out\win32-x64\*.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\out\win32-x64\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\out\win32-x64\build-manifest.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\controller.env.example"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README-ko.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "install-services.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\console.env.example"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\AidotVPN"; Filename: "{app}\aidotvpn-tray.exe"
Name: "{group}\AidotVPN Settings"; Filename: "{app}\aidotvpn-tray.exe"; Parameters: "--settings"
[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AidotVPN"; ValueData: """{app}\aidotvpn-tray.exe"""; Flags: uninsdeletevalue
[Run]
Filename: "{app}\aidotvpn-tray.exe"; Description: "Start AidotVPN tray"; Flags: nowait postinstall skipifsilent runasoriginaluser
[Code]
var ServiceSetupFailed: Boolean;
function ServiceScript(ScriptFile, Extra: String): Integer;
var Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptFile + '" -InstallDir "' + ExpandConstant('{app}') + '" ' + Extra,
    ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) then Code := -1;
  Log('AidotVPN service operation: ' + Extra + '; exit code: ' + IntToStr(Code));
  Result := Code;
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if FileExists(ExpandConstant('{app}\aidotvpn-service.exe')) then begin
    { Use this release's helper so a broken older helper cannot block repair. }
    ExtractTemporaryFile('install-services.ps1');
    if ServiceScript(ExpandConstant('{tmp}\install-services.ps1'), '-StopOnly') <> 0 then
      Result := 'Could not stop AidotVPN services. Check Windows Services and retry.';
  end;
end;
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    ServiceSetupFailed := ServiceScript(ExpandConstant('{app}\install-services.ps1'), '') <> 0;
    if ServiceSetupFailed then RaiseException('AidotVPN service setup failed. Installation is incomplete. See the setup log and run the installer again as administrator.');
  end;
end;
function GetCustomSetupExitCode(): Integer;
begin
  Result := 0;
  if ServiceSetupFailed then Result := 10;
end;
function InitializeUninstall(): Boolean;
begin
  Result := ServiceScript(ExpandConstant('{app}\install-services.ps1'), '-Remove') = 0;
  if not Result then MsgBox('Could not remove AidotVPN services. Stop them in Windows Services and retry.', mbError, MB_OK);
end;
// Customer AppData and ProgramData are deliberately retained on uninstall.
