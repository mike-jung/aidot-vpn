@echo off
setlocal
if not defined LOCALAPPDATA exit /b 1
set "AIDOTVPN_ENV_FILE=%LOCALAPPDATA%\AidotVPN\config\controller.env"
if not exist "%AIDOTVPN_ENV_FILE%" (
 echo Configure controller.env in the AidotVPN config folder first.
 pause
 exit /b 1
)
cd /d "%LOCALAPPDATA%\AidotVPN" || exit /b 1
"%~dp0aidotvpn-controller.exe"
exit /b %errorlevel%
