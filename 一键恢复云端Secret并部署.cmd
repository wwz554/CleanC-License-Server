@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\deploy-server.ps1" -RestoreSecrets
set "LICENSE_RESTORE_EXIT=%ERRORLEVEL%"
pause
exit /b %LICENSE_RESTORE_EXIT%
