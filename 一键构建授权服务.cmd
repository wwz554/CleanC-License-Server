@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build-server.ps1"
set "LICENSE_BUILD_EXIT=%ERRORLEVEL%"
pause
exit /b %LICENSE_BUILD_EXIT%
