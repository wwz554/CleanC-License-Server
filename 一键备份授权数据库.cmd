@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\backup-database.ps1"
set "LICENSE_BACKUP_EXIT=%ERRORLEVEL%"
pause
exit /b %LICENSE_BACKUP_EXIT%
