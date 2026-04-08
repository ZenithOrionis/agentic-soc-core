@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0soc.ps1" %*
exit /b %ERRORLEVEL%

