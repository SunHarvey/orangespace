@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0Uninstall.ps1"
set "OrangeExit=%ERRORLEVEL%"
if not "%OrangeExit%"=="0" pause
exit /b %OrangeExit%
