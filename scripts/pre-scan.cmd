@echo off
REM Fast-Mode Pre-Scanner Launcher (Bypasses PowerShell ExecutionPolicy restrictions)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0pre-scan.ps1" %*
