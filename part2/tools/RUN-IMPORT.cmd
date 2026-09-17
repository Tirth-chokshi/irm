@echo off
setlocal
cd /d "%~dp0"

rem --- re-launch elevated if not already admin ------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================================
echo   Importing Sysmon events into the Windows Event Log
echo ============================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Import-SysmonToEventViewer.ps1"

echo.
echo Press any key to close this window.
pause >nul
