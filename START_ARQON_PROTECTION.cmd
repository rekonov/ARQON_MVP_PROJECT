@echo off
setlocal
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\run_user_console.ps1"
if not "%ERRORLEVEL%"=="0" (
  echo.
  echo ARQON monitor stopped or interrupted.
  echo If protection status was RUNNING, background protection is still active.
  pause
)
endlocal
