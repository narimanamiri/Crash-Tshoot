@echo off
:: Cross-platform Python diagnoser (Windows launcher)
title Crash-Tshoot Python
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo Python not found on PATH. Install Python 3.10+ and retry.
    pause
    exit /b 1
)

:: Pass-through args. Examples:
::   Run-Python-Diagnoser.bat
::   Run-Python-Diagnoser.bat --llm
::   Run-Python-Diagnoser.bat --days 14 --log-folder D:\logs
python "%~dp0run_diagnoser.py" %*
set ERR=%ERRORLEVEL%
echo.
pause
exit /b %ERR%
