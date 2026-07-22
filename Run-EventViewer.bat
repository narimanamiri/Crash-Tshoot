@echo off
:: Crash-Tshoot Advanced Event Viewer
:: FullEventLogView-class: presets, filters, exports, HTML browser with bookmarks
title Crash-Tshoot Event Viewer

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
    exit /b
)

cd /d "%~dp0"

:: Prefer Python Event Viewer if available; else PowerShell engine
where python >nul 2>&1
if %errorlevel% equ 0 (
    echo Running Python Event Viewer...
    python "%~dp0run_diagnoser.py" --event-viewer --days 7 --export Csv,Json,Html,Tsv %*
    set ERR=%ERRORLEVEL%
    echo.
    pause
    exit /b %ERR%
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SystemDiagnoser.ps1" -EventViewerMode -Days 7 -Export Csv,Json,Html,Tsv %*
pause
