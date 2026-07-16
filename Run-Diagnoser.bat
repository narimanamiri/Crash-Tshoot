@echo off
:: ============================================================
::  Smart System Diagnoser - one-click launcher
::  Double-click this file. It self-elevates (UAC prompt) and
::  runs SystemDiagnoser.ps1 from this same folder.
:: ============================================================
title Smart System Diagnoser

:: --- Re-launch elevated if not already running as admin ---
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: --- Running elevated: invoke the PowerShell engine ---
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SystemDiagnoser.ps1" -Days 7
