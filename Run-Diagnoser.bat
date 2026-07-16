@echo off
:: ============================================================
::  Smart System Diagnoser - one-click launcher
::  Double-click this file. It self-elevates (UAC prompt) and
::  runs SystemDiagnoser.ps1 from this same folder.
::  Extra args are passed through, e.g. Run-Diagnoser.bat -Days 30
:: ============================================================
title Crash-Tshoot Diagnoser

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SystemDiagnoser.ps1" -Days 7 %*
