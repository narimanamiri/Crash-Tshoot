@echo off
:: ============================================================
::  Crash-Tshoot — Advanced Event Viewer mode
::  Full channel Critical/Error scan + Event Browser HTML + CSV/JSON export.
:: ============================================================
title Crash-Tshoot Event Viewer

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%*'"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SystemDiagnoser.ps1" -EventViewerMode -Days 7 %*
