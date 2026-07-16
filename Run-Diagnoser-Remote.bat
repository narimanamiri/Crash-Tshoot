@echo off
:: ============================================================
::  Crash-Tshoot — Remote SSH diagnosis
::  Prompts for host and user, then runs the collector over OpenSSH.
:: ============================================================
title Crash-Tshoot Remote

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set /p HOST=Remote computer name or IP: 
if "%HOST%"=="" (
    echo No host entered.
    pause
    exit /b 1
)
set /p USER=SSH username [%USERNAME%]: 
if "%USER%"=="" set USER=%USERNAME%
set /p DAYS=Days to scan [7]: 
if "%DAYS%"=="" set DAYS=7

echo.
echo Scanning %USER%@%HOST% (last %DAYS% days)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0SystemDiagnoser.ps1" -ComputerName "%HOST%" -SshUser "%USER%" -Days %DAYS%
