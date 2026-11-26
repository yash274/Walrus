@echo off
title Launch WALRUS Platform
echo Launching WALRUS - AI Agent Security & Intelligence Platform...
if exist "%~dp0dist\win-unpacked\WALRUS - AI Agent Security & Intelligence Platform.exe" (
  start "" "%~dp0dist\win-unpacked\WALRUS - AI Agent Security & Intelligence Platform.exe" %*
) else if exist "%~dp0dist\win-unpacked\AEGIS - AI Monitoring & Threat Detection.exe" (
  start "" "%~dp0dist\win-unpacked\AEGIS - AI Monitoring & Threat Detection.exe" %*
) else (
  npm start
)
