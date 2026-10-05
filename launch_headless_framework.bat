@echo off
REM ==============================================================================
REM launch_headless_framework.bat
REM Wrapper to execute launch_headless_framework.ps1 with Bypass execution policy
REM ==============================================================================

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0launch_headless_framework.ps1" %*
