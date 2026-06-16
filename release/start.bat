@echo off
chcp 65001 >nul 2>&1
setlocal

REM Check if Python is installed
if not exist "python\python.exe" (
    echo Please run build.bat first to set up the environment
    pause
    exit /b 1
)

REM Set data and static directories
set "IP_RADAR_DATA_DIR=%~dp0data"
set "IP_RADAR_STATIC_DIR=%~dp0static"

REM Add current directory to Python path so uvicorn can find app.main and ipdb
set "PYTHONPATH=%~dp0;%PYTHONPATH%"

echo ========================================
echo   IP Radar - IP Lookup Tool
echo   http://127.0.0.1:8000
echo ========================================
echo.
echo Press Ctrl+C to stop
echo.

python\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
