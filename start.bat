@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM ================================
REM   IP Radar - IP Lookup Tool
REM   http://127.0.0.1:8000
REM ================================

set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"

echo ========================================
echo   IP Radar - IP Lookup Tool
echo ========================================
echo.

REM --- Check Python ---
set "PYTHON="
where python3 >nul 2>&1 && set "PYTHON=python3"
if not defined PYTHON (
    where python >nul 2>&1 && set "PYTHON=python"
)
if not defined PYTHON (
    echo [ERROR] Python not found. Please install Python 3.12+
    pause
    exit /b 1
)
echo  Python:    !PYTHON! --version

REM --- Virtual environment ---
if not exist "backend\.venv\Scripts\activate.bat" (
    echo  Venv:      Not found, creating...
    "!PYTHON!" -m venv backend\.venv
    call backend\.venv\Scripts\activate.bat
    "!PYTHON!" -m pip install -q -r backend\requirements.txt
) else (
    call backend\.venv\Scripts\activate.bat
)
echo  Venv:      %VENV%

REM --- Frontend build ---
if not exist "frontend\dist\index.html" (
    echo  Frontend:  Not built, building...
    where npm >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        cd frontend
        call npm ci --silent 2>nul
        call npm run build
        cd "%PROJECT_ROOT%"
        echo  Frontend:  Build complete
    ) else (
        echo  Frontend:  npm not found, API only mode
    )
) else (
    echo  Frontend:  Already built
)

echo.
echo  --^> http://127.0.0.1:8000
echo  Ctrl+C to stop
echo.

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
