@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM ═══════════════════════════════════════
REM   IP Radar — IP Lookup Tool 启动脚本
REM   访问 http://127.0.0.1:8000
REM ═══════════════════════════════════════

set "PROJECT_ROOT=%~dp0"
cd /d "%PROJECT_ROOT%"

echo ========================================
echo   IP Radar — IP Lookup Tool
echo ========================================
echo.

REM ── 检查 Python ──
set "PYTHON="
where python3 >nul 2>&1 && set "PYTHON=python3"
if not defined PYTHON (
    where python >nul 2>&1 && set "PYTHON=python"
)
if not defined PYTHON (
    echo [错误] 未找到 Python。请安装 Python 3.12+
    pause
    exit /b 1
)
echo  Python:    !PYTHON! --version

REM ── 虚拟环境 ──
if not exist "backend\.venv\Scripts\activate.bat" (
    echo  Venv:      未找到，正在创建...
    "%PYTHON%" -m venv backend\.venv
    call backend\.venv\Scripts\activate.bat
    "%PYTHON%" -m pip install -q -r backend\requirements.txt
) else (
    call backend\.venv\Scripts\activate.bat
)
echo  Venv:      %VENV%

REM ── 前端构建 ──
if not exist "frontend\dist\index.html" (
    echo  Frontend:  未构建，正在构建...
    where npm >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        cd frontend
        call npm ci --silent 2>nul
        call npm run build
        cd "%PROJECT_ROOT%"
        echo  Frontend:  构建完成
    ) else (
        echo  Frontend:  未安装 npm，仅启动 API
    )
) else (
    echo  Frontend:  已构建
)

echo.
echo  → http://127.0.0.1:8000
echo  Ctrl+C 停止
echo.

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
