@echo off
chcp 65001 >nul 2>&1
setlocal

REM 检查是否已构建
if not exist "python\python.exe" (
    echo 请先运行 build.bat 构建环境
    pause
    exit /b 1
)

REM 设置数据目录和静态文件目录
set "IP_RADAR_DATA_DIR=%~dp0data"
set "IP_RADAR_STATIC_DIR=%~dp0static"

echo ========================================
echo   IP Radar — IP Lookup Tool
echo   http://127.0.0.1:8000
echo ========================================
echo.
echo 按 Ctrl+C 停止服务
echo.

python\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
pause
