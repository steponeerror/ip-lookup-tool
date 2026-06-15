@echo off
chcp 65001 >nul 2>&1
setlocal

set "PYTHON_VERSION=3.11.9"
set "PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-embed-amd64.zip"
set "GETPIP_URL=https://bootstrap.pypa.io/get-pip.py"
set "PYTHON_DIR=python"
set "ZIP_FILE=python-embed.zip"

echo ========================================
echo   IP Radar - 构建脚本
echo ========================================
echo.

REM --- 检查 python 目录是否已存在 ---
if exist "%PYTHON_DIR%\python.exe" (
    echo [OK] 已检测到内嵌 Python，跳过下载
    goto :install_deps
)

REM --- 下载 embeddable Python ---
echo [1/4] 下载 Python %PYTHON_VERSION% Embeddable Package...
curl -L -o "%ZIP_FILE%" "%PYTHON_URL%"
if errorlevel 1 (
    echo [错误] 下载 Python 失败，请检查网络连接
    pause
    exit /b 1
)

REM --- 解压 ---
echo [2/4] 解压 Python...
powershell -Command "Expand-Archive -Path '%ZIP_FILE%' -DestinationPath '%PYTHON_DIR%' -Force"
del "%ZIP_FILE%"

REM --- 启用 site-packages ---
echo [3/4] 配置 Python 环境...
for %%f in ("%PYTHON_DIR%\*._pth") do (
    powershell -Command "(Get-Content '%%f') -replace '#import site', 'import site' | Set-Content '%%f'"
)

REM --- 安装 pip ---
echo [4/4] 安装 pip...
curl -L -o get-pip.py "%GETPIP_URL%"
"%PYTHON_DIR%\python.exe" get-pip.py
del get-pip.py

:install_deps
REM --- 安装项目依赖 ---
echo.
echo [安装] 正在安装项目依赖...
REM 先安装有 wheel 的包（fastapi/uvicorn 等）
"%PYTHON_DIR%\python.exe" -m pip install fastapi uvicorn[standard] python-multipart python-dotenv cabby -q
REM 再编译 pytricia（需要 C 编译器，Microsoft C++ Build Tools）
"%PYTHON_DIR%\python.exe" -m pip install pytricia -q
if errorlevel 1 (
    echo.
    echo [警告] pytricia 编译失败，尝试预编译 wheel...
    REM 检查是否有提前下载好的 sdist
    if exist pytricia-*.tar.gz (
        "%PYTHON_DIR%\python.exe" -m pip install pytricia-*.tar.gz -q
    ) else (
        echo [错误] pytricia 安装失败，需要 Microsoft C++ Build Tools
        echo 下载: https://visualstudio.microsoft.com/visual-cpp-build-tools/
    )
)

echo.
echo ========================================
echo   构建完成！
echo   双击 start.bat 启动服务
echo ========================================
pause
