@echo off
chcp 65001 >nul 2>&1
setlocal

set "PYTHON_VERSION=3.11.9"
set "PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/python-%PYTHON_VERSION%-embed-amd64.zip"
set "GETPIP_URL=https://bootstrap.pypa.io/get-pip.py"
set "PYTHON_DIR=python"
set "ZIP_FILE=python-embed.zip"

echo ========================================
echo   IP Radar - Build Script
echo ========================================
echo.

REM --- Check if python directory already exists ---
if exist "%PYTHON_DIR%\python.exe" (
    echo [OK] Embedded Python found, skipping download
    goto :install_deps
)

REM --- Download embeddable Python ---
echo [1/4] Downloading Python %PYTHON_VERSION% Embeddable Package...
curl -L -o "%ZIP_FILE%" "%PYTHON_URL%"
if errorlevel 1 (
    echo [ERROR] Failed to download Python, check network connection
    pause
    exit /b 1
)

REM --- Extract ---
echo [2/4] Extracting Python...
powershell -Command "Expand-Archive -Path '%ZIP_FILE%' -DestinationPath '%PYTHON_DIR%' -Force"
del "%ZIP_FILE%"

REM --- Enable site-packages ---
echo [3/4] Configuring Python environment...
for %%f in ("%PYTHON_DIR%\*._pth") do (
    powershell -Command "(Get-Content '%%f') -replace '#import site', 'import site' | Set-Content '%%f'"
)

REM --- Install pip ---
echo [4/4] Installing pip...
curl -L -o get-pip.py "%GETPIP_URL%"
"%PYTHON_DIR%\python.exe" get-pip.py
del get-pip.py

:install_deps
REM --- Install project dependencies ---
echo.
echo [INSTALL] Installing project dependencies...
REM First install packages with pre-built wheels
"%PYTHON_DIR%\python.exe" -m pip install fastapi uvicorn[standard] python-multipart python-dotenv cabby -q

REM pytricia: download prebuilt wheel from CI release (avoids MSVC compilation)
echo [DOWNLOAD] Fetching prebuilt pytricia wheel...
curl -fL -o pytricia.whl "https://github.com/steponeerror/ip-lookup-tool/releases/download/wheels-v1/pytricia-1.0.2-cp311-cp311-win_amd64.whl" 2>nul
if not errorlevel 1 (
    echo [OK] Installing prebuilt pytricia wheel...
    "%PYTHON_DIR%\python.exe" -m pip install pytricia.whl -q
    del pytricia.whl
    goto :build_done
)

REM pytricia: check for cached wheel first, then try compile, then fallback
if exist pytricia-*.whl (
    echo [OK] Found cached pytricia wheel, installing...
    "%PYTHON_DIR%\python.exe" -m pip install pytricia-*.whl -q
    goto :build_done
)

REM Try to compile pytricia (requires Microsoft C++ Build Tools)
"%PYTHON_DIR%\python.exe" -m pip install pytricia -q
if errorlevel 1 (
    echo.
    echo [WARNING] pytricia compilation failed ^(needs MSVC^)
    echo.
    echo ========================================
    echo   To build pytricia on Windows:
    echo   1. Install Visual Studio Build Tools:
    echo      https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo   2. During install, select "Desktop development with C++"
    echo   3. Re-run build.bat
    echo.
    echo   After successful compilation, the wheel
    echo   will be cached for future use.
    echo ========================================
) else (
    REM Compilation succeeded - save the wheel for future use
    echo [OK] Caching pytricia wheel for future builds...
    "%PYTHON_DIR%\python.exe" -m pip wheel --no-deps pytricia -q -d .
)

:build_done

echo.
echo ========================================
echo   Build complete!
echo   Run start.bat to launch the server
echo ========================================
pause
