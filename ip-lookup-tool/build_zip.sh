#!/usr/bin/env bash
# 打包 Windows 分发包 — 解压即用（含 Portable Python + 依赖 + 数据 + 前端）
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
ZIP_NAME="IPRadar-Windows.zip"

PYTHON_VERSION="3.11.9"
PYTHON_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-embed-amd64.zip"
GETPIP_URL="https://bootstrap.pypa.io/get-pip.py"

RELEASE_DIR="$PROJECT_ROOT/release"

echo "═══════════════════════════════════════════"
echo "  IP Radar — Windows 分发包构建"
echo "═══════════════════════════════════════════"

# 1. 构建前端
echo ""
echo "[1/5] 构建前端..."
cd "$PROJECT_ROOT/frontend"
npm ci --silent 2>/dev/null || true
npm run build
echo "  → frontend/dist/ 构建完成"

# 2. 同步后端代码
echo ""
echo "[2/5] 同步后端代码..."
cd "$PROJECT_ROOT"
rm -rf "$RELEASE_DIR/app/ipdb"
cp -r backend/ipdb "$RELEASE_DIR/app/ipdb"
cp backend/main.py "$RELEASE_DIR/app/main.py"
find "$RELEASE_DIR/app" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
echo "  → app/ 同步完成"

# 3. 同步前端静态文件
echo ""
echo "[3/5] 同步前端静态文件..."
rm -rf "$RELEASE_DIR/static/"*
cp -r frontend/dist/* "$RELEASE_DIR/static/"
echo "  → static/ 同步完成"

# 4. 同步数据文件
echo ""
echo "[4/5] 同步数据文件..."
rm -rf "$RELEASE_DIR/data"
cp -r backend/data "$RELEASE_DIR/data"
find "$RELEASE_DIR/data" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
echo "  → data/ 同步完成"

# 5. 下载 Portable Python + 安装依赖
echo ""
echo "[5/5] 下载 Portable Python + 安装依赖..."
PYTHON_DIR="$RELEASE_DIR/python"

if [ -f "$PYTHON_DIR/python.exe" ]; then
    echo "  Python 已存在，跳过下载"
else
    echo "  下载 Python ${PYTHON_VERSION} embeddable..."
    curl -L -o /tmp/python-embed.zip "$PYTHON_URL"
    mkdir -p "$PYTHON_DIR"
    unzip -q -o /tmp/python-embed.zip -d "$PYTHON_DIR"
    rm /tmp/python-embed.zip

    # 启用 site-packages（改 ._pth 文件）
    for pth in "$PYTHON_DIR"/*._pth; do
        if [ -f "$pth" ]; then
            sed -i 's/#import site/import site/' "$pth"
        fi
    done
    echo "  Python 解压 + 配置完成"
fi

# 安装 pip（如果还没有）
if [ ! -f "$PYTHON_DIR/Scripts/pip.exe" ]; then
    echo "  安装 pip..."
    curl -L -o /tmp/get-pip.py "$GETPIP_URL"
    "$PYTHON_DIR/python.exe" /tmp/get-pip.py
    rm /tmp/get-pip.py
fi

# 安装项目依赖
echo "  安装项目依赖..."
"$PYTHON_DIR/python.exe" -m pip install -q -r "$RELEASE_DIR/requirements.txt"

# 拷贝 .env（如果有）
if [ -f "$PROJECT_ROOT/backend/.env" ]; then
    cp "$PROJECT_ROOT/backend/.env" "$RELEASE_DIR/.env"
    echo "  .env 配置已包含"
fi

# 打包 zip
echo ""
echo "═══════════════════════════════════════════"
echo "  打包 $ZIP_NAME ..."
rm -f "$PROJECT_ROOT/$ZIP_NAME"

cd "$RELEASE_DIR"
python3 -c "
import zipfile, os

with zipfile.ZipFile('../$ZIP_NAME', 'w', zipfile.ZIP_DEFLATED) as zf:
    for f in ['start.bat', 'build.bat', 'requirements.txt', '.env']:
        p = os.path.join('.', f)
        if os.path.exists(p):
            zf.write(p, f)

    # app/
    for root, dirs, files in os.walk('app'):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            full = os.path.join(root, f)
            zf.write(full, full)

    # python/
    for root, dirs, files in os.walk('python'):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            full = os.path.join(root, f)
            zf.write(full, full)

    # static/
    for root, dirs, files in os.walk('static'):
        for f in files:
            full = os.path.join(root, f)
            zf.write(full, full)

    # data/
    for root, dirs, files in os.walk('data'):
        dirs[:] = [d for d in dirs if d != '__pycache__']
        for f in files:
            full = os.path.join(root, f)
            zf.write(full, full)
"

cd "$PROJECT_ROOT"
echo ""
echo "  ✅ 打包完成: $(ls -lh "$ZIP_NAME" | awk '{print $5}')"
echo "  📦 $ZIP_NAME"
echo ""
echo "═══════════════════════════════════════════"
echo "  使用方式:"
echo "  1. 解压 $ZIP_NAME 到任意目录"
echo "  2. 双击 start.bat 启动"
echo "  3. 浏览器打开 http://127.0.0.1:8000"
echo "═══════════════════════════════════════════"
