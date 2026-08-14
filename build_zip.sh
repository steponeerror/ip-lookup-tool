#!/usr/bin/env bash
# 打包 Windows 分发包 — 含代码 + 前端 + 数据。
# Python 运行时与依赖不在本机安装/打包，统一由 build.bat 在 Windows 端首次运行时安装。
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
ZIP_NAME="IPRadar-Windows.zip"

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
mkdir -p "$RELEASE_DIR/app"
rm -rf "$RELEASE_DIR/app/ipdb" "$RELEASE_DIR/python"
cp -r backend/ipdb "$RELEASE_DIR/app/ipdb"
cp backend/main.py "$RELEASE_DIR/app/main.py"
find "$RELEASE_DIR/app" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
echo "  → app/ 同步完成"

# 3. 同步前端静态文件
echo ""
echo "[3/5] 同步前端静态文件..."
mkdir -p "$RELEASE_DIR/static"
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

# 5. Python + 依赖：不在本机安装，由 build.bat 在 Windows 端首次运行时安装
echo ""
echo "[5/5] Python + 依赖：不在本机安装，由 build.bat 在 Windows 端首次运行时安装"
echo "  → 依赖（lmdb 有官方 wheel、纯 Python 扩展）build.bat 直接 pip install，无需预编译 wheel"

# requirements.txt（build.bat / 用户参考用）
echo "fastapi>=0.115.0
uvicorn[standard]>=0.34.0
lmdb>=2.3.0
python-multipart>=0.0.20
python-dotenv>=1.1.0
cabby>=0.1.0" > "$RELEASE_DIR/requirements.txt"

# 拷贝 .env 到 app/（_registry.py 用 _app_dir/.env 加载，发布布局下 _app_dir=app/）
if [ -f "$PROJECT_ROOT/backend/.env" ]; then
    rm -f "$RELEASE_DIR/.env"
    cp "$PROJECT_ROOT/backend/.env" "$RELEASE_DIR/app/.env"
    echo "  .env 配置已包含 (app/.env)"
fi

# 打包 zip
echo ""
echo "═══════════════════════════════════════════"
echo "  打包 $ZIP_NAME ..."
rm -f "$PROJECT_ROOT/$ZIP_NAME"

cd "$RELEASE_DIR"
python3 -c "
import zipfile, os

def write_bat(zf, name):
    \"\"\"Write a .bat file with CRLF line endings.\"\"\"
    p = os.path.join('.', name)
    if os.path.exists(p):
        with open(p, 'rb') as f:
            data = f.read()
        # Normalize to CRLF
        data = data.replace(b'\\r\\n', b'\\n').replace(b'\\n', b'\\r\\n')
        zf.writestr(name, data)

with zipfile.ZipFile('../$ZIP_NAME', 'w', zipfile.ZIP_DEFLATED) as zf:
    for f in ['start.bat', 'build.bat']:
        write_bat(zf, f)
    for f in ['requirements.txt']:
        p = os.path.join('.', f)
        if os.path.exists(p):
            zf.write(p, f)

    # app/
    for root, dirs, files in os.walk('app'):
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
echo "  2. 双击 build.bat 安装 Python + 依赖（仅首次）"
echo "  3. 双击 start.bat 启动"
echo "  4. 浏览器打开 http://127.0.0.1:8000"
echo "═══════════════════════════════════════════"
