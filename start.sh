#!/usr/bin/env bash
# IP Radar — IP Lookup Tool 启动脚本
# Usage: ./start.sh [--dev]

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

# ── 颜色 ──
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${GREEN}  IP Radar — IP Lookup Tool${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

# ── 检查 Python ──
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo -e "${YELLOW}Error: Python not found. Install Python 3.12+${NC}"
    exit 1
fi
echo -e "  Python:    $($PYTHON --version 2>&1)"

# ── 虚拟环境 ──
VENV="$PROJECT_ROOT/backend/.venv"
if [ ! -f "$VENV/bin/activate" ]; then
    echo -e "  Venv:      ${YELLOW}not found, creating...${NC}"
    $PYTHON -m venv "$VENV"
    source "$VENV/bin/activate"
    pip install -q -r "$PROJECT_ROOT/backend/requirements.txt"
    echo -e "  Venv:      ${GREEN}ready${NC}"
else
    source "$VENV/bin/activate"
    echo -e "  Venv:      ${GREEN}ready${NC}"
fi

# ── 前端构建 ──
if [ ! -d "$PROJECT_ROOT/frontend/dist" ]; then
    echo -e "  Frontend:  ${YELLOW}not built, building...${NC}"
    if command -v npm &>/dev/null; then
        cd "$PROJECT_ROOT/frontend"
        npm ci --silent 2>/dev/null
        npm run build
        cd "$PROJECT_ROOT"
        echo -e "  Frontend:  ${GREEN}built${NC}"
    else
        echo -e "  Frontend:  ${YELLOW}npm not found, API only${NC}"
    fi
else
    echo -e "  Frontend:  ${GREEN}built${NC}"
fi

# ── 环境变量 ──
if [ -f "$PROJECT_ROOT/backend/.env" ]; then
    set -a; source "$PROJECT_ROOT/backend/.env"; set +a
fi

# ── 启动 ──
echo ""
echo -e "${GREEN}  → http://127.0.0.1:8000${NC}"
echo -e "    API docs: http://127.0.0.1:8000/docs"
echo -e "    Ctrl+C 停止"
echo ""

cd "$PROJECT_ROOT/backend"
WORKERS="$("$VENV/bin/python" -m ipdb._batch_pool n-workers)"
exec "$VENV/bin/uvicorn" main:app --host 127.0.0.1 --port 8000 --workers "$WORKERS"
