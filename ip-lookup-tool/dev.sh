#!/usr/bin/env bash
# IP Radar — 开发模式启动（前端热更新 + 后端 API 分离）
# 前端: http://localhost:5173（API 代理到 8000）
# 后端: http://localhost:8000

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

# 后端
echo "[Backend] Starting..."
cd backend
source .venv/bin/activate
.venv/bin/uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

sleep 2

# 前端
echo "[Frontend] Starting..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "  Backend:  http://localhost:8000  (PID $BACKEND_PID)"
echo "  Frontend: http://localhost:5173  (PID $FRONTEND_PID)"
echo "  Ctrl+C 停止全部"
echo ""

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
