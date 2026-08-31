#!/bin/bash

# MT Pentester Startup Script
# Starts FastAPI backend, Streamlit frontend and docs server.
# Reproducibility policy: requirements.lock is required by default.

set -u

echo "🚀 Starting MT Pentester - AI-Driven Autonomous Red Team Operator"
echo "================================================================"

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python 3.10+ first."
    exit 1
fi

if [ ! -f "requirements.lock" ]; then
    if [ "${ALLOW_UNLOCKED_INSTALL:-false}" != "true" ]; then
        echo "❌ requirements.lock not found. Refusing a non-reproducible install."
        echo "   Set ALLOW_UNLOCKED_INSTALL=true only for an intentional development fallback."
        exit 1
    fi
    if [ ! -f "requirements.txt" ]; then
        echo "❌ requirements.txt not found either."
        exit 1
    fi
fi

if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv || exit 1
fi

source venv/bin/activate

echo "📦 Installing pinned dependencies..."
if [ -f "requirements.lock" ]; then
    python -m pip install --no-deps -r requirements.lock --quiet || exit 1
else
    echo "⚠️  Development fallback: installing unlocked requirements.txt"
    python -m pip install -r requirements.txt --quiet || exit 1
fi
python -m pip check || exit 1

if ! command -v nmap &> /dev/null; then
    echo "⚠️  Warning: Nmap is not installed. Some scan features may not work."
fi

echo "ℹ️  AI is optional at startup — configure it from Settings in the web UI."

if [ ! -f ".env" ]; then
    echo "🔧 Creating .env file..."
    cp .env.example .env 2>/dev/null || touch .env
    chmod 600 .env 2>/dev/null || true
    echo "⚠️  .env created. Configure AI and an explicit SCOPE_ALLOWLIST before use."
fi

_port_in_use() {
    if command -v ss &>/dev/null; then
        ss -tlnp | grep -q ":$1 "
    elif command -v lsof &>/dev/null; then
        lsof -Pi :"$1" -sTCP:LISTEN -t >/dev/null 2>&1
    else
        return 1
    fi
}

_find_free_port() {
    local port=$1
    while _port_in_use "$port" 2>/dev/null; do
        port=$((port + 1))
    done
    echo "$port"
}

_set_env_val() {
    local key=$1 val=$2
    sed -i "/^${key}=/d" .env 2>/dev/null
    echo "${key}=${val}" >> .env
    chmod 600 .env 2>/dev/null || true
}

BACKEND_PORT=$(grep -m1 "^BACKEND_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
BACKEND_PORT="${BACKEND_PORT:-6000}"
FRONTEND_PORT=$(grep -m1 "^FRONTEND_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
FRONTEND_PORT="${FRONTEND_PORT:-8501}"
DOCS_PORT=$(grep -m1 "^DOCS_PORT=" .env 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr -d "'" | tr -d ' ')
DOCS_PORT="${DOCS_PORT:-3500}"

if _port_in_use "$BACKEND_PORT"; then
    FREE=$(_find_free_port 6000)
    echo "ℹ️  Port $BACKEND_PORT is busy — using $FREE (existing process is left untouched)"
    _set_env_val "BACKEND_PORT" "$FREE"
    BACKEND_PORT=$FREE
fi
if _port_in_use "$FRONTEND_PORT"; then
    FREE=$(_find_free_port 8501)
    echo "ℹ️  Port $FRONTEND_PORT is busy — using $FREE (existing process is left untouched)"
    _set_env_val "FRONTEND_PORT" "$FREE"
    FRONTEND_PORT=$FREE
fi
if _port_in_use "$DOCS_PORT"; then
    FREE=$(_find_free_port 3500)
    echo "ℹ️  Port $DOCS_PORT is busy — using $FREE (existing process is left untouched)"
    _set_env_val "DOCS_PORT" "$FREE"
    DOCS_PORT=$FREE
fi

export BACKEND_PORT FRONTEND_PORT DOCS_PORT

echo "🚀 Starting services..."

BACKEND_PID=""
FRONTEND_PID=""
DOCS_PID=""
cleanup() {
    echo "🛑 Shutting down services..."
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null || true
    [ -n "$DOCS_PID" ] && kill "$DOCS_PID" 2>/dev/null || true
}
trap 'cleanup; exit 0' SIGINT SIGTERM

python3 main.py &
BACKEND_PID=$!
sleep 5

if ! curl -s "http://localhost:${BACKEND_PORT}/health" > /dev/null; then
    echo "❌ Backend failed to start"
    cleanup
    exit 1
fi

streamlit run frontend.py --server.port "$FRONTEND_PORT" --server.headless true &
FRONTEND_PID=$!
python3 docs_server.py &
DOCS_PID=$!

sleep 3

echo "✅ MT Pentester started successfully!"
echo "   Dashboard:     http://localhost:${FRONTEND_PORT}"
echo "   Documentation: http://localhost:${DOCS_PORT}"
echo "   API Docs:      http://localhost:${BACKEND_PORT}/api/docs"
echo "   Health Check:  http://localhost:${BACKEND_PORT}/health"
echo "🛑 Press Ctrl+C to stop all services"

wait "$BACKEND_PID" "$FRONTEND_PID" "$DOCS_PID"
