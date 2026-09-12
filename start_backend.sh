#!/usr/bin/env bash
# Script for Backend Systems (Sys 2, Sys 3, Sys 4)
# Usage: ./start_backend.sh <SYS1_IP_OR_HOSTNAME> [PORT]
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

SYS1_HOST="${1:-127.0.0.1}"
BACKEND_PORT="${2:-5000}"

echo "=================================================="
echo " Starting Backend Server on port $BACKEND_PORT"
echo " Connecting to Central DB at: http://$SYS1_HOST:5001"
echo "=================================================="

# Stop any previous backend instances
pkill -f "server.py" || true

# Set environment
export PORT="$BACKEND_PORT"
export CENTRAL_DB_URL="http://$SYS1_HOST:5001"

nohup python3 server.py > server.log 2>&1 &
sleep 2

if curl -s "http://127.0.0.1:$BACKEND_PORT/health" | grep -q "ok"; then
    echo "  -> Backend Server is RUNNING on port $BACKEND_PORT (OK)"
    echo "=================================================="
else
    echo "  -> [ERROR] Backend Server failed to start. Check server.log"
    exit 1
fi
