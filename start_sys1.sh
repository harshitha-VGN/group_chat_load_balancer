#!/usr/bin/env bash
# Script for Sys 1: Starts Central DB Service & Dynamic Load Balancer
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=================================================="
echo " Starting System 1 (Load Balancer & Central DB)"
echo "=================================================="

# Stop any previous instances
pkill -f "db_service.py" || true
pkill -f "./lb" || true

# 1. Start Central DB Service on port 5001
echo "[1/2] Launching Central DB Service on port 5001..."
export DB_PORT=5001
nohup python3 db_service.py > db_service.log 2>&1 &
sleep 2

# Verify DB Service
if curl -s http://127.0.0.1:5001/health | grep -q "ok"; then
    echo "  -> Central DB Service is RUNNING on port 5001 (OK)"
else
    echo "  -> [ERROR] Central DB failed to start. Check db_service.log"
    exit 1
fi

# 2. Build and run Dynamic Load Balancer
echo "[2/2] Building and launching Dynamic Load Balancer on port 8080..."
go build -o lb lb.go

# Backend addresses: configure with IPs or hostnames of Sys2, Sys3, Sys4
BACKENDS="${BACKENDS:-http://10.1.75.79:2246,http://10.1.75.79:2247,http://10.1.75.79:2248}"
# Note: If running on internal ports on each system (port 5000):
# Replace with internal IPs or hostnames e.g., http://stu42_sys2:5000,http://stu42_sys3:5000,http://stu42_sys4:5000

echo "Configured Backends: $BACKENDS"
nohup ./lb -backends "$BACKENDS" -port 8080 -threshold 8 > lb.log 2>&1 &
sleep 2

if ps aux | grep -v grep | grep -q "./lb"; then
    echo "  -> Dynamic Load Balancer is RUNNING on port 8080 (OK)"
    echo "=================================================="
    echo " System 1 Ready! URL: http://<SYS1_IP>:8080"
    echo "=================================================="
else
    echo "  -> [ERROR] Load Balancer failed to start. Check lb.log"
    exit 1
fi
