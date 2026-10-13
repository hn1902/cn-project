#!/bin/sh
set -e

echo "=== Starting Selective E2E Encrypted Messaging Stack ==="
export RELAY_HOST=${RELAY_HOST:-"127.0.0.1"}
export RELAY_PORT=${RELAY_PORT:-"9999"}
export BRIDGE_PORT=${PORT:-${BRIDGE_PORT:-"8000"}}

echo "1. Launching TCP Relay Server on ${RELAY_HOST}:${RELAY_PORT}..."
python server/server.py &
RELAY_PID=$!

# Wait for relay server to start listening
sleep 2

echo "2. Launching FastAPI WebSocket Bridge on 0.0.0.0:${BRIDGE_PORT}..."
python -m uvicorn bridge.bridge:app --host 0.0.0.0 --port ${BRIDGE_PORT} &
BRIDGE_PID=$!

trap "kill $RELAY_PID $BRIDGE_PID" SIGINT SIGTERM

echo "Stack is running! Bridge listening on port ${BRIDGE_PORT}."
wait $BRIDGE_PID
