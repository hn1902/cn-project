@echo off
echo ==========================================
echo Starting Secure Messaging Stack...
echo ==========================================

start "Relay Server" cmd /k "python server/server.py"
timeout /t 2
start "Bridge Gateway" cmd /k "python bridge/bridge.py"
timeout /t 2
cd frontend
start "Frontend UI" cmd /k "npm run dev"

echo ==========================================
echo All services started!
echo 1. Relay: localhost:9999
echo 2. Bridge: localhost:8000
echo 3. Frontend: http://localhost:5173
echo ==========================================
pause
