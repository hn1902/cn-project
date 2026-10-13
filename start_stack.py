"""
start_stack.py — Cross-platform orchestrator for local running and testing.
Runs:
1. TCP Relay Server (server/server.py on port 9999)
2. FastAPI Bridge + Web UI (bridge/bridge.py on port 8000)
"""
import subprocess
import sys
import time
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    print("=" * 60)
    print(" Starting CN Secure Messaging Stack")
    print("=" * 60)

    # 1. Start Relay Server
    print("[1/2] Starting Relay Server (TCP 9999)...")
    relay_proc = subprocess.Popen([sys.executable, str(root / "server" / "server.py")])
    time.sleep(1.5)

    # 2. Start Bridge Gateway
    print("[2/2] Starting Bridge & Web UI Server (HTTP/WS 8000)...")
    bridge_proc = subprocess.Popen([sys.executable, str(root / "bridge" / "bridge.py")])
    time.sleep(1.5)

    print("\n" + "=" * 60)
    print(" All services are LIVE!")
    print(" Web UI & WebSocket:  http://localhost:8000")
    print(" TCP Relay Server:    localhost:9999")
    print("=" * 60)
    print(" Press Ctrl+C to terminate all services.\n")

    try:
        bridge_proc.wait()
    except KeyboardInterrupt:
        print("\nStopping services...")
    finally:
        bridge_proc.terminate()
        relay_proc.terminate()
        try:
            relay_proc.wait(timeout=3)
            bridge_proc.wait(timeout=3)
        except Exception:
            relay_proc.kill()
            bridge_proc.kill()
        print("All services stopped.")

if __name__ == "__main__":
    main()
