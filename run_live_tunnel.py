"""
run_live_tunnel.py — Start local stack and publish to public internet via Cloudflare Tunnel.
Zero signups, zero credit cards required.
"""
import subprocess
import sys
import time
import re
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    cloudflared = root / "cloudflared.exe"
    if not cloudflared.exists():
        cloudflared = Path(sys.prefix) / "cloudflared.exe"

    print("=" * 65)
    print("  Launching CN-Secure Stack + Cloudflare Public Internet Tunnel")
    print("=" * 65)

    # 1. Start Relay
    print("[1/3] Starting TCP Relay Server (port 9999)...")
    relay_proc = subprocess.Popen([sys.executable, str(root / "server" / "server.py")])
    time.sleep(1.5)

    # 2. Start Bridge + Web UI
    print("[2/3] Starting FastAPI Bridge + UI (port 8000)...")
    bridge_proc = subprocess.Popen([sys.executable, str(root / "bridge" / "bridge.py")])
    time.sleep(2)

    # 3. Start Cloudflare Tunnel
    print("[3/3] Requesting secure public internet tunnel...")
    cf_proc = subprocess.Popen(
        [str(cloudflared), "tunnel", "--url", "http://127.0.0.1:8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    public_url = None
    try:
        for line in cf_proc.stdout:
            match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
            if match:
                public_url = match.group(0)
                print("\n" + "=" * 65)
                print("  🎉 APP IS LIVE WORLDWIDE ON THE PUBLIC INTERNET!")
                print(f"  Public URL: {public_url}")
                print("=" * 65 + "\n")
                break

        # Keep running
        cf_proc.wait()
    except KeyboardInterrupt:
        print("\nStopping services...")
    finally:
        cf_proc.terminate()
        bridge_proc.terminate()
        relay_proc.terminate()
        print("Done.")

if __name__ == "__main__":
    main()
