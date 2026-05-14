import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from client.client import SecureClient

app = FastAPI()

# Allow CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "Bridge is running", "ports": {"relay": 9999, "websocket": 8000}}

# Active clients: websocket_id -> SecureClient
# For simplicity, we'll use a local SecureClient instance per WebSocket connection.
class BridgeConnection:
    def __init__(self, username: str, websocket: WebSocket):
        self.username = username
        self.websocket = websocket
        self.client = SecureClient(username=username, keys_dir=f"keys/{username}")
        self.task = None

    async def start(self):
        # 1. Setup keys (both RSA and X25519)
        self.client.setup_keys()
        
        # 2. Connect to the TCP server (localhost:9999)
        await self.client.connect()
        await self.client.register()
        
        self.client._loop = asyncio.get_running_loop()
        
        # Start background receive task
        self.task = asyncio.create_task(self.receive_handler())

    async def receive_handler(self):
        """Modified receive loop: listens to TCP and pushes to WebSocket."""
        while True:
            try:
                raw = await self.client.reader.readline()
                if not raw:
                    print(f"[BRIDGE] TCP for {self.username} closed.")
                    break
                
                frame = json.loads(raw.decode("utf-8"))
                ftype = frame.get("type", "")
                
                # If it's a delivery, we need to handle decryption first
                if ftype == "DELIVER":
                    from_user = frame.get("from", "?")
                    message = frame.get("message", {})
                    asyncio.create_task(self._handle_delivery(from_user, message, frame.get("timestamp")))
                
                elif ftype == "USER_LIST":
                    await self.websocket.send_json({
                        "type": "USER_LIST",
                        "users": frame.get("users", [])
                    })
                
                elif ftype == "ACK":
                    await self.websocket.send_json({
                        "type": "ACK",
                        "info": frame.get("info", "")
                    })
                
                elif ftype == "ERROR":
                    await self.websocket.send_json({
                        "type": "ERROR",
                        "message": frame.get("info", "")
                    })
                
                elif ftype == "KEY_RESPONSE":
                    uname = frame["username"]
                    from crypto.keys import deserialize_public_key, deserialize_x25519_public
                    rsa_pub = deserialize_public_key(frame["public_key_pem"].encode())
                    x25519_pub = None
                    x25519_pem = frame.get("x25519_public_key_pem", "")
                    if x25519_pem:
                        x25519_pub = deserialize_x25519_public(x25519_pem.encode())
                    self.client._key_cache[uname] = {
                        "rsa": rsa_pub,
                        "x25519": x25519_pub,
                    }
                    fut = self.client._pending_key_requests.pop(uname, None)
                    if fut and not fut.done():
                        fut.set_result(self.client._key_cache[uname])

            except Exception as e:
                print(f"[BRIDGE] Error in recv for {self.username}: {e}")
                break

    async def _handle_delivery(self, from_user: str, message: dict, timestamp: str = None):
        """Async delivery handler: fetches key, decrypts, and pushes to WebSocket."""
        try:
            keys = await self.client.fetch_public_key(from_user)
            sender_rsa_pub = keys["rsa"]
            
            from client.message_reader import read_encrypted_message
            from cryptography.exceptions import InvalidSignature
            
            plaintext = read_encrypted_message(
                message=message,
                receiver_private_key=self.client.x25519_private,  # X25519 for DH
                sender_public_key=sender_rsa_pub,                  # RSA for sig verify
            )
            # Push to WS
            await self.websocket.send_json({
                "type": "MESSAGE",
                "from": from_user,
                "content": plaintext,
                "timestamp": timestamp or ""
            })
        except Exception as e:
            print(f"[BRIDGE] Decryption error for {self.username}: {e}")
            await self.websocket.send_json({
                "type": "ERROR",
                "message": f"Couldn't decrypt message from {from_user}: {str(e)}"
            })

    async def send_message(self, recipient: str, text: str):
        # Delegate to SecureClient logic
        await self.client.send_message(recipient, text)

    async def list_users(self):
        await self.client.list_users()

    async def stop(self):
        if self.task:
            self.task.cancel()
        if self.client.writer:
            self.client.writer.close()

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    await websocket.accept()
    conn = BridgeConnection(username, websocket)
    try:
        await conn.start()
        await websocket.send_json({"type": "STATUS", "message": f"Connected as {username}"})
        
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            
            ctype = cmd.get("type")
            if ctype == "SEND":
                await conn.send_message(cmd["to"], cmd["text"])
            elif ctype == "LIST":
                await conn.list_users()
            
    except WebSocketDisconnect:
        print(f"[BRIDGE] WS closed for {username}")
    except Exception as e:
        print(f"[BRIDGE] Error: {e}")
    finally:
        await conn.stop()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
