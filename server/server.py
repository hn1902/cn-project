"""
server/server.py — Asyncio TCP server (port 9999).

The server is INTENTIONALLY UNTRUSTED:
  - It stores only usernames and public keys (PEM strings).
  - It routes encrypted message blobs without touching components or keys.
  - It never decrypts anything.

Protocol: newline-delimited JSON frames.

Client → Server frames:
  {"type": "REGISTER",    "username": ..., "public_key_pem": ...}
  {"type": "SEND",        "to": ..., "message": {...}}
  {"type": "GET_KEY",     "username": ...}
  {"type": "LIST_USERS"}

Server → Client frames:
  {"type": "ACK",          "info": ...}
  {"type": "ERROR",        "info": ...}
  {"type": "KEY_RESPONSE", "username": ..., "public_key_pem": ...}
  {"type": "DELIVER",      "from": ..., "message": {...}}
  {"type": "USER_LIST",    "users": [...]}
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.store import UserStore

HOST = os.environ.get("RELAY_HOST", "0.0.0.0")
PORT = int(os.environ.get("RELAY_PORT", 9999))

store = UserStore()

# maps username → asyncio StreamWriter (so server can push DELIVER frames)
_writers: dict[str, asyncio.StreamWriter] = {}
_writers_lock = asyncio.Lock()


async def send_frame(writer: asyncio.StreamWriter, frame: dict):
    """Serialize *frame* to JSON and write it as a newline-terminated line."""
    data = json.dumps(frame, separators=(",", ":")) + "\n"
    writer.write(data.encode("utf-8"))
    await writer.drain()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    print(f"[SERVER] New connection from {peer}")
    username: str | None = None

    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break  # client disconnected

            try:
                frame = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                await send_frame(writer, {"type": "ERROR", "info": "Invalid JSON"})
                continue

            ftype = frame.get("type", "")

            # ── REGISTER ─────────────────────────────────────────────────────
            if ftype == "REGISTER":
                uname = frame.get("username", "").strip()
                pub_pem = frame.get("public_key_pem", "")
                x25519_pub_pem = frame.get("x25519_public_key_pem", "")
                if not uname or not pub_pem:
                    await send_frame(writer, {"type": "ERROR", "info": "Missing fields"})
                    continue

                ok = await store.register(uname, pub_pem, x25519_pub_pem)
                if ok:
                    username = uname
                    async with _writers_lock:
                        _writers[username] = writer
                    print(f"[SERVER] Registered user '{username}'")
                    await send_frame(writer, {"type": "ACK", "info": f"Registered as '{username}'"})
                else:
                    await send_frame(writer, {"type": "ERROR", "info": f"Username '{uname}' already taken"})

            # ── GET_KEY ───────────────────────────────────────────────────────
            elif ftype == "GET_KEY":
                target = frame.get("username", "")
                pub_pem = await store.get_public_key(target)
                x25519_pub_pem = await store.get_x25519_public_key(target)
                if pub_pem:
                    await send_frame(writer, {
                        "type": "KEY_RESPONSE",
                        "username": target,
                        "public_key_pem": pub_pem,
                        "x25519_public_key_pem": x25519_pub_pem or "",
                    })
                else:
                    await send_frame(writer, {"type": "ERROR", "info": f"User '{target}' not found"})

            # ── LIST_USERS ────────────────────────────────────────────────────
            elif ftype == "LIST_USERS":
                users = await store.list_users()
                await send_frame(writer, {"type": "USER_LIST", "users": users})

            # ── SEND ──────────────────────────────────────────────────────────
            elif ftype == "SEND":
                if not username:
                    await send_frame(writer, {"type": "ERROR", "info": "Register first"})
                    continue

                recipient = frame.get("to", "")
                message = frame.get("message")

                if not recipient or message is None:
                    await send_frame(writer, {"type": "ERROR", "info": "Missing 'to' or 'message'"})
                    continue

                # Server only reads metadata.receiver for routing — nothing else
                print(f"[SERVER] Routing message from '{username}' to '{recipient}' "
                      f"[{len(json.dumps(message))} bytes] — contents OPAQUE")

                async with _writers_lock:
                    recipient_writer = _writers.get(recipient)

                if recipient_writer:
                    await send_frame(recipient_writer, {
                        "type": "DELIVER",
                        "from": username,
                        "message": message,
                    })
                    await send_frame(writer, {"type": "ACK", "info": f"Message delivered to '{recipient}'"})
                else:
                    # Recipient offline — queue it
                    queued = await store.enqueue(recipient, {
                        "from": username,
                        "message": message,
                    })
                    if queued:
                        await send_frame(writer, {"type": "ACK", "info": f"'{recipient}' offline — message queued"})
                    else:
                        await send_frame(writer, {"type": "ERROR", "info": f"User '{recipient}' does not exist"})

            else:
                await send_frame(writer, {"type": "ERROR", "info": f"Unknown frame type '{ftype}'"})

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        if username:
            async with _writers_lock:
                _writers.pop(username, None)
            print(f"[SERVER] '{username}' disconnected")
        writer.close()


async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[SERVER] Listening on {addrs}")
    print("[SERVER] Untrusted relay — will never decrypt message contents.\n")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
