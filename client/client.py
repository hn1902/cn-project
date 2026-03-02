"""
client/client.py — Interactive CLI client for the encrypted messaging system.

Usage:
    python client/client.py --user alice --keys-dir keys/alice

Commands (at the prompt):
    send <recipient> <message text>
    list                              # list online users
    quit
"""

import asyncio
import json
import sys
import argparse
import threading
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import (
    generate_rsa_keypair, save_private_key, save_public_key,
    load_private_key, load_public_key, serialize_public_key, deserialize_public_key,
)
from client.message_builder import build_encrypted_message
from client.message_reader import read_encrypted_message
from cryptography.exceptions import InvalidSignature

HOST = "127.0.0.1"
PORT = 9999


class SecureClient:
    def __init__(self, username: str, keys_dir: str):
        self.username = username
        self.keys_dir = Path(keys_dir)
        self.private_key = None
        self.public_key = None
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        # Cache of public keys fetched from server: username -> public_key object
        self._key_cache: dict = {}
        self._pending_key_requests: dict[str, asyncio.Future] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    # ── Key management ────────────────────────────────────────────────────────

    def setup_keys(self):
        """Load existing keys or generate new ones."""
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = self.keys_dir / "private.pem"
        pub_path = self.keys_dir / "public.pem"

        if priv_path.exists() and pub_path.exists():
            print(f"[KEY] Loaded existing keys from {self.keys_dir}")
            self.private_key = load_private_key(str(priv_path))
            self.public_key = load_public_key(str(pub_path))
        else:
            print(f"[KEY] Generating new RSA-2048 key pair → {self.keys_dir}")
            self.private_key, self.public_key = generate_rsa_keypair()
            save_private_key(self.private_key, str(priv_path))
            save_public_key(self.public_key, str(pub_path))
            print("[KEY] Keys saved.")

    # ── Networking ────────────────────────────────────────────────────────────

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
        print(f"[NET] Connected to {HOST}:{PORT}")

    async def send_frame(self, frame: dict):
        data = json.dumps(frame, separators=(",", ":")) + "\n"
        self.writer.write(data.encode("utf-8"))
        await self.writer.drain()

    async def register(self):
        pub_pem = serialize_public_key(self.public_key).decode("utf-8")
        await self.send_frame({
            "type": "REGISTER",
            "username": self.username,
            "public_key_pem": pub_pem,
        })

    async def fetch_public_key(self, username: str):
        """Request a user's public key from the server. Returns key object."""
        if username in self._key_cache:
            return self._key_cache[username]
        fut = self._loop.create_future()
        self._pending_key_requests[username] = fut
        await self.send_frame({"type": "GET_KEY", "username": username})
        return await fut

    async def list_users(self):
        await self.send_frame({"type": "LIST_USERS"})

    # ── Send a message ────────────────────────────────────────────────────────

    async def send_message(self, recipient: str, plaintext: str):
        print(f"\n[→] Preparing message to '{recipient}'...")

        # Get recipient's public key
        try:
            recipient_pub = await self.fetch_public_key(recipient)
        except Exception as exc:
            print(f"[ERROR] Could not get public key for '{recipient}': {exc}")
            return

        msg_dict, _ = build_encrypted_message(
            plaintext=plaintext,
            sender=self.username,
            receiver=recipient,
            sender_private_key=self.private_key,
            receiver_public_key=recipient_pub,
        )

        await self.send_frame({
            "type": "SEND",
            "to": recipient,
            "message": msg_dict,
        })

    # ── Receive loop ──────────────────────────────────────────────────────────

    async def receive_loop(self):
        while True:
            try:
                raw = await self.reader.readline()
                if not raw:
                    print("[NET] Server closed connection.")
                    break

                frame = json.loads(raw.decode("utf-8"))
                ftype = frame.get("type", "")

                if ftype == "ACK":
                    print(f"[OK] {frame.get('info', '')}")

                elif ftype == "ERROR":
                    print(f"[!] Server error: {frame.get('info', '')}")

                elif ftype == "KEY_RESPONSE":
                    uname = frame["username"]
                    pub_key = deserialize_public_key(frame["public_key_pem"].encode())
                    self._key_cache[uname] = pub_key
                    fut = self._pending_key_requests.pop(uname, None)
                    if fut and not fut.done():
                        fut.set_result(pub_key)

                elif ftype == "USER_LIST":
                    users = frame.get("users", [])
                    print(f"[USERS] Online/registered: {', '.join(users) or '(none)'}")

                elif ftype == "DELIVER":
                    from_user = frame.get("from", "?")
                    message = frame.get("message", {})
                    # Dispatch to a separate task so the receive loop stays free
                    # to process the KEY_RESPONSE that _handle_delivery will need.
                    asyncio.create_task(self._handle_delivery(from_user, message))


            except (asyncio.IncompleteReadError, ConnectionResetError):
                print("[NET] Connection lost.")
                break
            except Exception as exc:
                print(f"[NET] Receive error: {exc}")

    # ── Main run loop ─────────────────────────────────────────────────────────

    async def run(self):
        self._loop = asyncio.get_running_loop()
        self.setup_keys()
        await self.connect()
        await self.register()

        # Start receiver in background
        recv_task = asyncio.create_task(self.receive_loop())

        print(f"\n[READY] Logged in as '{self.username}'")
        print("─"*65)
        print("  Commands:")
        print("    send <recipient> <message>   — Encrypt and send a message")
        print("    list                         — List registered users")
        print("    help                         — Show all commands")
        print("    quit                         — Disconnect")
        print()
        print("  Example:")
        print("    send bob My name is Alice. My SSN is 472 7782663 and balance is $5000.00")
        print("─"*65 + "\n")

        loop = asyncio.get_running_loop()

        def stdin_reader():
            while True:
                try:
                    line = input(f"{self.username}> ").strip()
                except EOFError:
                    loop.call_soon_threadsafe(recv_task.cancel)
                    return
                if line:
                    asyncio.run_coroutine_threadsafe(self._handle_input(line), loop)
                    if line.lower() == "quit":
                        return

        thread = threading.Thread(target=stdin_reader, daemon=True)
        thread.start()

        try:
            await recv_task
        except asyncio.CancelledError:
            pass

        self.writer.close()
        print("Goodbye.")

    async def _handle_delivery(self, from_user: str, message: dict):
        """Decrypt and display an incoming message. Runs as a separate task."""
        print(f"\n{'='*65}")
        print(f"  INCOMING MESSAGE from '{from_user}'")
        print(f"{'='*65}")

        # Fetch sender's public key (may require a network round-trip to server)
        try:
            sender_pub = await self.fetch_public_key(from_user)
        except Exception as exc:
            print(f"  [!] Cannot verify — could not get public key for '{from_user}': {exc}")
            print(f"{'='*65}\n")
            return

        try:
            plaintext = read_encrypted_message(
                message=message,
                receiver_private_key=self.private_key,
                sender_public_key=sender_pub,
            )
            print(f"\n  ► Reconstructed message: {plaintext!r}")
            print(f"{'='*65}\n")
        except InvalidSignature:
            print("  [SECURITY] Message REJECTED -- invalid signature!")
            print(f"{'='*65}\n")
        except Exception as exc:
            print(f"  [ERROR] Decryption failed: {exc}")
            print(f"{'='*65}\n")

    # ── Input handling ────────────────────────────────────────────────────────

    async def _handle_input(self, line: str):
        parts = line.split(maxsplit=2)
        cmd = parts[0].lower() if parts else ""

        if cmd == "send":
            if len(parts) < 3:
                print("  Usage: send <recipient> <message text>")
                print("  Example: send bob Hello Bob Smith, your ID is 123456789 and balance is $4500.00")
            else:
                await self.send_message(parts[1], parts[2])
        elif cmd == "list":
            await self.list_users()
        elif cmd == "quit":
            self.writer.close()
        elif cmd == "help":
            self._print_help()
        else:
            print(f"\n  [!] Unknown command '{cmd}'.")
            self._print_help()

    def _print_help(self):
        print("  Commands:")
        print("    send <recipient> <message>   — Encrypt and send a message")
        print("    list                         — List registered users")
        print("    help                         — Show this help")
        print("    quit                         — Disconnect")
        print()
        print("  Example:")
        print("    send bob My name is Alice. My SSN is 472 7782663 and balance is $5000.00")


def main():
    parser = argparse.ArgumentParser(description="Secure E2E Encrypted Messenger")
    parser.add_argument("--user", required=True, help="Username to register as")
    parser.add_argument("--keys-dir", default=None, help="Directory for key files")
    args = parser.parse_args()

    keys_dir = args.keys_dir or f"keys/{args.user}"
    client = SecureClient(username=args.user, keys_dir=keys_dir)
    asyncio.run(client.run())


if __name__ == "__main__":
    main()
