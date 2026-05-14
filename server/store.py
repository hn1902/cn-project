"""
server/store.py — In-memory user registry and public-key store.
Thread-safe via asyncio.Lock (single-process event loop).

Stores both RSA (signing) and X25519 (DH key exchange) public keys per user.
"""

import asyncio


class UserStore:
    def __init__(self):
        self._lock = asyncio.Lock()
        # username -> RSA public_key_pem (str, UTF-8 decoded)
        self._users: dict[str, str] = {}
        # username -> X25519 public_key_pem (str, UTF-8 decoded)
        self._x25519_keys: dict[str, str] = {}
        # username -> asyncio.Queue for incoming messages
        self._queues: dict[str, asyncio.Queue] = {}

    # ── Registration ──────────────────────────────────────────────────────────

    async def register(self, username: str, public_key_pem: str,
                       x25519_public_key_pem: str = "") -> bool:
        """Register a user with RSA and X25519 public keys. Returns False if username already taken."""
        async with self._lock:
            if username in self._users:
                return False
            self._users[username] = public_key_pem
            if x25519_public_key_pem:
                self._x25519_keys[username] = x25519_public_key_pem
            self._queues[username] = asyncio.Queue()
            return True

    # ── Key lookup ────────────────────────────────────────────────────────────

    async def get_public_key(self, username: str) -> str | None:
        async with self._lock:
            return self._users.get(username)

    async def get_x25519_public_key(self, username: str) -> str | None:
        async with self._lock:
            return self._x25519_keys.get(username)

    async def user_exists(self, username: str) -> bool:
        async with self._lock:
            return username in self._users

    async def list_users(self) -> list[str]:
        async with self._lock:
            return list(self._users.keys())

    # ── Message queuing ───────────────────────────────────────────────────────

    async def enqueue(self, recipient: str, message: dict) -> bool:
        """Put *message* in the recipient's queue. Returns False if unknown user."""
        async with self._lock:
            if recipient not in self._queues:
                return False
            await self._queues[recipient].put(message)
            return True

    async def get_queue(self, username: str) -> asyncio.Queue | None:
        async with self._lock:
            return self._queues.get(username)
