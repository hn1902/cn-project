"""
crypto/keys.py — RSA-2048 and X25519 key generation, serialization, and loading.

RSA keys are used for digital signatures (RSA-PSS).
X25519 keys are long-term identity keys used for Diffie-Hellman key exchange.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization


# ── RSA Key Generation ────────────────────────────────────────────────────────

def generate_rsa_keypair():
    """Generate an RSA-2048 key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


# ── X25519 Key Generation ────────────────────────────────────────────────────

def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate a long-term X25519 key pair. Returns (private_key, public_key)."""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


# ── RSA Serialization ────────────────────────────────────────────────────────

def serialize_private_key(private_key, password: bytes | None = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_private_key(pem: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(pem, password=password)


def deserialize_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


# ── X25519 Serialization ─────────────────────────────────────────────────────

def serialize_x25519_private(private_key: X25519PrivateKey) -> bytes:
    """Serialize X25519 private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_x25519_public(public_key: X25519PublicKey) -> bytes:
    """Serialize X25519 public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_x25519_private(pem: bytes) -> X25519PrivateKey:
    """Deserialize PEM bytes to X25519 private key."""
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, X25519PrivateKey):
        raise TypeError(f"Expected X25519PrivateKey, got {type(key).__name__}")
    return key


def deserialize_x25519_public(pem: bytes) -> X25519PublicKey:
    """Deserialize PEM bytes to X25519 public key."""
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, X25519PublicKey):
        raise TypeError(f"Expected X25519PublicKey, got {type(key).__name__}")
    return key


# ── File I/O ─────────────────────────────────────────────────────────────────

def save_private_key(private_key, path: str, password: bytes | None = None):
    with open(path, "wb") as f:
        f.write(serialize_private_key(private_key, password))


def save_public_key(public_key, path: str):
    with open(path, "wb") as f:
        f.write(serialize_public_key(public_key))


def load_private_key(path: str, password: bytes | None = None):
    with open(path, "rb") as f:
        return deserialize_private_key(f.read(), password)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return deserialize_public_key(f.read())


# ── X25519 File I/O ──────────────────────────────────────────────────────────

def save_x25519_private(private_key: X25519PrivateKey, path: str):
    with open(path, "wb") as f:
        f.write(serialize_x25519_private(private_key))


def save_x25519_public(public_key: X25519PublicKey, path: str):
    with open(path, "wb") as f:
        f.write(serialize_x25519_public(public_key))


def load_x25519_private(path: str) -> X25519PrivateKey:
    with open(path, "rb") as f:
        return deserialize_x25519_private(f.read())


def load_x25519_public(path: str) -> X25519PublicKey:
    with open(path, "rb") as f:
        return deserialize_x25519_public(f.read())
