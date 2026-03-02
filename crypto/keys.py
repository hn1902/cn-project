"""
crypto/keys.py — RSA-2048 key generation, serialization, and loading.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keypair():
    """Generate an RSA-2048 key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


# ── Serialization ────────────────────────────────────────────────────────────

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
