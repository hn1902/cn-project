"""
crypto/x25519_ecdh.py — X25519 Ephemeral Diffie-Hellman + HKDF key derivation.

Provides forward secrecy: each message generates a fresh ephemeral keypair,
derives a shared secret with the receiver's long-term X25519 key, and uses
HKDF-SHA256 to derive per-component AES-256 keys.

This replaces RSA-OAEP key wrapping for session key delivery.
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes, serialization
import base64


# ── Key Generation ────────────────────────────────────────────────────────────

def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an ephemeral X25519 key pair. Returns (private_key, public_key)."""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


# ── Serialization ─────────────────────────────────────────────────────────────

def serialize_x25519_public(public_key: X25519PublicKey) -> bytes:
    """Serialize X25519 public key to 32 raw bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_x25519_public(raw_bytes: bytes) -> X25519PublicKey:
    """Deserialize 32 raw bytes back to an X25519 public key object."""
    return X25519PublicKey.from_public_bytes(raw_bytes)


def serialize_x25519_private(private_key: X25519PrivateKey) -> bytes:
    """Serialize X25519 private key to 32 raw bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_x25519_private(raw_bytes: bytes) -> X25519PrivateKey:
    """Deserialize 32 raw bytes back to an X25519 private key object."""
    return X25519PrivateKey.from_private_bytes(raw_bytes)


# ── Base64 helpers (for wire format) ──────────────────────────────────────────

def x25519_pub_to_b64(public_key: X25519PublicKey) -> str:
    """Encode X25519 public key as base64 string for JSON transmission."""
    return base64.b64encode(serialize_x25519_public(public_key)).decode("ascii")


def x25519_pub_from_b64(b64_str: str) -> X25519PublicKey:
    """Decode base64 string back to X25519 public key object."""
    return deserialize_x25519_public(base64.b64decode(b64_str))


# ── Shared Secret & Key Derivation ───────────────────────────────────────────

HKDF_SALT = b"cn-project-selective-encryption-v2"
HKDF_INFO_PREFIX = b"component-key:"


def compute_shared_secret(
    my_private: X25519PrivateKey,
    their_public: X25519PublicKey,
) -> bytes:
    """Compute the raw X25519 shared secret (32 bytes)."""
    return my_private.exchange(their_public)


def derive_master_key(shared_secret: bytes) -> bytes:
    """
    Derive a 32-byte master key from the raw shared secret using HKDF-Extract.
    The salt ensures domain separation.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=b"master-key",
    )
    return hkdf.derive(shared_secret)


def derive_component_key(master_key: bytes, component_type: str) -> bytes:
    """
    Derive a 32-byte AES key for a specific component type from the master key.
    Uses HKDF-Expand with a type-specific info label for domain separation.
    Each component type gets a cryptographically independent key.
    """
    hkdf = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=HKDF_INFO_PREFIX + component_type.encode("utf-8"),
    )
    return hkdf.derive(master_key)


def derive_keys_for_types(shared_secret: bytes, component_types: list[str]) -> dict[str, bytes]:
    """
    Full derivation pipeline: shared_secret → master_key → per-type AES keys.
    Returns dict mapping component_type → 32-byte AES key.
    """
    master = derive_master_key(shared_secret)
    return {t: derive_component_key(master, t) for t in component_types}
