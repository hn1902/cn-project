"""
crypto/aes_gcm.py — AES-256-GCM authenticated encryption / decryption.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32   # 256-bit
NONCE_SIZE = 12  # 96-bit — standard GCM recommendation


def generate_aes_key() -> bytes:
    """Return 32 random bytes suitable as an AES-256 key."""
    return os.urandom(KEY_SIZE)


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns (ciphertext, nonce, tag).
    Note: the cryptography library appends the 16-byte tag to ciphertext.
    We split it out for explicit storage in the message JSON.
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    combined = aesgcm.encrypt(nonce, plaintext, None)  # No additional data
    # AESGCM.encrypt() returns ciphertext || tag (tag is always last 16 bytes)
    ciphertext = combined[:-16]
    tag = combined[-16:]
    return ciphertext, nonce, tag


def aes_gcm_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt and authenticate.  Raises InvalidTag if authentication fails.
    """
    aesgcm = AESGCM(key)
    combined = ciphertext + tag  # re-join before passing to library
    return aesgcm.decrypt(nonce, combined, None)
