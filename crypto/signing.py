"""
crypto/signing.py — RSA-PSS digital signature generation and verification.

The entire message payload (components + encrypted_keys + metadata) is
canonicalized to JSON (sorted keys, compact) and then signed / verified.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def sign_payload(payload_bytes: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Sign *payload_bytes* using RSA-PSS (SHA-256).
    Returns the raw signature bytes.
    """
    return private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(
    payload_bytes: bytes,
    signature: bytes,
    public_key: RSAPublicKey,
) -> bool:
    """
    Verify *signature* over *payload_bytes* using RSA-PSS.
    Returns True on success.
    Raises InvalidSignature (re-raised) on failure so callers can distinguish
    tamper detection from other errors.
    """
    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        raise  # Let callers handle it explicitly
