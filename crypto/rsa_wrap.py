"""
crypto/rsa_wrap.py — RSA-OAEP key wrapping / unwrapping.

AES session keys are encrypted with the receiver's RSA public key (key wrapping)
and decrypted by the receiver's private key (key unwrapping).
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def wrap_key(aes_key: bytes, recipient_public_key) -> bytes:
    """
    Encrypt *aes_key* using RSA-OAEP (SHA-256).
    Returns the wrapped key ciphertext.
    """
    return recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key(wrapped_key: bytes, recipient_private_key) -> bytes:
    """
    Decrypt *wrapped_key* using RSA-OAEP.
    Returns the original AES key bytes.
    Raises ValueError / cryptography exceptions on failure.
    """
    return recipient_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
