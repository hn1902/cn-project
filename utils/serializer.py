"""
utils/serializer.py — JSON message frame construction and parsing.

All binary fields (ciphertext, nonce, tag, wrapped keys, signature, ephemeral
public key) are stored as standard base64 strings inside JSON so the protocol
stays human-readable.

Updated to support:
  - ephemeral_public_key field (forward secrecy via X25519)
  - sequence_number in metadata (replay protection)
  - canonical serialization includes both new fields for signature binding
"""

import json
import base64


# ── Encoding helpers ──────────────────────────────────────────────────────────

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


# ── Message construction ──────────────────────────────────────────────────────

def build_message(
    metadata: dict,
    components: list[dict],
    encrypted_keys: dict[str, str],
    signature: bytes,
    ephemeral_public_key: str = "",
) -> dict:
    """
    Assemble the final message dict ready for JSON serialisation.

    components: list of dicts, each with keys:
        seq, type, ciphertext (bytes), nonce (bytes), tag (bytes)

    encrypted_keys: dict mapping type → wrapped_key (bytes)
        (empty dict when using forward secrecy — keys are HKDF-derived)

    ephemeral_public_key: base64-encoded X25519 public key (forward secrecy)
    """
    enc_components = []
    for c in components:
        enc_components.append({
            "seq": c["seq"],
            "type": c["type"],
            "ciphertext": b64e(c["ciphertext"]),
            "nonce": b64e(c["nonce"]),
            "tag": b64e(c["tag"]),
        })

    enc_keys = {k: b64e(v) for k, v in encrypted_keys.items()}

    msg = {
        "metadata": metadata,
        "components": enc_components,
        "encrypted_keys": enc_keys,
        "signature": b64e(signature),
    }

    # Add ephemeral public key if provided (forward secrecy mode)
    if ephemeral_public_key:
        msg["ephemeral_public_key"] = ephemeral_public_key

    return msg


def canonical_bytes(message: dict, exclude_signature: bool = True) -> bytes:
    """
    Return the canonical JSON bytes of *message* used for signing/verification.

    The signature field is excluded before signing (it doesn't exist yet at sign
    time, and must be excluded at verify time to reproduce the same bytes).

    IMPORTANT: The canonical form INCLUDES ephemeral_public_key and
    metadata.sequence_number — both are signature-bound to prevent
    substitution and replay attacks.
    """
    if exclude_signature:
        payload = {k: v for k, v in message.items() if k != "signature"}
    else:
        payload = message
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def message_to_json(message: dict) -> str:
    """Pretty-print the full message (including signature) as JSON."""
    return json.dumps(message, indent=2, sort_keys=True)


def message_from_json(raw: str) -> dict:
    """Parse a JSON string back into a message dict."""
    return json.loads(raw)


# ── Message parsing (receiver side) ──────────────────────────────────────────

def parse_message(message: dict) -> tuple[dict, list[dict], dict[str, bytes], bytes]:
    """
    Decode base64 fields back to bytes.

    Returns:
        metadata: dict (includes sequence_number if present)
        components: list of dicts with bytes fields
        encrypted_keys: dict mapping type → wrapped_key bytes (may be empty)
        signature: bytes
    """
    metadata = message["metadata"]
    signature = b64d(message["signature"])

    components = []
    for c in sorted(message["components"], key=lambda x: x["seq"]):
        components.append({
            "seq": c["seq"],
            "type": c["type"],
            "ciphertext": b64d(c["ciphertext"]),
            "nonce": b64d(c["nonce"]),
            "tag": b64d(c["tag"]),
        })

    encrypted_keys = {k: b64d(v) for k, v in message.get("encrypted_keys", {}).items()}

    return metadata, components, encrypted_keys, signature
