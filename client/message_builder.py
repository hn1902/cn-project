"""
client/message_builder.py — Classify → Encrypt → Wrap Keys → Sign.

This is the core sender-side pipeline.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timezone

from crypto.aes_gcm import generate_aes_key, aes_gcm_encrypt
from crypto.rsa_wrap import wrap_key
from crypto.signing import sign_payload
from utils.classifier import classify_message
from utils.serializer import build_message, canonical_bytes, message_to_json


def build_encrypted_message(
    plaintext: str,
    sender: str,
    receiver: str,
    sender_private_key,
    receiver_public_key,
) -> tuple[dict, str]:
    """
    Full sender-side pipeline.

    Returns:
        (message_dict, display_str)
        message_dict — ready to serialise and send over the wire
        display_str  — pretty-printed JSON of the encrypted payload (for demos)
    """

    # ── 1. Classify ──────────────────────────────────────────────────────────
    components = classify_message(plaintext)

    print("\n" + "="*65)
    print("  SENDER: Component Classification")
    print("="*65)
    for c in components:
        print(f"  [seq={c.seq}] type={c.type!r:8s}  value={c.value!r}")
    print()

    # ── 2. Generate one AES key per unique component type ────────────────────
    type_keys: dict[str, bytes] = {}
    unique = list({c.type for c in components})
    for t in unique:
        type_keys[t] = generate_aes_key()

    # ── 3. Encrypt each component with its type's AES key ───────────────────
    encrypted_components = []
    for c in components:
        key = type_keys[c.type]
        ciphertext, nonce, tag = aes_gcm_encrypt(key, c.value.encode("utf-8"))
        encrypted_components.append({
            "seq": c.seq,
            "type": c.type,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
        })

    # ── 4. Wrap each AES key with receiver's RSA public key ──────────────────
    wrapped_keys: dict[str, bytes] = {}
    for t, aes_key in type_keys.items():
        wrapped_keys[t] = wrap_key(aes_key, receiver_public_key)

    # ── 5. Build metadata ────────────────────────────────────────────────────
    metadata = {
        "sender": sender,
        "receiver": receiver,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── 6. Assemble unsigned message dict (base64-encoded) ───────────────────
    msg = build_message(metadata, encrypted_components, wrapped_keys, b"PLACEHOLDER")
    # Remove placeholder signature so canonical_bytes produces the right payload
    del msg["signature"]

    # ── 7. Sign the canonical bytes ──────────────────────────────────────────
    payload = canonical_bytes(msg, exclude_signature=True)
    signature = sign_payload(payload, sender_private_key)

    # ── 8. Re-assemble with real signature ───────────────────────────────────
    from utils.serializer import b64e
    msg["signature"] = b64e(signature)

    # ── 9. Print the encrypted payload so the sender can see it ─────────────
    display = message_to_json(msg)
    print("="*65)
    print("  SENDER: Encrypted Message (what travels over the network)")
    print("="*65)
    print(display)
    print("="*65 + "\n")

    return msg, display
