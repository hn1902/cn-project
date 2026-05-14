"""
client/message_builder.py — Classify → Encrypt → Sign (with Forward Secrecy).

This is the core sender-side pipeline.

Security features:
  - Ephemeral X25519 key exchange (forward secrecy)
  - HKDF-derived per-component AES keys
  - AES-256-GCM authenticated encryption
  - RSA-PSS digital signature over entire payload (including ephemeral key + seq)
  - Monotonic sequence number for replay protection
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timezone

from crypto.aes_gcm import aes_gcm_encrypt
from crypto.signing import sign_payload
from crypto.x25519_ecdh import (
    generate_x25519_keypair,
    x25519_pub_to_b64,
    compute_shared_secret,
    derive_keys_for_types,
)
from utils.classifier import classify_message
from utils.serializer import build_message, canonical_bytes, message_to_json


# ── Per-sender monotonic sequence counter ─────────────────────────────────────
# In production this would be persisted to disk; for this project, in-memory
# is sufficient since each client process is a single session.

_sequence_counters: dict[str, int] = {}


def _next_sequence(sender: str) -> int:
    """Return the next sequence number for *sender* and increment the counter."""
    current = _sequence_counters.get(sender, 0)
    _sequence_counters[sender] = current + 1
    return current + 1


def build_encrypted_message(
    plaintext: str,
    sender: str,
    receiver: str,
    sender_private_key,          # RSA private key (for signing)
    receiver_public_key,         # X25519 public key (for DH key exchange)
) -> tuple[dict, str]:
    """
    Full sender-side pipeline with forward secrecy and replay protection.

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

    # ── 2. Ephemeral Key Exchange (Forward Secrecy) ──────────────────────────
    # Generate a fresh ephemeral X25519 key pair for THIS message only
    eph_private, eph_public = generate_x25519_keypair()

    # Compute shared secret: X25519(ephemeral_private, receiver_long_term_public)
    shared_secret = compute_shared_secret(eph_private, receiver_public_key)

    # Derive per-component AES keys via HKDF
    unique_types = list({c.type for c in components})
    type_keys = derive_keys_for_types(shared_secret, unique_types)

    # CRITICAL: Discard ephemeral private key immediately after use.
    # Only the ephemeral PUBLIC key travels with the message.
    del eph_private
    del shared_secret

    print("  [FORWARD SECRECY] Ephemeral X25519 keypair generated")
    print("  [FORWARD SECRECY] Shared secret derived via ECDH")
    print("  [FORWARD SECRECY] Per-component keys derived via HKDF-SHA256")
    print("  [FORWARD SECRECY] Ephemeral private key DESTROYED")
    print()

    # ── 3. Encrypt each component with its type's HKDF-derived AES key ──────
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

    # ── 4. Build metadata (with sequence number for replay protection) ───────
    seq_num = _next_sequence(sender)
    metadata = {
        "sender": sender,
        "receiver": receiver,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sequence_number": seq_num,
    }

    print(f"  [REPLAY PROTECTION] Sequence number: {seq_num}")
    print()

    # ── 5. Assemble unsigned message dict ────────────────────────────────────
    # The ephemeral public key is included so the receiver can derive the
    # same shared secret. No encrypted_keys section needed anymore.
    msg = build_message(
        metadata=metadata,
        components=encrypted_components,
        encrypted_keys={},            # empty — keys are HKDF-derived, not wrapped
        signature=b"PLACEHOLDER",
        ephemeral_public_key=x25519_pub_to_b64(eph_public),
    )

    # Remove placeholder signature so canonical_bytes produces the right payload
    del msg["signature"]

    # ── 6. Sign the canonical bytes ──────────────────────────────────────────
    # The signature covers: metadata (incl. sequence_number) + components +
    # ephemeral_public_key. This binds the ephemeral key and sequence number
    # to the message, preventing substitution attacks.
    payload = canonical_bytes(msg, exclude_signature=True)
    signature = sign_payload(payload, sender_private_key)

    # ── 7. Re-assemble with real signature ───────────────────────────────────
    from utils.serializer import b64e
    msg["signature"] = b64e(signature)

    # ── 8. Print the encrypted payload so the sender can see it ──────────────
    display = message_to_json(msg)
    print("="*65)
    print("  SENDER: Encrypted Message (what travels over the network)")
    print("="*65)
    print(display)
    print("="*65 + "\n")

    return msg, display
