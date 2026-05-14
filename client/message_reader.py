"""
client/message_reader.py — Verify Signature -> Derive Keys (ECDH) -> Decrypt -> Reconstruct.

This is the full receiver-side pipeline with:
  - Forward secrecy: shared secret derived from sender's ephemeral X25519 key
  - Replay protection: sequence number validation per sender
  - Signature verification covers ephemeral key + sequence number (binding)
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import base64
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature

from crypto.aes_gcm import aes_gcm_decrypt
from crypto.signing import verify_signature
from crypto.x25519_ecdh import (
    x25519_pub_from_b64,
    compute_shared_secret,
    derive_keys_for_types,
)
from utils.serializer import canonical_bytes, parse_message


# ── Replay protection state ──────────────────────────────────────────────────
# Maps sender username → last accepted sequence number.
# In production, this would be persisted; in-memory is fine for a demo system.

_last_seen_sequence: dict[str, int] = {}


def _check_replay(sender: str, seq_num: int) -> bool:
    """
    Check if the sequence number is fresh (not a replay).
    Returns True if the message is fresh, False if it's a replay.
    Updates the last-seen counter on acceptance.
    """
    last_seen = _last_seen_sequence.get(sender, 0)
    if seq_num <= last_seen:
        return False  # replay or out-of-order
    _last_seen_sequence[sender] = seq_num
    return True


def reset_replay_state():
    """Reset replay detection state. Used by demos to allow re-running."""
    _last_seen_sequence.clear()


def _short_b64(data: bytes, chars: int = 20) -> str:
    """Return a truncated base64 string followed by '...' to show it's ciphertext."""
    b64 = base64.b64encode(data).decode("ascii")
    return b64[:chars] + "..." if len(b64) > chars else b64


def show_partial_views(
    components: list[dict],
    decrypted_keys: dict[str, bytes],
) -> None:
    """
    Show what an attacker sees if they have only ONE AES session key.

    For each component type present in the message, simulate an attacker who
    holds only that type's key:
      - Components of that type  → shown as decrypted plaintext
      - All other components     → shown as raw base64 ciphertext (the actual
                                   encrypted bytes that travel on the wire)
    """
    unique_types = list(dict.fromkeys(c["type"] for c in components))

    if len(unique_types) <= 1:
        return

    print("\n" + "=" * 65)
    print("  DAMAGE CONTAINMENT — What a partial key reveals:")
    print("=" * 65)
    print("  (Encrypted parts shown as real base64 ciphertext from the wire)\n")

    for held_type in unique_types:
        held_key = decrypted_keys.get(held_type)
        if held_key is None:
            continue

        parts: list[tuple[int, str]] = []
        legend: list[str] = []

        for c in components:
            if c["type"] == held_type:
                try:
                    plain = aes_gcm_decrypt(held_key, c["ciphertext"], c["nonce"], c["tag"])
                    parts.append((c["seq"], plain.decode("utf-8")))
                except Exception:
                    parts.append((c["seq"], f"<DECRYPT_ERR>"))
            else:
                b64_snippet = _short_b64(c["ciphertext"])
                parts.append((c["seq"], b64_snippet))
                if c["type"] not in legend:
                    legend.append(c["type"])

        parts.sort(key=lambda x: x[0])
        reconstructed = "".join(text for _, text in parts).strip()

        hidden = ", ".join(f"'{t}'" for t in unique_types if t != held_type)
        print(f"  Attacker holds ONLY the '{held_type}' key")
        print(f"  ('{held_type}' components readable; {hidden} remain as raw ciphertext):")
        print(f"  >> {reconstructed}")
        print()

    print("  => Each component type is independently encrypted.")
    print("     Compromising one key reveals ONLY that type of data.")
    print("=" * 65)


def read_encrypted_message(
    message: dict,
    receiver_private_key,          # X25519 private key (for DH)
    sender_public_key,             # RSA public key (for signature verification)
) -> str:
    """
    Full receiver-side pipeline with forward secrecy and replay protection.

    Returns the reconstructed plaintext string.
    Raises InvalidSignature if the message has been tampered with.
    Raises ValueError if replay is detected.
    """

    # -- 1. Verify signature BEFORE doing anything else -----------------------
    # The signature covers: metadata (incl. sequence_number) + components +
    # ephemeral_public_key — any modification is detected.
    sig_b64 = message.get("signature", "")
    signature = base64.b64decode(sig_b64)

    payload = canonical_bytes(message, exclude_signature=True)
    try:
        verify_signature(payload, signature, sender_public_key)
        print("[OK] Signature verified -- message is authentic and untampered.")
        print("     (covers metadata, components, ephemeral key, and sequence number)")
    except InvalidSignature:
        print("[FAIL] SIGNATURE VERIFICATION FAILED -- Message may have been tampered with!")
        raise

    # -- 2. Parse (decode base64 fields back to bytes) ------------------------
    metadata, components, encrypted_keys, _ = parse_message(message)

    print(f"\n  Metadata : sender={metadata['sender']!r}, "
          f"receiver={metadata['receiver']!r}, ts={metadata['timestamp']!r}")

    # -- 3. Replay protection — check sequence number -------------------------
    seq_num = metadata.get("sequence_number", 0)
    sender = metadata["sender"]
    print(f"  Sequence : {seq_num}")

    if not _check_replay(sender, seq_num):
        print(f"  [SECURITY] REPLAY DETECTED — sequence {seq_num} from '{sender}' "
              f"already seen (last accepted: {_last_seen_sequence.get(sender, 0)})")
        raise ValueError(
            f"Replay attack detected: sequence {seq_num} from '{sender}' "
            f"is not greater than last seen {_last_seen_sequence.get(sender, 0)}"
        )
    print(f"  [OK] Sequence number {seq_num} is fresh — not a replay.")

    # -- 4. Derive AES keys via X25519 ECDH + HKDF ----------------------------
    # Extract sender's ephemeral public key from the message
    eph_pub_b64 = message.get("ephemeral_public_key", "")
    if not eph_pub_b64:
        raise ValueError("Message missing ephemeral_public_key — cannot derive decryption keys")

    sender_eph_pub = x25519_pub_from_b64(eph_pub_b64)

    # Compute shared secret: X25519(receiver_long_term_private, sender_ephemeral_public)
    shared_secret = compute_shared_secret(receiver_private_key, sender_eph_pub)

    # Derive per-component AES keys using the same HKDF pipeline as the sender
    component_types = list(dict.fromkeys(c["type"] for c in components))
    decrypted_keys = derive_keys_for_types(shared_secret, component_types)

    # Discard shared secret
    del shared_secret

    print("  [FORWARD SECRECY] Shared secret derived from ephemeral key")
    print("  [FORWARD SECRECY] Per-component AES keys derived via HKDF")

    # -- 5. Decrypt each component in sequence order --------------------------
    plaintext_parts: list[tuple[int, str]] = []
    print("\n  Component decryption:")
    for c in components:
        aes_key = decrypted_keys.get(c["type"])
        if aes_key is None:
            print(f"    [seq={c['seq']}] type={c['type']!r}: SKIP (key unavailable)")
            plaintext_parts.append((c["seq"], f"<ENCRYPTED:{c['type']}>"))
            continue
        try:
            plain = aes_gcm_decrypt(aes_key, c["ciphertext"], c["nonce"], c["tag"])
            text = plain.decode("utf-8")
            print(f"    [seq={c['seq']}] type={c['type']!r}: {text!r}")
            plaintext_parts.append((c["seq"], text))
        except Exception as exc:
            print(f"    [seq={c['seq']}] type={c['type']!r}: DECRYPTION ERROR -- {exc}")
            plaintext_parts.append((c["seq"], f"<ERROR:{c['type']}>"))

    # -- 6. Reconstruct message in sequence order -----------------------------
    plaintext_parts.sort(key=lambda x: x[0])
    reconstructed = "".join(text for _, text in plaintext_parts).strip()

    # -- 7. Show partial key views (damage containment demo) ------------------
    show_partial_views(components, decrypted_keys)

    return reconstructed
