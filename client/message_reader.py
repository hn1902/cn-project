"""
client/message_reader.py — Verify Signature -> Unwrap Keys -> Decrypt -> Reconstruct.

This is the full receiver-side pipeline.
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import base64
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature

from crypto.aes_gcm import aes_gcm_decrypt
from crypto.rsa_wrap import unwrap_key
from crypto.signing import verify_signature
from utils.serializer import canonical_bytes, parse_message


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
        # Only one type — nothing interesting to compare
        return

    print("\n" + "=" * 65)
    print("  DAMAGE CONTAINMENT — What a partial key reveals:")
    print("=" * 65)
    print("  (Encrypted parts shown as real base64 ciphertext from the wire)\n")

    for held_type in unique_types:
        held_key = decrypted_keys.get(held_type)
        if held_key is None:
            continue  # skip if we couldn't unwrap this key either

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
                # Show the real encrypted bytes — this is what the attacker actually sees
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
    receiver_private_key,
    sender_public_key,
) -> str:
    """
    Full receiver-side pipeline.

    Returns the reconstructed plaintext string.
    Raises InvalidSignature if the message has been tampered with.
    """

    # -- 1. Verify signature BEFORE doing anything else -----------------------
    sig_b64 = message.get("signature", "")
    signature = base64.b64decode(sig_b64)

    payload = canonical_bytes(message, exclude_signature=True)
    try:
        verify_signature(payload, signature, sender_public_key)
        print("[OK] Signature verified -- message is authentic and untampered.")
    except InvalidSignature:
        print("[FAIL] SIGNATURE VERIFICATION FAILED -- Message may have been tampered with!")
        raise

    # -- 2. Parse (decode base64 fields back to bytes) ------------------------
    metadata, components, encrypted_keys, _ = parse_message(message)

    print(f"\n  Metadata : sender={metadata['sender']!r}, "
          f"receiver={metadata['receiver']!r}, ts={metadata['timestamp']!r}")

    # -- 3. Unwrap each AES session key ---------------------------------------
    decrypted_keys: dict[str, bytes] = {}
    for comp_type, wrapped in encrypted_keys.items():
        try:
            decrypted_keys[comp_type] = unwrap_key(wrapped, receiver_private_key)
        except Exception as exc:
            print(f"  [!] Failed to unwrap key for type '{comp_type}': {exc}")
            decrypted_keys[comp_type] = None  # type: ignore[assignment]

    # -- 4. Decrypt each component in sequence order --------------------------
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

    # -- 5. Reconstruct message in sequence order -----------------------------
    plaintext_parts.sort(key=lambda x: x[0])
    reconstructed = "".join(text for _, text in plaintext_parts).strip()

    # -- 6. Show partial key views (damage containment demo) ------------------
    show_partial_views(components, decrypted_keys)

    return reconstructed
