"""
client/message_reader.py — Verify Signature → Unwrap Keys → Decrypt → Reconstruct.

This is the full receiver-side pipeline.
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature

from crypto.aes_gcm import aes_gcm_decrypt
from crypto.rsa_wrap import unwrap_key
from crypto.signing import verify_signature
from utils.serializer import canonical_bytes, parse_message


def read_encrypted_message(
    message: dict,
    receiver_private_key,
    sender_public_key,
) -> str:
    """
    Full receiver-side pipeline.

    Returns the reconstructed plaintext string.
    Raises InvalidSignature if the message has been tampered with.
    Raises RuntimeError for individual component decryption failures.
    """

    # ── 1. Verify signature BEFORE doing anything else ───────────────────────
    sig_b64 = message.get("signature", "")
    import base64
    signature = base64.b64decode(sig_b64)

    payload = canonical_bytes(message, exclude_signature=True)
    try:
        verify_signature(payload, signature, sender_public_key)
        print("[OK] Signature verified -- message is authentic and untampered.")
    except InvalidSignature:
        print("[FAIL] SIGNATURE VERIFICATION FAILED -- Message may have been tampered with!")
        raise

    # ── 2. Parse (decode base64 fields back to bytes) ────────────────────────
    metadata, components, encrypted_keys, _ = parse_message(message)

    print(f"\n  Metadata : sender={metadata['sender']!r}, "
          f"receiver={metadata['receiver']!r}, ts={metadata['timestamp']!r}")

    # ── 3. Unwrap each AES session key ───────────────────────────────────────
    decrypted_keys: dict[str, bytes] = {}
    for comp_type, wrapped in encrypted_keys.items():
        try:
            decrypted_keys[comp_type] = unwrap_key(wrapped, receiver_private_key)
        except Exception as exc:
            # Partial key compromise: log error but continue with other keys
            print(f"  [!] Failed to unwrap key for type '{comp_type}': {exc}")
            decrypted_keys[comp_type] = None  # type: ignore[assignment]

    # ── 4. Decrypt each component in sequence order ──────────────────────────
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
            print(f"    [seq={c['seq']}] type={c['type']!r}: DECRYPTION ERROR — {exc}")
            plaintext_parts.append((c["seq"], f"<ERROR:{c['type']}>"))

    # ── 5. Reconstruct message in sequence order ─────────────────────────────
    plaintext_parts.sort(key=lambda x: x[0])
    # Join with empty string — component values include surrounding whitespace
    # from character-offset slicing, so no separator is needed.
    reconstructed = "".join(text for _, text in plaintext_parts).strip()
    return reconstructed
