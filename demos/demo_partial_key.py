"""
demos/demo_partial_key.py — Partial AES key compromise simulation.

Demonstrates damage containment: if an attacker compromises only ONE
of the per-component AES session keys, they can only decrypt that
component type. All other components remain confidential.

The demo simulates this by:
  1. Encrypting a multi-component message.
  2. Manually extracting one unwrapped AES key.
  3. Showing what the attacker can and cannot see with that partial key.
  4. Also shows receiver's graceful handling when one wrapped key is corrupted.
"""

import sys
import copy
import base64
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair
from crypto.aes_gcm import generate_aes_key, aes_gcm_encrypt, aes_gcm_decrypt
from crypto.rsa_wrap import wrap_key, unwrap_key
from crypto.signing import sign_payload, verify_signature
from utils.classifier import classify_message
from utils.serializer import build_message, canonical_bytes, b64e, b64d
from client.message_reader import read_encrypted_message


def main():
    print("\n" + "="*65)
    print("  DEMO: Partial AES Session Key Compromise")
    print("="*65)

    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv, bob_pub = generate_rsa_keypair()

    plaintext = "Transfer $7500.00 to Bob Smith account 112233445566"
    print(f'\n[ALICE] Message: "{plaintext}"')

    # ── Manually build the message so we can leak one key ─────────────────────
    components = classify_message(plaintext)
    print("\n[CLASSIFICATION]")
    for c in components:
        print(f"  [seq={c.seq}] type={c.type!r}  value={c.value!r}")

    # Generate per-type AES keys
    type_keys: dict[str, bytes] = {}
    for c in components:
        if c.type not in type_keys:
            type_keys[c.type] = generate_aes_key()

    # Encrypt components
    enc_components = []
    for c in components:
        ct, nonce, tag = aes_gcm_encrypt(type_keys[c.type], c.value.encode())
        enc_components.append({"seq": c.seq, "type": c.type,
                                "ciphertext": ct, "nonce": nonce, "tag": tag})

    # Wrap keys for Bob
    wrapped_keys = {t: wrap_key(k, bob_pub) for t, k in type_keys.items()}

    metadata = {"sender": "alice", "receiver": "bob", "timestamp": "2026-03-02T14:00:00+00:00"}
    msg = build_message(metadata, enc_components, wrapped_keys, b"PLACEHOLDER")
    del msg["signature"]

    payload_bytes = canonical_bytes(msg)
    sig = sign_payload(payload_bytes, alice_priv)
    msg["signature"] = b64e(sig)

    # ── Scenario A: Attacker has the 'number' AES key ─────────────────────────
    leaked_type = "number"
    if leaked_type not in type_keys:
        leaked_type = list(type_keys.keys())[0]

    leaked_key = type_keys[leaked_type]

    print(f"\n{'='*65}")
    print(f"  SCENARIO A: Attacker obtained the '{leaked_type}' AES key")
    print(f"{'='*65}")
    print(f"  Leaked key : {leaked_key.hex()}")
    print(f"  With this key, the attacker can ONLY decrypt '{leaked_type}' components:")
    for c in enc_components:
        if c["type"] == leaked_type:
            try:
                plain = aes_gcm_decrypt(leaked_key, c["ciphertext"], c["nonce"], c["tag"])
                print(f"    [seq={c['seq']}] DECRYPTED: {plain.decode()!r}")
            except Exception as e:
                print(f"    [seq={c['seq']}] FAILED: {e}")
        else:
            print(f"    [seq={c['seq']}] type={c['type']!r}: STILL ENCRYPTED (different key) ✓")

    # ── Scenario B: One wrapped key is corrupted → graceful degradation ────────
    print(f"\n{'='*65}")
    print(f"  SCENARIO B: One wrapped key corrupted (e.g. transmission error)")
    print(f"{'='*65}")

    corrupted_msg = copy.deepcopy(msg)
    first_type = list(json_keys(corrupted_msg))
    # Corrupt the first wrapped key
    from utils.serializer import b64d
    import json as _json
    all_types = list(corrupted_msg["encrypted_keys"].keys())
    target_type = all_types[0]
    original_wrapped = b64d(corrupted_msg["encrypted_keys"][target_type])
    corrupted = bytearray(original_wrapped)
    for i in range(0, min(16, len(corrupted))):
        corrupted[i] ^= 0xAB
    corrupted_msg["encrypted_keys"][target_type] = b64e(bytes(corrupted))

    print(f"  Corrupted wrapped key for type: '{target_type}'")
    print(f"  System should gracefully handle missing component and decrypt the rest:\n")

    # Verification will fail because keys changed but signature covers them.
    # Re-sign so we can test the decryption path specifically:
    corrupted_msg_nosig = {k: v for k, v in corrupted_msg.items() if k != "signature"}
    new_sig = sign_payload(canonical_bytes(corrupted_msg_nosig), alice_priv)
    corrupted_msg["signature"] = b64e(new_sig)

    read_encrypted_message(corrupted_msg, bob_priv, alice_pub)

    print("\n[DEMO COMPLETE]\n")


def json_keys(msg):
    return msg.get("encrypted_keys", {}).keys()


if __name__ == "__main__":
    main()
