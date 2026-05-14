"""
demos/demo_partial_key.py — Partial AES key compromise simulation.

Demonstrates damage containment: if an attacker compromises only ONE
of the per-component HKDF-derived AES keys, they can only decrypt that
component type. All other components remain confidential.

The demo simulates this by:
  1. Encrypting a multi-component message.
  2. Manually extracting one derived AES key (simulating a leak).
  3. Showing what the attacker can and cannot see with that partial key.
"""

import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import copy
import base64
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair, generate_x25519_keypair
from crypto.aes_gcm import aes_gcm_encrypt, aes_gcm_decrypt
from crypto.x25519_ecdh import (
    generate_x25519_keypair as generate_ephemeral_pair,
    compute_shared_secret,
    derive_keys_for_types,
    x25519_pub_to_b64,
)
from crypto.signing import sign_payload
from utils.classifier import classify_message
from utils.serializer import build_message, canonical_bytes, b64e


def main():
    print("\n" + "="*65)
    print("  DEMO: Partial AES Session Key Compromise")
    print("="*65)

    alice_rsa_priv, alice_rsa_pub = generate_rsa_keypair()
    bob_x25519_priv, bob_x25519_pub = generate_x25519_keypair()

    plaintext = "Transfer $7500.00 to Bob Smith account 112233445566"
    print(f'\n[ALICE] Message: "{plaintext}"')

    # ── Manually build the message so we can extract individual keys ──────
    components = classify_message(plaintext)
    print("\n[CLASSIFICATION]")
    for c in components:
        print(f"  [seq={c.seq}] type={c.type!r}  value={c.value!r}")

    # Generate ephemeral key and derive per-type keys
    eph_priv, eph_pub = generate_ephemeral_pair()
    shared_secret = compute_shared_secret(eph_priv, bob_x25519_pub)
    unique_types = list({c.type for c in components})
    type_keys = derive_keys_for_types(shared_secret, unique_types)

    # Encrypt components
    enc_components = []
    for c in components:
        ct, nonce, tag = aes_gcm_encrypt(type_keys[c.type], c.value.encode())
        enc_components.append({"seq": c.seq, "type": c.type,
                                "ciphertext": ct, "nonce": nonce, "tag": tag})

    metadata = {
        "sender": "alice",
        "receiver": "bob",
        "timestamp": "2026-03-02T14:00:00+00:00",
        "sequence_number": 1,
    }

    msg = build_message(
        metadata, enc_components, {},
        b"PLACEHOLDER",
        ephemeral_public_key=x25519_pub_to_b64(eph_pub),
    )
    del msg["signature"]
    payload_bytes = canonical_bytes(msg)
    sig = sign_payload(payload_bytes, alice_rsa_priv)
    msg["signature"] = b64e(sig)

    # ── Scenario A: Attacker has one HKDF-derived AES key ─────────────────
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

    # ── Scenario B: Attacker tries another type's key on wrong component ──
    print(f"\n{'='*65}")
    print(f"  SCENARIO B: Attacker tries '{leaked_type}' key on other component types")
    print(f"{'='*65}")
    for c in enc_components:
        if c["type"] != leaked_type:
            try:
                aes_gcm_decrypt(leaked_key, c["ciphertext"], c["nonce"], c["tag"])
                print(f"    [seq={c['seq']}] type={c['type']!r}: DECRYPTED (unexpected!)")
            except Exception:
                print(f"    [seq={c['seq']}] type={c['type']!r}: FAILED — wrong key, "
                      f"AES-GCM InvalidTag ✓")

    print(f"\n{'='*65}")
    print("  RESULT: Each component type has cryptographically independent keys.")
    print("  Compromising one HKDF-derived key reveals ONLY that type of data.")
    print("  All other component types remain fully confidential.")
    print(f"{'='*65}")

    print("\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
