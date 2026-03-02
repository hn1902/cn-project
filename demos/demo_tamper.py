"""
demos/demo_tamper.py — Signature tampering detection.

Shows that any modification to the message after signing causes
signature verification to FAIL, protecting against message tampering.

Tests:
  1. Ciphertext byte flip (component data tampered)
  2. Metadata field modification (sender ID spoofed)
  3. Encrypted key replacement (key swap attack)
"""

import sys
import copy
import base64
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair
from client.message_builder import build_encrypted_message
from client.message_reader import read_encrypted_message
from cryptography.exceptions import InvalidSignature


def attempt_verify(msg: dict, bob_priv, alice_pub, label: str):
    print(f"\n  {label}")
    print(f"  {'-'*58}")
    try:
        result = read_encrypted_message(msg, bob_priv, alice_pub)
        print(f"  [UNEXPECTED PASS] Reconstructed: {result!r}")
    except InvalidSignature:
        print(f"  [✓ CORRECTLY FAILED] Signature verification rejected tampered message.")
    except Exception as exc:
        print(f"  [ERROR] {exc}")


def main():
    print("\n" + "="*65)
    print("  DEMO: Signature Tampering Detection")
    print("="*65)

    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv, bob_pub = generate_rsa_keypair()

    plaintext = "Bob Smith owes $500.50 — ID 99887766"

    print(f'\n[ALICE] Original message: "{plaintext}"')
    msg_dict, _ = build_encrypted_message(
        plaintext=plaintext,
        sender="alice",
        receiver="bob",
        sender_private_key=alice_priv,
        receiver_public_key=bob_pub,
    )

    # ── Test 1: Flip a byte in the first component's ciphertext ──────────────
    tampered_1 = copy.deepcopy(msg_dict)
    ct = base64.b64decode(tampered_1["components"][0]["ciphertext"])
    ct_list = bytearray(ct)
    ct_list[0] ^= 0xFF  # flip all bits of first byte
    tampered_1["components"][0]["ciphertext"] = base64.b64encode(bytes(ct_list)).decode()
    attempt_verify(tampered_1, bob_priv, alice_pub, "Attack 1: Ciphertext byte flip")

    # ── Test 2: Metadata modification (sender spoofing) ──────────────────────
    tampered_2 = copy.deepcopy(msg_dict)
    tampered_2["metadata"]["sender"] = "mallory"
    attempt_verify(tampered_2, bob_priv, alice_pub, "Attack 2: Metadata sender spoofing")

    # ── Test 3: Replace an encrypted key with random bytes ───────────────────
    tampered_3 = copy.deepcopy(msg_dict)
    import os
    first_type = next(iter(tampered_3["encrypted_keys"]))
    tampered_3["encrypted_keys"][first_type] = base64.b64encode(os.urandom(256)).decode()
    attempt_verify(tampered_3, bob_priv, alice_pub, "Attack 3: Encrypted key replacement")

    # ── Control: Verify original still passes ────────────────────────────────
    print("\n  Control: Original message (should pass)")
    print(f"  {'-'*58}")
    try:
        result = read_encrypted_message(msg_dict, bob_priv, alice_pub)
        print(f"  [✓ PASS] Reconstructed: {result!r}")
    except Exception as exc:
        print(f"  [FAIL] {exc}")

    print("\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
