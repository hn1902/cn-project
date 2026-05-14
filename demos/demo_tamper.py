"""
demos/demo_tamper.py - Signature tampering detection.

Shows that any modification to the message after signing causes
signature verification to FAIL, protecting against message tampering.

Tests:
  1. Ciphertext byte flip (component data tampered)
  2. Metadata field modification (sender ID spoofed)
  3. Ephemeral public key substitution (key swap attack)
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
from client.message_builder import build_encrypted_message
from client.message_reader import read_encrypted_message, reset_replay_state
from cryptography.exceptions import InvalidSignature


def attempt_verify(msg: dict, bob_x25519_priv, alice_rsa_pub, label: str):
    print(f"\n  {label}")
    print(f"  {'-'*58}")
    try:
        result = read_encrypted_message(msg, bob_x25519_priv, alice_rsa_pub)
        print(f"  [UNEXPECTED PASS] Reconstructed: {result!r}")
    except InvalidSignature:
        print(f"  [OK] CORRECTLY BLOCKED: Signature rejected tampered message.")
    except Exception as exc:
        print(f"  [ERROR] {exc}")


def main():
    print("\n" + "="*65)
    print("  DEMO: Signature Tampering Detection")
    print("="*65)

    alice_rsa_priv, alice_rsa_pub = generate_rsa_keypair()
    bob_x25519_priv, bob_x25519_pub = generate_x25519_keypair()
    reset_replay_state()

    plaintext = "Bob Smith owes $500.50 -- ID 99887766"

    print(f'\n[ALICE] Original message: "{plaintext}"')
    msg_dict, _ = build_encrypted_message(
        plaintext=plaintext,
        sender="alice",
        receiver="bob",
        sender_private_key=alice_rsa_priv,
        receiver_public_key=bob_x25519_pub,
    )

    # -- Test 1: Flip a byte in the first component's ciphertext --------------
    reset_replay_state()
    tampered_1 = copy.deepcopy(msg_dict)
    ct = base64.b64decode(tampered_1["components"][0]["ciphertext"])
    ct_list = bytearray(ct)
    if len(ct_list) > 0:
        ct_list[0] ^= 0xFF
    tampered_1["components"][0]["ciphertext"] = base64.b64encode(bytes(ct_list)).decode()
    attempt_verify(tampered_1, bob_x25519_priv, alice_rsa_pub, "Attack 1: Ciphertext byte flip")

    # -- Test 2: Metadata modification (sender spoofing) ----------------------
    reset_replay_state()
    tampered_2 = copy.deepcopy(msg_dict)
    tampered_2["metadata"]["sender"] = "mallory"
    attempt_verify(tampered_2, bob_x25519_priv, alice_rsa_pub, "Attack 2: Metadata sender spoofing")

    # -- Test 3: Ephemeral public key substitution ----------------------------
    reset_replay_state()
    tampered_3 = copy.deepcopy(msg_dict)
    from crypto.x25519_ecdh import generate_x25519_keypair as gen_eph, x25519_pub_to_b64
    _, fake_eph_pub = gen_eph()
    tampered_3["ephemeral_public_key"] = x25519_pub_to_b64(fake_eph_pub)
    attempt_verify(tampered_3, bob_x25519_priv, alice_rsa_pub,
                   "Attack 3: Ephemeral public key substitution")

    # -- Control: Verify original still passes --------------------------------
    reset_replay_state()
    print("\n  Control: Original message (should pass)")
    print(f"  {'-'*58}")
    try:
        result = read_encrypted_message(msg_dict, bob_x25519_priv, alice_rsa_pub)
        print(f"  [OK PASS] Reconstructed: {result!r}")
    except Exception as exc:
        print(f"  [FAIL] {exc}")

    print("\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
