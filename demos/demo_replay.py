"""
demos/demo_replay.py — Demonstrates replay attack detection.

Scenario:
  1. Alice sends a legitimate message to Bob.
  2. Bob successfully decrypts and accepts it.
  3. An attacker captures the message and replays it (sends exact same bytes).
  4. Bob's replay detection REJECTS the replayed message.
  5. Attacker tries to modify the sequence number to bypass detection.
  6. Signature verification FAILS — sequence number is signature-bound.
"""

import sys
import copy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair, generate_x25519_keypair
from client.message_builder import build_encrypted_message
from client.message_reader import read_encrypted_message, reset_replay_state
from cryptography.exceptions import InvalidSignature


def main():
    print("\n" + "="*65)
    print("  DEMO: Replay Attack Detection")
    print("="*65)

    # ── Setup ────────────────────────────────────────────────────────────
    print("\n[SETUP] Generating keys...")
    alice_rsa_priv, alice_rsa_pub = generate_rsa_keypair()
    bob_x25519_priv, bob_x25519_pub = generate_x25519_keypair()
    reset_replay_state()

    # ── Alice sends a legitimate message ─────────────────────────────────
    plaintext = "Transfer $50000 to account 987654321"
    print(f'\n[ALICE] Sending: "{plaintext}"')

    msg_dict, _ = build_encrypted_message(
        plaintext=plaintext,
        sender="alice",
        receiver="bob",
        sender_private_key=alice_rsa_priv,
        receiver_public_key=bob_x25519_pub,
    )

    # ── Bob receives and decrypts (first time — should succeed) ──────────
    print("\n" + "="*65)
    print("  ATTEMPT 1: Bob receives the original message")
    print("="*65)

    try:
        result = read_encrypted_message(
            message=msg_dict,
            receiver_private_key=bob_x25519_priv,
            sender_public_key=alice_rsa_pub,
        )
        print(f'\n  ✓ SUCCESS: Decrypted to: "{result}"')
    except Exception as e:
        print(f"\n  ✗ Unexpected failure: {e}")

    # ── Attacker replays the EXACT same message ──────────────────────────
    print("\n" + "="*65)
    print("  ATTEMPT 2: Attacker replays the EXACT same message")
    print("  (same sequence number, same everything)")
    print("="*65)

    replayed_msg = copy.deepcopy(msg_dict)  # exact copy

    try:
        result = read_encrypted_message(
            message=replayed_msg,
            receiver_private_key=bob_x25519_priv,
            sender_public_key=alice_rsa_pub,
        )
        print(f"\n  ✗ UNEXPECTED: Message was accepted! This shouldn't happen.")
    except ValueError as e:
        print(f"\n  ✓ REPLAY DETECTED: {e}")
        print("  → The receiver rejected the duplicate message.")
    except Exception as e:
        print(f"\n  ✓ REJECTED: {e}")

    # ── Attacker modifies the sequence number to try to bypass ───────────
    print("\n" + "="*65)
    print("  ATTEMPT 3: Attacker modifies sequence_number to bypass detection")
    print("  (changes seq 1 → 999, but doesn't have Alice's signing key)")
    print("="*65)

    tampered_msg = copy.deepcopy(msg_dict)
    original_seq = tampered_msg["metadata"]["sequence_number"]
    tampered_msg["metadata"]["sequence_number"] = 999
    print(f"\n  Original sequence: {original_seq}")
    print(f"  Tampered sequence: 999")

    try:
        result = read_encrypted_message(
            message=tampered_msg,
            receiver_private_key=bob_x25519_priv,
            sender_public_key=alice_rsa_pub,
        )
        print(f"\n  ✗ UNEXPECTED: Tampered message was accepted!")
    except InvalidSignature:
        print(f"\n  ✓ SIGNATURE VERIFICATION FAILED")
        print("  → Changing the sequence number invalidates the RSA-PSS signature.")
        print("  → The attacker cannot forge a valid signature without Alice's private key.")

    # ── Attacker modifies the ephemeral public key ───────────────────────
    print("\n" + "="*65)
    print("  ATTEMPT 4: Attacker substitutes the ephemeral public key")
    print("  (tries to redirect DH exchange to their own key)")
    print("="*65)

    from crypto.x25519_ecdh import generate_x25519_keypair as gen_eph, x25519_pub_to_b64

    epk_tampered_msg = copy.deepcopy(msg_dict)
    attacker_eph_priv, attacker_eph_pub = gen_eph()
    original_epk = epk_tampered_msg["ephemeral_public_key"][:30]
    epk_tampered_msg["ephemeral_public_key"] = x25519_pub_to_b64(attacker_eph_pub)
    print(f"\n  Original EPK: {original_epk}...")
    print(f"  Attacker EPK: {epk_tampered_msg['ephemeral_public_key'][:30]}...")

    reset_replay_state()  # reset to allow seq 1 again for this test

    try:
        result = read_encrypted_message(
            message=epk_tampered_msg,
            receiver_private_key=bob_x25519_priv,
            sender_public_key=alice_rsa_pub,
        )
        print(f"\n  ✗ UNEXPECTED: Tampered message was accepted!")
    except InvalidSignature:
        print(f"\n  ✓ SIGNATURE VERIFICATION FAILED")
        print("  → The ephemeral public key is covered by the signature.")
        print("  → Substituting it breaks the RSA-PSS signature.")

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "="*65)
    print("  REPLAY PROTECTION — Summary")
    print("="*65)
    print("""
  SEQUENCE NUMBERS:
    - Each message has a monotonically increasing sequence number.
    - The receiver tracks the last-seen sequence per sender.
    - Duplicate or older sequence numbers are REJECTED.

  SIGNATURE BINDING:
    - The RSA-PSS signature covers:
      • metadata (including sequence_number)
      • encrypted components
      • ephemeral_public_key
    - An attacker CANNOT:
      • Replay exact messages (sequence check fails)
      • Modify sequence number (signature check fails)
      • Substitute ephemeral key (signature check fails)
      • Forge a new signature (requires sender's RSA private key)
""")
    print("="*65)
    print("[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
