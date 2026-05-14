"""
demos/demo_normal.py — End-to-end encrypted message demonstration.

Shows:
  1. Alice classifies her message into typed components.
  2. Ephemeral X25519 key exchange (forward secrecy).
  3. Per-component AES keys derived via HKDF.
  4. Each component is encrypted with AES-256-GCM.
  5. Message is RSA-PSS signed by Alice (covers ephemeral key + seq number).
  6. The encrypted JSON (what travels on the network) is printed.
  7. Bob verifies signature, derives keys via ECDH, decrypts, and reconstructs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair, generate_x25519_keypair
from client.message_builder import build_encrypted_message
from client.message_reader import read_encrypted_message, reset_replay_state


def main():
    print("\n" + "="*65)
    print("  DEMO: Normal Encrypted Message Transmission")
    print("  (with Forward Secrecy + Replay Protection)")
    print("="*65)

    # ── Key generation ---------------------------------------------------
    print("\n[SETUP] Generating RSA-2048 key pairs (signing)...")
    alice_rsa_priv, alice_rsa_pub = generate_rsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()

    print("[SETUP] Generating X25519 key pairs (DH key exchange)...")
    alice_x25519_priv, alice_x25519_pub = generate_x25519_keypair()
    bob_x25519_priv, bob_x25519_pub = generate_x25519_keypair()
    print("[SETUP] Keys generated.\n")

    # ── Reset replay state for demo re-runs ------------------------------
    reset_replay_state()

    # ── Original message -------------------------------------------------
    plaintext = "Hello Bob Smith, your ID is 123456789 and balance is $4500.00 please confirm."
    print(f'[ALICE] Original message: "{plaintext}"\n')

    # ── Encrypt (sender side) --------------------------------------------
    msg_dict, _ = build_encrypted_message(
        plaintext=plaintext,
        sender="alice",
        receiver="bob",
        sender_private_key=alice_rsa_priv,       # RSA (signing)
        receiver_public_key=bob_x25519_pub,      # X25519 (DH)
    )

    # ── Decrypt (receiver side) ------------------------------------------
    print("="*65)
    print("  BOB: Receiving and Decrypting Message")
    print("="*65)

    reconstructed = read_encrypted_message(
        message=msg_dict,
        receiver_private_key=bob_x25519_priv,    # X25519 (DH)
        sender_public_key=alice_rsa_pub,         # RSA (sig verification)
    )

    print(f'\n[BOB] Reconstructed message: "{reconstructed}"')
    print(f'\n[VERIFY] Match: {reconstructed == plaintext}')
    print("\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
