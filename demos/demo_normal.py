"""
demos/demo_normal.py — End-to-end encrypted message demonstration.

Shows:
  1. Alice classifies her message into typed components.
  2. Each component is encrypted with its own AES-256-GCM key.
  3. All AES keys are RSA-OAEP wrapped with Bob's public key.
  4. Message is RSA-PSS signed by Alice.
  5. The encrypted JSON (what travels on the network) is printed.
  6. Bob verifies the signature, unwraps keys, decrypts, and reconstructs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair
from client.message_builder import build_encrypted_message
from client.message_reader import read_encrypted_message


def main():
    print("\n" + "="*65)
    print("  DEMO: Normal Encrypted Message Transmission")
    print("="*65)

    # ── Key generation ---------------------------------------------------
    print("\n[SETUP] Generating RSA-2048 key pairs for Alice and Bob...")
    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv, bob_pub = generate_rsa_keypair()
    print("[SETUP] Keys generated.\n")

    # ── Original message -------------------------------------------------
    plaintext = "Hello Bob Smith, your ID is 123456789 and balance is $4500.00 please confirm."
    print(f'[ALICE] Original message: "{plaintext}"\n')

    # ── Encrypt (sender side) --------------------------------------------
    msg_dict, _ = build_encrypted_message(
        plaintext=plaintext,
        sender="alice",
        receiver="bob",
        sender_private_key=alice_priv,
        receiver_public_key=bob_pub,
    )

    # ── Decrypt (receiver side) ------------------------------------------
    print("="*65)
    print("  BOB: Receiving and Decrypting Message")
    print("="*65)

    reconstructed = read_encrypted_message(
        message=msg_dict,
        receiver_private_key=bob_priv,
        sender_public_key=alice_pub,
    )

    print(f'\n[BOB] Reconstructed message: "{reconstructed}"')
    print(f'\n[VERIFY] Match: {reconstructed == plaintext}')
    print("\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
