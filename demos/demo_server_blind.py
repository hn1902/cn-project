"""
demos/demo_server_blind.py — Server receives the message without being able to read it.

Simulates what the server sees:
  - It can read: metadata (sender, receiver, timestamp)
  - It CANNOT read: component values (all base64 ciphertext), AES keys (all wrapped)
  - It CANNOT read: the signature meaning (just opaque bytes)
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair
from client.message_builder import build_encrypted_message


def server_relay(message: dict):
    """Simulates what an untrusted server does: reads only routing info."""
    print("\n" + "="*65)
    print("  SERVER (untrusted relay) — what it can access:")
    print("="*65)

    meta = message.get("metadata", {})
    print(f"  Sender   : {meta.get('sender', '?')!r}")
    print(f"  Receiver : {meta.get('receiver', '?')!r}")
    print(f"  Timestamp: {meta.get('timestamp', '?')!r}")

    print(f"\n  Number of components : {len(message.get('components', []))}")
    print(f"  Component types      : {[c['type'] for c in message.get('components', [])]}")

    print("\n  Component ciphertexts (server view — OPAQUE):")
    for c in message.get("components", []):
        print(f"    [seq={c['seq']}] type={c['type']!r}  ciphertext={c['ciphertext'][:40]}...")

    print("\n  Encrypted session keys (server view — OPAQUE):")
    for t, wrapped in message.get("encrypted_keys", {}).items():
        print(f"    type={t!r}  wrapped_key={wrapped[:40]}...")

    print(f"\n  Signature (server view — OPAQUE): {message.get('signature', '')[:40]}...")
    print("\n  ► The server cannot decrypt, reconstruct, or read any plaintext.")
    print("="*65)


def main():
    print("\n" + "="*65)
    print("  DEMO: Server Blindness — Untrusted Relay")
    print("="*65)

    alice_priv, alice_pub = generate_rsa_keypair()
    _, bob_pub = generate_rsa_keypair()

    plaintext = "Transfer $9999.99 to account 9876543210 for Charlie."

    print(f'\n[ALICE] Encrypting: "{plaintext}"')

    msg_dict, _ = build_encrypted_message(
        plaintext=plaintext,
        sender="alice",
        receiver="bob",
        sender_private_key=alice_priv,
        receiver_public_key=bob_pub,
    )

    # Simulate server processing
    server_relay(msg_dict)

    print("\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
