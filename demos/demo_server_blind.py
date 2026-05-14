"""
demos/demo_server_blind.py — Server receives the message without being able to read it.

Simulates what the server sees:
  - It can read: metadata (sender, receiver, timestamp, sequence_number)
  - It can see: ephemeral_public_key (but cannot use it without receiver's private key)
  - It CANNOT read: component values (all base64 ciphertext)
  - It CANNOT read: the signature meaning (just opaque bytes)
  - There are NO encrypted_keys to see (keys are HKDF-derived, not transmitted)
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair, generate_x25519_keypair
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
    print(f"  Seq Num  : {meta.get('sequence_number', '?')}")

    print(f"\n  Number of components : {len(message.get('components', []))}")
    print(f"  Component types      : {[c['type'] for c in message.get('components', [])]}")

    print("\n  Component ciphertexts (server view — OPAQUE):")
    for c in message.get("components", []):
        print(f"    [seq={c['seq']}] type={c['type']!r}  ciphertext={c['ciphertext'][:40]}...")

    epk = message.get("ephemeral_public_key", "")
    print(f"\n  Ephemeral public key: {epk[:40]}...")
    print("  (Server can see this but CANNOT derive the shared secret")
    print("   without the receiver's X25519 private key)")

    enc_keys = message.get("encrypted_keys", {})
    if enc_keys:
        print(f"\n  Encrypted session keys: {len(enc_keys)} types")
    else:
        print(f"\n  Encrypted session keys: NONE")
        print("  (Keys are derived via HKDF from the DH shared secret —")
        print("   they never travel on the wire at all)")

    print(f"\n  Signature (server view — OPAQUE): {message.get('signature', '')[:40]}...")

    wire_size = len(json.dumps(message))
    print(f"\n  Total wire size: {wire_size:,} bytes")
    print("\n  ► The server cannot decrypt, reconstruct, or read any plaintext.")
    print("  ► The server cannot derive session keys (no access to DH private key).")
    print("="*65)


def main():
    print("\n" + "="*65)
    print("  DEMO: Server Blindness — Untrusted Relay")
    print("="*65)

    alice_rsa_priv, _ = generate_rsa_keypair()
    _, bob_x25519_pub = generate_x25519_keypair()

    plaintext = "Transfer $9999.99 to account 9876543210 for Charlie."

    print(f'\n[ALICE] Encrypting: "{plaintext}"')

    msg_dict, _ = build_encrypted_message(
        plaintext=plaintext,
        sender="alice",
        receiver="bob",
        sender_private_key=alice_rsa_priv,
        receiver_public_key=bob_x25519_pub,
    )

    # Simulate server processing
    server_relay(msg_dict)

    print("\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
