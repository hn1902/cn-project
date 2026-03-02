"""
demos/demo_performance.py — Performance comparison: single-key vs multi-key encryption.

Measures and compares:
  - Encryption time (ms)
  - Decryption time (ms)
  - Message size (bytes)

For the SAME plaintext, run with:
  Mode A — Single AES key for the entire message
  Mode B — One AES key per component type (the project's approach)

Averaged over N_RUNS iterations for stable timing.
"""

import sys
import time
import json
import base64
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from crypto.keys import generate_rsa_keypair
from crypto.aes_gcm import generate_aes_key, aes_gcm_encrypt, aes_gcm_decrypt
from crypto.rsa_wrap import wrap_key, unwrap_key
from crypto.signing import sign_payload, verify_signature
from utils.classifier import classify_message
from utils.serializer import canonical_bytes, b64e, b64d

N_RUNS = 20  # average over this many iterations

PLAINTEXT = (
    "Hello Bob Smith, your account ID is 112233445566 "
    "and your balance is $4500.75. Please confirm the transfer of "
    "$250.00 to Charlie Johnson with transaction ID 99887766554433."
)


def b64_size(data: bytes) -> int:
    return len(base64.b64encode(data))


# ── Mode A: Single AES key for whole message ──────────────────────────────────

def encrypt_single_key(plaintext: str, sender_priv, receiver_pub):
    key = generate_aes_key()
    ct, nonce, tag = aes_gcm_encrypt(key, plaintext.encode())
    wrapped = wrap_key(key, receiver_pub)

    msg = {
        "metadata": {"sender": "alice", "receiver": "bob", "timestamp": "2026-01-01T00:00:00Z"},
        "ciphertext": b64e(ct),
        "nonce": b64e(nonce),
        "tag": b64e(tag),
        "encrypted_key": b64e(wrapped),
    }
    payload = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
    sig = sign_payload(payload, sender_priv)
    msg["signature"] = b64e(sig)
    return msg


def decrypt_single_key(msg: dict, receiver_priv, sender_pub):
    sig = b64d(msg["signature"])
    payload = {k: v for k, v in msg.items() if k != "signature"}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    verify_signature(payload_bytes, sig, sender_pub)

    key = unwrap_key(b64d(msg["encrypted_key"]), receiver_priv)
    plain = aes_gcm_decrypt(key, b64d(msg["ciphertext"]), b64d(msg["nonce"]), b64d(msg["tag"]))
    return plain.decode()


# ── Mode B: One AES key per component type ────────────────────────────────────

def encrypt_multi_key(plaintext: str, sender_priv, receiver_pub):
    components = classify_message(plaintext)
    type_keys = {c.type: generate_aes_key() for c in components if c.type not in {}}
    # re-build properly
    type_keys = {}
    for c in components:
        if c.type not in type_keys:
            type_keys[c.type] = generate_aes_key()

    enc_comps = []
    for c in components:
        key = type_keys[c.type]
        ct, nonce, tag = aes_gcm_encrypt(key, c.value.encode())
        enc_comps.append({"seq": c.seq, "type": c.type,
                           "ciphertext": b64e(ct), "nonce": b64e(nonce), "tag": b64e(tag)})

    wrapped_keys = {t: b64e(wrap_key(k, receiver_pub)) for t, k in type_keys.items()}

    msg = {
        "metadata": {"sender": "alice", "receiver": "bob", "timestamp": "2026-01-01T00:00:00Z"},
        "components": enc_comps,
        "encrypted_keys": wrapped_keys,
    }
    payload = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
    sig = sign_payload(payload, sender_priv)
    msg["signature"] = b64e(sig)
    return msg


def decrypt_multi_key(msg: dict, receiver_priv, sender_pub):
    sig = b64d(msg["signature"])
    payload = {k: v for k, v in msg.items() if k != "signature"}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    verify_signature(payload_bytes, sig, sender_pub)

    dec_keys = {t: unwrap_key(b64d(w), receiver_priv) for t, w in msg["encrypted_keys"].items()}
    parts = []
    for c in sorted(msg["components"], key=lambda x: x["seq"]):
        key = dec_keys[c["type"]]
        plain = aes_gcm_decrypt(key, b64d(c["ciphertext"]), b64d(c["nonce"]), b64d(c["tag"]))
        parts.append((c["seq"], plain.decode()))
    return " ".join(t for _, t in sorted(parts))


# ── Benchmark runner ──────────────────────────────────────────────────────────

def benchmark(name, encrypt_fn, decrypt_fn, sender_priv, sender_pub, receiver_priv, receiver_pub):
    enc_times = []
    dec_times = []
    msg_size = 0

    for i in range(N_RUNS):
        t0 = time.perf_counter()
        msg = encrypt_fn(PLAINTEXT, sender_priv, receiver_pub)
        enc_times.append(time.perf_counter() - t0)

        if i == 0:
            msg_size = len(json.dumps(msg).encode("utf-8"))

        t1 = time.perf_counter()
        decrypt_fn(msg, receiver_priv, sender_pub)
        dec_times.append(time.perf_counter() - t1)

    avg_enc = (sum(enc_times) / N_RUNS) * 1000
    avg_dec = (sum(dec_times) / N_RUNS) * 1000
    return avg_enc, avg_dec, msg_size


def main():
    print("\n" + "="*65)
    print("  DEMO: Performance Comparison — Single-Key vs Multi-Key")
    print("="*65)
    print(f"\n  Message   : {PLAINTEXT[:60]}...")
    print(f"  Runs      : {N_RUNS} iterations per mode\n")

    print("[SETUP] Generating RSA-2048 keys...")
    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv, bob_pub = generate_rsa_keypair()
    print("[SETUP] Done\n")

    print("[BENCHMARK] Mode A: Single AES Key for whole message...")
    enc_a, dec_a, size_a = benchmark(
        "Single-Key",
        encrypt_single_key, decrypt_single_key,
        alice_priv, alice_pub, bob_priv, bob_pub,
    )

    print("[BENCHMARK] Mode B: One AES Key per component type...")
    enc_b, dec_b, size_b = benchmark(
        "Multi-Key",
        encrypt_multi_key, decrypt_multi_key,
        alice_priv, alice_pub, bob_priv, bob_pub,
    )

    # ── Results table ─────────────────────────────────────────────────────────
    print()
    print(f"  {'Metric':<30} {'Single-Key (A)':>16} {'Multi-Key (B)':>16} {'Overhead':>10}")
    print(f"  {'-'*74}")
    print(f"  {'Avg Encryption Time (ms)':<30} {enc_a:>16.3f} {enc_b:>16.3f} {enc_b-enc_a:>+10.3f}")
    print(f"  {'Avg Decryption Time (ms)':<30} {dec_a:>16.3f} {dec_b:>16.3f} {dec_b-dec_a:>+10.3f}")
    print(f"  {'Message Size (bytes)':<30} {size_a:>16,} {size_b:>16,} {size_b-size_a:>+10,}")
    print()
    print("  Notes:")
    print("  - Multi-key overhead comes from per-type RSA-OAEP wrapping.")
    print("  - Each additional component type adds ~344 bytes (RSA-2048 OAEP ciphertext).")
    print("  - The granularity benefit: partial key compromise only reveals one type.")
    print(f"\n[DEMO COMPLETE]\n")


if __name__ == "__main__":
    main()
