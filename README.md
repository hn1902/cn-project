# Selective Component-Level End-to-End Encryption

A secure client–server messaging system that implements **hybrid encryption**, **per-component AES session keys**, **ephemeral X25519 Diffie-Hellman key exchange (forward secrecy)**, **RSA-PSS digital signatures**, and **replay protection** — with an untrusted relay server that can never read plaintext.

## Project Structure

```
CN-Project/
├── crypto/
│   ├── keys.py          # RSA-2048 + X25519 key generation, PEM I/O
│   ├── aes_gcm.py       # AES-256-GCM encrypt/decrypt
│   ├── rsa_wrap.py      # RSA-OAEP key wrap/unwrap (legacy, retained)
│   ├── signing.py       # RSA-PSS sign/verify
│   └── x25519_ecdh.py   # X25519 ECDH + HKDF key derivation (NEW)
├── utils/
│   ├── classifier.py    # spaCy NER-based component classifier
│   └── serializer.py    # JSON message build/parse, base64 encoding
├── server/
│   ├── store.py         # In-memory user/key store (RSA + X25519)
│   └── server.py        # Asyncio TCP relay server (port 9999)
├── client/
│   ├── message_builder.py  # Classify → ECDH → HKDF → Encrypt → Sign
│   ├── message_reader.py   # Verify → ECDH → HKDF → Decrypt → Replay Check
│   └── client.py           # Interactive CLI client
├── bridge/
│   └── bridge.py        # WebSocket↔TCP bridge for frontend
├── demos/
│   ├── demo_normal.py          # End-to-end encrypted message flow
│   ├── demo_forward_secrecy.py # Forward secrecy demonstration (NEW)
│   ├── demo_replay.py          # Replay attack detection (NEW)
│   ├── demo_server_blind.py    # Server cannot read plaintext
│   ├── demo_tamper.py          # Signature tampering detection
│   ├── demo_partial_key.py     # Partial AES key compromise
│   └── demo_performance.py     # Single-key vs multi-key benchmark
├── keys/                       # Auto-created — stores PEM key files per user
└── requirements.txt
```

## Cryptographic Design

| Layer | Algorithm | Purpose |
|---|---|---|
| Key exchange | X25519 ECDH (ephemeral) | Forward secrecy — per-message key agreement |
| Key derivation | HKDF-SHA256 | Derive per-component AES keys from shared secret |
| Component encryption | AES-256-GCM | Confidentiality + authenticity per component |
| Digital signature | RSA-2048 PSS (SHA-256) | Message integrity + sender authentication |
| Replay protection | Monotonic sequence numbers | Prevent message replay attacks |
| Nonce | 12-byte random | Prevents GCM nonce reuse |
| Encoding | Base64 in JSON | Human-readable wire format |

### Key Types Per User

| Key | Algorithm | Purpose | Lifetime |
|---|---|---|---|
| RSA private key | RSA-2048 | Sign outgoing messages | Long-term |
| RSA public key | RSA-2048 | Verify incoming signatures | Long-term |
| X25519 private key | Curve25519 | Compute DH shared secrets (receiver) | Long-term |
| X25519 public key | Curve25519 | Compute DH shared secrets (sender) | Long-term |
| Ephemeral X25519 key | Curve25519 | Per-message DH exchange | Single message |

## Message Format

```json
{
  "metadata": {
    "sender": "alice",
    "receiver": "bob",
    "timestamp": "2026-04-07T12:00:00+00:00",
    "sequence_number": 1
  },
  "components": [
    { "seq": 1, "type": "name",   "ciphertext": "...", "nonce": "...", "tag": "..." },
    { "seq": 2, "type": "id",     "ciphertext": "...", "nonce": "...", "tag": "..." },
    { "seq": 3, "type": "number", "ciphertext": "...", "nonce": "...", "tag": "..." }
  ],
  "encrypted_keys": {},
  "ephemeral_public_key": "<base64 X25519 public key>",
  "signature": "<RSA-PSS signature over all fields above>"
}
```

### What Changed vs. the Old Format

| Field | Old (RSA-OAEP) | New (X25519 + HKDF) |
|---|---|---|
| `encrypted_keys` | RSA-wrapped AES keys per type | Empty — keys derived via HKDF |
| `ephemeral_public_key` | Did not exist | Sender's per-message X25519 public key |
| `sequence_number` | Did not exist | Monotonic counter for replay protection |
| Signature covers | metadata + components | metadata + components + ephemeral key |

## Encryption Flow

### Sender (message_builder.py)

```
1. Classify message → typed components (name, id, number, text)
2. Generate ephemeral X25519 keypair: (eph_priv, eph_pub)
3. Compute shared secret: X25519(eph_priv, receiver_x25519_pub)
4. Derive master key: HKDF-Extract(shared_secret, salt)
5. Derive per-component AES keys: HKDF-Expand(master, info=type_label)
6. DELETE ephemeral private key immediately
7. Encrypt each component with its type's AES-256-GCM key
8. Increment sequence counter
9. Sign canonical JSON (metadata + components + eph_pub) with RSA-PSS
10. Transmit: { components, metadata, ephemeral_public_key, signature }
```

### Receiver (message_reader.py)

```
1. Verify RSA-PSS signature (covers metadata, components, ephemeral key)
2. Check sequence_number > last_seen[sender] (reject replays)
3. Extract sender's ephemeral public key from message
4. Compute shared secret: X25519(receiver_x25519_priv, sender_eph_pub)
5. Derive same per-component AES keys via HKDF
6. Decrypt each component with its type's key
7. Reconstruct plaintext in sequence order
```

## Installation

```bash
pip install cryptography spacy
python -m spacy download en_core_web_sm
```

## Running the Demos (standalone, no server needed)

```bash
# Normal end-to-end flow (forward secrecy + replay protection)
python demos/demo_normal.py

# Forward secrecy: ephemeral keys, wrong-key rejection
python demos/demo_forward_secrecy.py

# Replay attack: detection and signature binding
python demos/demo_replay.py

# Server blindness: shows what the relay server sees
python demos/demo_server_blind.py

# Tamper detection: ciphertext, metadata, and ephemeral key attacks
python demos/demo_tamper.py

# Partial key compromise: damage containment
python demos/demo_partial_key.py

# Performance: single-key vs multi-key timing + size table
python demos/demo_performance.py
```

## Running the Live Server + Clients

**Terminal 1 — Start the server:**
```bash
python server/server.py
```

**Terminal 2 — Alice:**
```bash
python client/client.py --user alice
```

**Terminal 3 — Bob:**
```bash
python client/client.py --user bob
```

**Alice's prompt:**
```
alice> send bob Hello Bob Smith, your ID is 123456789 and balance is $4500.00
```

Alice's terminal will show:
1. Component classification table
2. Ephemeral key generation + HKDF derivation logs
3. The **full encrypted JSON** (over the wire — all base64 ciphertext, no plaintext)

Bob's terminal will show:
1. Signature verification result (covers ephemeral key + sequence number)
2. Replay protection check (sequence number validation)
3. ECDH shared secret derivation
4. Per-component decryption results
5. Reconstructed plaintext

Server terminal will only show routing logs — **no plaintext, no keys**.

## Security Goals (Protected)

- ✅ Network eavesdropping — all content AES-GCM encrypted
- ✅ Honest-but-curious server — server only sees opaque base64
- ✅ Message tampering — RSA-PSS signature covers entire payload
- ✅ Component reordering — verified by sequence numbers in signature
- ✅ Partial key compromise — each component type has its own AES key
- ✅ **Forward secrecy** — ephemeral X25519 DH, keys deleted after use
- ✅ **Replay attacks** — monotonic sequence numbers with signature binding
- ✅ **Ephemeral key substitution** — ephemeral public key is signature-bound
- ✅ **Sequence number tampering** — sequence number is signature-bound

## Security Improvements Over Previous Version

### Forward Secrecy (X25519 Ephemeral DH)

**Before:** AES session keys were wrapped with RSA-OAEP using the receiver's long-term public key. If the private key was ever compromised, ALL previously captured messages could be decrypted.

**After:** Each message generates a fresh X25519 keypair. The shared secret is computed via ECDH, and AES keys are derived via HKDF. The ephemeral private key is deleted immediately. Even if the long-term X25519 key is compromised, past sessions remain secure because:
- The shared secret depends on BOTH the ephemeral and long-term key
- The ephemeral private key no longer exists
- Each message's keys are cryptographically independent

### Replay Protection (Sequence Numbers + Signature Binding)

**Before:** No replay detection. An attacker could resend captured messages.

**After:** Each message includes a monotonically increasing `sequence_number` in metadata. The receiver tracks `last_seen_sequence[sender]` and rejects:
- Duplicate messages (same sequence number)
- Older messages (lower sequence number)

The sequence number is covered by the RSA-PSS signature, so an attacker **cannot** modify it without invalidating the signature. Similarly, the `ephemeral_public_key` is signature-bound, preventing key substitution attacks.

## Security Limitations (Out of Scope)

- ❌ Compromised private keys — no revocation mechanism
- ❌ Endpoint malware — application-layer security only
- ❌ Metadata leakage — sender, receiver, timestamp, and sequence are visible
