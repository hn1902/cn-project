# Selective Component-Level End-to-End Encryption

A secure client–server messaging system that implements **hybrid encryption**, **per-component AES session keys**, **RSA-OAEP key wrapping**, and **RSA-PSS digital signatures** — with an untrusted relay server that can never read plaintext.

## Project Structure

```
CN-Project/
├── crypto/
│   ├── keys.py         # RSA-2048 key generation, PEM I/O
│   ├── aes_gcm.py      # AES-256-GCM encrypt/decrypt
│   ├── rsa_wrap.py     # RSA-OAEP key wrap/unwrap
│   └── signing.py      # RSA-PSS sign/verify
├── utils/
│   ├── classifier.py   # Rule-based component classifier (regex)
│   └── serializer.py   # JSON message build/parse, base64 encoding
├── server/
│   ├── store.py        # In-memory user/key store (asyncio-safe)
│   └── server.py       # Asyncio TCP relay server (port 9999)
├── client/
│   ├── message_builder.py  # Classify → Encrypt → Sign pipeline
│   ├── message_reader.py   # Verify → Unwrap → Decrypt pipeline
│   └── client.py           # Interactive CLI client
├── demos/
│   ├── demo_normal.py       # End-to-end encrypted message flow
│   ├── demo_server_blind.py # Server cannot read plaintext
│   ├── demo_tamper.py       # Signature tampering detection
│   ├── demo_partial_key.py  # Partial AES key compromise
│   └── demo_performance.py  # Single-key vs multi-key benchmark
├── keys/                    # Auto-created — stores PEM key files per user
└── requirements.txt
```

## Cryptographic Design

| Layer | Algorithm | Purpose |
|---|---|---|
| Component encryption | AES-256-GCM | Confidentiality + authenticity per component |
| Key wrapping | RSA-2048 OAEP (SHA-256) | Secure session key delivery |
| Digital signature | RSA-PSS (SHA-256) | Message integrity + authentication |
| Nonce | 12-byte random | Prevents GCM nonce reuse |
| Encoding | Base64 in JSON | Human-readable wire format |

## Message Format

```json
{
  "metadata": { "sender": "alice", "receiver": "bob", "timestamp": "..." },
  "components": [
    { "seq": 1, "type": "name",   "ciphertext": "...", "nonce": "...", "tag": "..." },
    { "seq": 2, "type": "id",     "ciphertext": "...", "nonce": "...", "tag": "..." },
    { "seq": 3, "type": "number", "ciphertext": "...", "nonce": "...", "tag": "..." }
  ],
  "encrypted_keys": {
    "name":   "<RSA-OAEP wrapped AES key>",
    "id":     "<RSA-OAEP wrapped AES key>",
    "number": "<RSA-OAEP wrapped AES key>"
  },
  "signature": "<RSA-PSS signature over all fields above>"
}
```

## Installation

```bash
pip install cryptography
```

## Running the Demos (standalone, no server needed)

```bash
# Normal end-to-end flow (shows encrypted payload + decrypted output)
python demos/demo_normal.py

# Server blindness: shows what the relay server sees
python demos/demo_server_blind.py

# Tamper detection: all 3 attacks must fail
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
2. The **full encrypted JSON** (over the wire — all base64 ciphertext, no plaintext)

Bob's terminal will show:
1. Signature verification result
2. Per-component decryption results
3. Reconstructed plaintext

Server terminal will only show routing logs — **no plaintext**.

## Component Classifier

| Pattern | Classified As |
|---|---|
| 8+ consecutive digits | `id` |
| `$amount` or decimal number | `number` |
| Single capitalized word | `name` |
| Everything else | `text` (fallback / high-sensitivity) |

Adjacent tokens of the same type are merged into one span.

## Security Goals (Protected)

- ✅ Network eavesdropping — all content AES-GCM encrypted
- ✅ Honest-but-curious server — server only sees opaque base64
- ✅ Message tampering — RSA-PSS signature covers entire payload
- ✅ Component reordering — verified by sequence numbers in signature
- ✅ Partial key compromise — each component type has its own AES key

## Security Limitations (Out of Scope for This Project)

- ❌ Compromised private keys — no revocation mechanism
- ❌ Endpoint malware — application-layer security only
- ❌ Metadata leakage — sender, receiver, and timestamp are visible
- ❌ Replay attacks — no nonce/timestamp validation at server
