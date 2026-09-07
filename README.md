# Author Identity Layer

> Fast, cryptographically signed self-sovereign identity without phone numbers or email addresses.

---

## Features
- **Phone & Email Free**: Identities are bound to user-chosen usernames (`[a-z0-9_]{3,32}`) and signed with **Ed25519** public keys.
- **Embedded Web App Shell**: Responsive modern UI served directly by the relay (`http://localhost:8080/`) with **WebAuthn Biometric Unlock** (Windows Hello, Touch ID, Fingerprint).
- **Relay Messaging Queue**: End-to-end signed ephemeral message queue (`/v1/send`, `/v1/inbox`, `/v1/ack`) with auto-deletion after delivery.
- **Pure-Go Relay**: Single static binary with embedded SQLite (`modernc.org/sqlite`). 100% CGO-free, zero-config deployment.
- **Replay Protection**: Nonce deduplication cache + 5-minute sliding timestamp window.
- **Key Lifecycle Management**: Full support for `CLAIM`, `RESOLVE`, `ROTATE`, and `REVOKE`.
- **Client & CLI**: Built-in CLI tool (`author`) with local profile management and per-device cap (max 3 identities).
- **Audit Logging**: Immutable SQLite audit log tracking every key state transition and signature.

---

## Architecture

```
                                  +-----------------------+
                                  |    author CLI / App   |
                                  |  (Local Ed25519 Keys) |
                                  +-----------+-----------+
                                              |
                   HTTPS POST /v1/claim       |
                   HTTPS GET  /v1/resolve     | Signed Payloads
                   HTTPS POST /v1/rotate      |
                   HTTPS POST /v1/revoke      |
                                              v
                              +-------------------------------+
                              |       Go Relay Server         |
                              |-------------------------------|
                              | - Ed25519 Signature Verifier  |
                              | - Replay Nonce Cache          |
                              | - In-memory IP Rate Limiter   |
                              +---------------+---------------+
                                              |
                                              v
                                   +---------------------+
                                   |    SQLite Store     |
                                   |  (WAL mode enabled) |
                                   +---------------------+
```

---

## Quick Start

### 1. Build Binaries
```bash
# Build Relay
go build -o relay.exe ./cmd/relay

# Build CLI
go build -o author.exe ./cmd/author
```

### 2. Start Local Relay
```bash
./relay.exe
# Server runs on port :8080 (SQLite file in ./data/author.db)
```

### 3. Use the CLI
```bash
# Generate standalone keypair
./author.exe keygen

# Claim a new username (creates Ed25519 keypair and registers on relay)
./author.exe claim alice

# Resolve public key and status
./author.exe resolve alice

# List local identities (max 3 per install)
./author.exe list

# Rotate key to version 2
./author.exe rotate alice

# Export recovery private key
./author.exe export alice

# Permanently revoke identity
./author.exe revoke alice
```

---

## API Specification

### Health Check
- **`GET /health`**
- Response: `{"status":"ok", "uptime_seconds": 120, "total_claims": 5, "version": "0.1.0"}`

### Claim Identity
- **`POST /v1/claim`**
- Payload:
  ```json
  {
    "username": "alice",
    "pubkey": "3d4f...",
    "timestamp": 1788775200,
    "nonce": "a1b2c3d4e5f60718",
    "sig": "9a8b..."
  }
  ```
- Canonical message format: `"author-id:v1:CLAIM:<username>:<pubkey>:<timestamp>:<nonce>"`

### Resolve Identity
- **`GET /v1/resolve/:user`**
- Response:
  ```json
  {
    "username": "alice",
    "pubkey": "3d4f...",
    "status": "active",
    "version": 1,
    "created_at": "2026-09-07T10:00:00Z",
    "updated_at": "2026-09-07T10:00:00Z"
  }
  ```

### Rotate Key
- **`POST /v1/rotate`**
- Canonical message format: `"author-id:v1:ROTATE:<username>:<old_pubkey>:<new_pubkey>:<version>:<timestamp>:<nonce>"`
- Signed by old key; supports optional dual-signing by new key (`new_sig`).

### Revoke Identity
- **`POST /v1/revoke`**
- Canonical message format: `"author-id:v1:REVOKE:<username>:<pubkey>:<timestamp>:<nonce>"`
- Permanently locks the username.

---

## Testing

Run unit and end-to-end integration tests:
```bash
go test -v ./...
```
