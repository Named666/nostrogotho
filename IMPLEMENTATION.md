# Implementation Guide

## Architecture

| Module | Responsibility |
| --- | --- |
| [src/main.c](src/main.c) | Parses runtime configuration; initializes crypto, storage, and the server. |
| [src/server.c](src/server.c) | HTTP metadata, WebSocket protocol frames, subscription state, authentication, and event lifecycle rules. |
| [src/json_util.c](src/json_util.c) | Bounded JSON parsing for protocol arrays, filters, and events; JSON serialization. |
| [src/crypto.c](src/crypto.c) | SHA-256, Schnorr signatures, NIP-26 delegation, and NIP-13 PoW validation. |
| [src/storage.c](src/storage.c) | SQLite schema, retrieval, queries, replacement, deletion, and expiration. |
| [src/nostrogotho.c](src/nostrogotho.c) | Owned event/filter/tag allocation utilities. |

The event loop and SQLite context are single-threaded. Do not call the storage
context concurrently without adding synchronization and testing it.

## Event Flow

1. `server.c` parses a WebSocket JSON array and dispatches its command.
2. `json_util.c` validates the event shape and preserves tag JSON.
3. `crypto.c` verifies the event ID, signature, and delegation tags.
4. `server.c` enforces size, timestamp, PoW, authorization, and event-kind
   lifecycle rules.
5. `storage.c` persists/query events; `server.c` sends matching subscriptions.

Keep the stored-query and live-subscription paths behaviorally aligned,
especially for NIP-17 gift wraps and filter matching.

## Contribution Rules

- Preserve C99 compatibility.
- Treat all network data and SQLite text as length-bounded, untrusted input.
- Use JSON serializers for protocol strings; do not interpolate event content
  into a JSON frame.
- Keep schema/index migrations explicit and backward-compatible.
- Update [README.md](README.md), [API_REFERENCE.md](API_REFERENCE.md), and
  [NOSTR.md](NOSTR.md) when externally visible behavior changes.
- Do not edit vendored `thirdparty/` code for relay behavior without documenting
  the upstream version and local patch rationale.

## Validation

Run this after source changes:

```powershell
gcc -std=c99 -Wall -Wextra -Wpedantic -I. -Isrc -Ithirdparty -Ithirdparty/mongoose -fsyntax-only src/main.c src/server.c src/storage.c src/json_util.c src/crypto.c src/nostrogotho.c
git diff --check
```

Then rebuild with `gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe`
and `.\nob.exe`. The vendored secp256k1 build can emit warnings; investigate
new warnings from project `src/` files before accepting a change.

A complete rewrite of the Nostr relay storage and cryptographic operations from C++ to C99.

## Overview

This implementation provides:
- **SQLite3 Database Layer**: Event storage and querying with full Nostr protocol support
- **Cryptographic Operations**: Schnorr signature verification (secp256k1), SHA256 hashing, delegation verification
- **Mongoose Server**: High-performance WebSocket server for Nostr relay protocol
- **C99 Compliance**: All code is ANSI C99 compatible for maximum portability

## Architecture

### Components

1. **nostrogotho.{h,c}** - Core data structures and memory management
   - Event representation
   - Filter/query structures
   - Tag handling

2. **crypto.{h,c}** - Cryptographic operations
   - SHA256 hashing (OpenSSL)
   - Schnorr signature verification (secp256k1)
   - Event validation
   - Delegation checking (NIP-26)
   - Proof of work calculation

3. **storage.{h,c}** - SQLite3 database layer
   - Event CRUD operations
   - Complex query filtering
   - Database initialization and schema management
   - LIKE-based tag searching

4. **server.c** - Mongoose relay server
   - WebSocket protocol handling
   - Event message reception and transmission
   - System state management

## Building

### Requirements
- CMake 3.10+
- SQLite3 development libraries
- OpenSSL development libraries
- secp256k1 development libraries

### Debian/Ubuntu
```bash
sudo apt-get install libsqlite3-dev libssl-dev libsecp256k1-dev
```

### macOS
```bash
brew install sqlite3 openssl secp256k1
```

### Build
```bash
mkdir build
cd build
cmake ..
make
make install
```

## Usage

### Running the server
```bash
./nostr_server --port 8080 --db file:nostr.db
```

### Options
- `--port NUM` - WebSocket port (default: 8080)
- `--db PATH` - SQLite database path (default: file:nostr.db?mode=memory)
- `--help` - Show help message

## Database Schema

```sql
CREATE TABLE event (
    id TEXT NOT NULL,              -- Event ID (64-char hex)
    pubkey TEXT NOT NULL,          -- Author public key (64-char hex)
    created_at INTEGER NOT NULL,   -- Creation timestamp
    kind INTEGER NOT NULL,         -- Event kind/type
    tags TEXT NOT NULL,            -- JSON array of tags
    content TEXT NOT NULL,         -- Event content
    sig TEXT NOT NULL              -- Schnorr signature (128-char hex)
);

-- Indexes for performance
CREATE UNIQUE INDEX ididx ON event(id);
CREATE INDEX pubkeyprefix ON event(pubkey);
CREATE INDEX timeidx ON event(created_at DESC);
CREATE INDEX kindidx ON event(kind);
CREATE INDEX kindtimeidx ON event(kind,created_at DESC);
```

## Nostr Protocol Support

Currently implements:
- Event storage and retrieval
- Query filtering (ids, authors, kinds, since, until, search)
- Signature verification
- Delegation checking (NIP-26)
- Event expiration handling
- Replacement events by kind (kind-based deletion with timestamps)

## Implementation Notes

### Cryptography
- Uses secp256k1 for Schnorr signatures (Bitcoin standard)
- Uses OpenSSL EVP interface for SHA256
- All hexadecimal conversions follow Nostr specification

### Database
- WAL mode enabled for concurrent access
- Proper indexes for common queries
- LIKE queries escaped for injection prevention
- Memory optimization with cache_size pragma

### Memory Management
- All allocations checked for NULL
- Proper cleanup on errors
- No memory leaks detected (verified with valgrind)

## Limitations & TODO

- [ ] Full Nostr protocol message parsing (REQ, EVENT, CLOSE)
- [ ] Authentication support
- [ ] Subscription management
- [ ] Client connection tracking
- [ ] Performance optimization for large databases
- [ ] Logging framework
- [ ] Configuration file support
- [ ] Metrics/monitoring

## Protocol Specification

For detailed Nostr protocol information, see:
- [Nostr Protocol](https://nostr.com/)
- [Nostr Implementation Possibilities](https://github.com/nostr-protocol/nostr)

## License

This implementation is provided as-is for experimental use.
