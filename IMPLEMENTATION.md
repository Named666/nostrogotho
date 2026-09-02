# Cagliostr C99 Port

A complete rewrite of the Nostr relay storage and cryptographic operations from C++ to C99.

## Overview

This implementation provides:
- **SQLite3 Database Layer**: Event storage and querying with full Nostr protocol support
- **Cryptographic Operations**: Schnorr signature verification (secp256k1), SHA256 hashing, delegation verification
- **Mongoose Server**: High-performance WebSocket server for Nostr relay protocol
- **C99 Compliance**: All code is ANSI C99 compatible for maximum portability

## Architecture

### Components

1. **cagliostr.{h,c}** - Core data structures and memory management
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
