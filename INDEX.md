# Documentation Index

- [README.md](README.md): relay capabilities, supported NIPs, limits, and all runtime options.
- [QUICKSTART.md](QUICKSTART.md): Windows build, local execution, deployment, and validation.
- [NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md): NIP implementation status and compatibility audit.

## 📚 Documentation

Start here based on your needs:

### For Beginners
1. **[QUICKSTART.md](QUICKSTART.md)** - Installation and basic usage
2. **[NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md)** - NIP implementation status
3. **[README.md](README.md)** - Project overview and NIP support table

### For Developers
1. **[API_REFERENCE.md](API_REFERENCE.md)** - Complete API documentation
2. **[IMPLEMENTATION.md](IMPLEMENTATION.md)** - Architecture overview
3. Source code in `src/` directory

### For Integration
1. **[src/server.c](src/server.c)** - Server implementation
2. **[NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md)** - NIP wiring status

---

## 📁 Project Structure

```
nostrogotho/
│
├── 📄 Root Documentation
│   ├── README.md              ← Project overview, NIP support, configuration
│   ├── QUICKSTART.md          ← Windows build, local execution, deployment
│   ├── NOSTR_COMPATABILITY.md ← NIP implementation status (living document)
│   ├── IMPLEMENTATION.md      ← Architecture and contributor workflow
│   ├── API_REFERENCE.md       ← Public C interfaces
│   └── NOSTR.md               ← Nostr protocol message types
│
├── 🔨 Build System
│   ├── nob.c                  ← Two-stage build driver (gcc → nob → main.exe)
│   ├── nob.h                  ← Nob header
│   └── build/                 ← Generated build output
│
├── 📁 Source Code (src/)
│   ├── nostrogotho.h/c        ← Core data structures (event_t, tag_t, filter_t)
│   ├── crypto.h/c             ← Cryptographic ops (sha256, signature_verify, check_event)
│   ├── storage.h/c            ← SQLite3 layer (insert_record, send_records, indexes)
│   ├── server.c               ← WebSocket server, event loop, NIP plugin architecture
│   └── main.c                 ← Example main entry point
│
├── 📁 NIP Plugins (src/nips/)
│   ├── nip01.c              ← Basic Protocol Flow, replaceable events, addressable events
│   ├── nip09.c              ← Event Deletion Request
│   ├── nip11.c              ← Relay Information Document (HTTP)
│   ├── nip13.c              ← Proof of Work
│   ├── nip17.c              ← Private Direct Messages
│   ├── nip26.c              ← Delegated Event Signing
│   ├── nip40.c              ← Expiration Timestamp
│   ├── nip42.c              ← Client Authentication
│   ├── nip45.c              ← Event Counts (COUNT queries)
│   ├── nip62.c              ← Request to Vanish
│   ├── nip67.c              ← EOSE Completeness Hint
│   ├── nip_template.c           - New-NIP scaffold (excluded from build)
│   └── nip_capability.c/h          - Capability registry + composition
│
├── 📁 Third-party (thirdparty/)
│   ├── sqlite3.c/h            ← SQLite3 source amalgamation
│   ├── mongoose/              ← WebSocket library (bundled)
│   └── secp256k1/             ← Schnorr signature library
│
└── 📄 Additional Files
    ├── TODO.md                ← TODO list
    ├── nob.c README.md        ← Nob build system docs
    ├── QUICKSTART.md          ← Quick start guide
    └── nostrogotho.sqlite     ← SQLite database (WAL mode)
```

---

## 🎯 Quick Navigation

### Core Modules

| Module | Purpose | Lines | Key Functions |
|--------|---------|-------|---------------|
| **nostrogotho.h/c** | Data structures | 229 | `event_alloc`, `filter_alloc`, memory management |
| **crypto.h/c** | Cryptography | 358 | `sha256`, `signature_verify`, `check_event` |
| **storage.h/c** | Database | 476 | `insert_record`, `send_records`, SQLite ops |
| **server.c** | WebSocket + NIP plugins | 295+ | mongoose event handler, event loop, plugin hooks |
| **NIP Plugins** | Protocol-specific logic | varies | nip01, nip09, nip11, nip13, nip17, nip26, nip40, nip42, nip45, nip62, nip67 |

### Total: ~1,400+ lines of C99 code

---

## 🚀 Getting Started

### 1. First Time Setup
```powershell
# Read this first
cat QUICKSTART.md

# Build the nob driver
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe

# Run the nob builder
.\nob.exe

# Run the relay
.\build\main.exe -service-url wss://relay.example.com
```

### 2. Understanding the Code
- Review [NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md) for NIP implementation status
- Check [IMPLEMENTATION.md](IMPLEMENTATION.md) for architecture overview
- Examine [API_REFERENCE.md](API_REFERENCE.md) for public C interfaces

### 3. NIP Support Status
- See [NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md) summary table for current NIP status
- All NIPs listed as ✅ Complete or 🟡 Partial with detailed integration notes

---

## 📊 NIP Support Summary

Implemented NIPs (as of 2026-09-03 audit):

| NIP | Title | Status | Wired into server |
|-----|-------|--------|-------------------|
| 01 | Basic Protocol Flow | ✅ Complete | Yes |
| 09 | Event Deletion Request | ✅ Complete | Yes |
| 11 | Relay Information Document | ✅ Complete | Yes (HTTP) |
| 13 | Proof of Work | ✅ Complete | Yes (via NIP-01) |
| 16 | Event Treatment | ✅ Complete (→ NIP-01) | Yes |
| 17 | Private Direct Messages | ✅ Complete | Yes |
| 26 | Delegated Event Signing | ✅ Complete | Yes (via crypto) |
| 33 | Parameterized Replaceable Events | ✅ Complete (→ NIP-01) | Yes |
| 40 | Expiration Timestamp | ✅ Complete | Yes |
| 42 | Client Authentication | ✅ Complete | Yes |
| 45 | Event Counts | ✅ Complete | Yes |
| 62 | Request to Vanish | ✅ Complete | Yes |
| 67 | EOSE Completeness Hint | ✅ Complete | Yes |

**Target `supported_nips`:** `[1, 9, 11, 13, 16, 17, 26, 33, 40, 42, 45, 62, 67]`

---

## 📦 Build Configuration

The project uses [nob](nob.c) - a two-stage build driver. Build from repository root:

```powershell
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
.\nob.exe
```

`nob` compiles the relay and SQLite amalgamation directly, linking bundled dependencies from `thirdparty/install`.

**Output:** `build/nostrogotho.exe`

**Configuration options** (via command-line or environment variables):
- `-database PATH`, `--db PATH` → `DATABASE_URL` → `./nostrogotho.sqlite`
- `-port PORT` → `7447` (default listener port)
- `-service-url URL` → `SERVICE_URL` (public URL for NIP-42 and NIP-62)
- `-min-pow BITS` → `MIN_POW_DIFFICULTY` → `0` (disable PoW)
- `-created-at-limit SECONDS` → `CREATED_AT_LOWER_LIMIT` → `0` (disable age limit)
- `-created-at-upper-limit SECONDS` → `CREATED_AT_UPPER_LIMIT` → `900` (max future timestamp)

---

## 🎯 Quick Navigation

### Core Modules

| Module | Purpose | Lines | Key Functions |
|--------|---------|-------|---|
| **nostrogotho.h/c** | Data structures | 229 | `event_alloc`, `filter_alloc`, memory management |
| **crypto.h/c** | Cryptography | 358 | `sha256`, `signature_verify`, `check_event` |
| **storage.h/c** | Database | 476 | `insert_record`, `send_records`, SQLite ops |
| **server.c** | WebSocket | 295 | mongoose event handler, event loop |

### Total: 1,400+ lines of C99 code

---

## 🚀 Getting Started

### 1. First Time Setup
```bash
# Read this first
cat QUICKSTART.md

# Install dependencies
sudo apt-get install libsqlite3-dev libssl-dev libsecp256k1-dev cmake

# Build
mkdir build && cd build && cmake .. && make
```

### 2. Understanding the Code
```bash
# Read architecture
cat IMPLEMENTATION.md

# Study examples
cat examples/example.c

# Browse API
cat API_REFERENCE.md
```

### 3. Running the Server
```bash
# Start server
./nostr_server --port 8080 --db file:nostr.db

# Test with another terminal
wscat -c ws://localhost:8080
```

---

## 📖 Documentation Map

```
QUICKSTART.md
├── Installation
├── Basic Usage
├── File Organization
└── Common Tasks

API_REFERENCE.md
├── Core Modules (nostrogotho, crypto, storage)
├── Function Reference
├── Usage Examples
├── Constants
└── Performance Notes

IMPLEMENTATION.md
├── Architecture
├── Components
├── Dependencies
├── Database Schema
├── Nostr Protocol
└── Limitations

PROJECT_SUMMARY.md
├── Project Status
├── Deliverables
├── Milestones
└── Next Steps
```

---

## 💡 Key Features

✅ **C99 Compliant** - Pure C implementation, no C++ dependencies
✅ **Cryptography** - Schnorr signatures, SHA256, delegation verification
✅ **Database** - SQLite3 with proper indexing and optimization
✅ **Server** - Mongoose server
✅ **Well-Documented** - Comprehensive API and examples
✅ **Production-Ready** - Error handling, memory management, SQL injection protection

---

## 🔧 Development Workflow

### Adding a New Feature
1. Identify which module to modify (nostrogotho, crypto, storage, server)
2. Update header file (.h) with new declarations
3. Implement in source file (.c)
4. Add examples to examples/example.c
5. Update API_REFERENCE.md
6. Rebuild: `cd build && cmake .. && make`

### Testing
```bash
# Compile and run example
cd build
make
./test_main

# Or build custom tests
gcc -std=c99 -o mytest mytest.c -lnostrogotho -lsqlite3 -lcrypto -lsecp256k1
```

### Performance Profiling
```bash
# Run with profiling
valgrind --leak-check=full ./nostr_server

# Check performance
perf record ./nostr_server
perf report
```

---

## 📋 Checklist for New Users

- [ ] Read QUICKSTART.md
- [ ] Install dependencies
- [ ] Build the project
- [ ] Run examples/example.c
- [ ] Read API_REFERENCE.md
- [ ] Start hacking!

---

## 🤝 Integration Points

### Adding Nostr Protocol Support
- Edit `server.c` to parse JSON messages
- Implement REQ, EVENT, CLOSE handlers
- Use storage functions to query/store events

### Adding Persistence
- Change database path in server main()
- Or use CMake variable: `-DDEFAULT_DB_PATH=/var/lib/nostr/events.db`

### Adding Authentication
- Extend filter_t to include user context
- Add permission checks in send_records callback
- Use crypto functions to verify client pubkeys

---

## 📞 Reference

### External Resources
- [Nostr Protocol Spec](https://github.com/nostr-protocol/nostr)
- [SQLite3 Documentation](https://sqlite.org/docs.html)
- [OpenSSL EVP](https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestInit.html)
- [secp256k1](https://github.com/bitcoin-core/secp256k1)
- [mongoose](https://mongoose.ws/)

### Internal References
- See API_REFERENCE.md for function signatures
- See IMPLEMENTATION.md for database schema
- See examples/example.c for code patterns
- See src/*.c for implementation details

---

## ✨ Project Status

**Status**: ✅ **COMPLETE** and ready for:
- Integration into Nostr relay implementations
- Extension with additional features
- Deployment in production environments
- Further optimization and tuning

---

**Last Updated**: 2026-09-01
**Version**: 1.0.0
**Language**: C99
**License**: Experimental use
