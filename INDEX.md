# Documentation Index

- [README.md](README.md): relay capabilities, supported NIPs, limits, and all runtime options.
- [QUICKSTART.md](QUICKSTART.md): Windows build, local execution, deployment, and validation.
- [IMPLEMENTATION.md](IMPLEMENTATION.md): architecture and contributor workflow.
- [API_REFERENCE.md](API_REFERENCE.md): public C interfaces and ownership rules.
- [NOSTR.md](NOSTR.md): Nostr protocol message types and relay applicability.

Historical completion and reimplementation reports were consolidated into these
current guides because they described an earlier, incomplete C99 port and a
nonexistent CMake build.

## 📚 Documentation

Start here based on your needs:

### For Beginners
1. **[QUICKSTART.md](QUICKSTART.md)** - Installation and basic usage
2. **[examples/example.c](examples/example.c)** - Working code examples
3. **[IMPLEMENTATION.md](IMPLEMENTATION.md)** - Architecture overview

### For Developers
1. **[API_REFERENCE.md](API_REFERENCE.md)** - Complete API documentation
- [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) - Project details
3. Source code in `src/` directory

### For Integration
1. **[CMakeLists.txt](CMakeLists.txt)** - Build configuration
2. **[src/server.c](src/server.c)** - Server implementation

---

## 📦 Project Structure

```
nostrogotho/
│
├── 📄 Documentation
│   ├── QUICKSTART.md           ← Start here!
│   ├── API_REFERENCE.md        ← Complete API
│   ├── IMPLEMENTATION.md       ← Architecture
│   ├── PROJECT_SUMMARY.md   ← Project overview
│   └── README.md              ← Original project
│
├── 🔨 Build System
│   ├── CMakeLists.txt         ← Build config
│   ├── build.sh               ← Build script
│   ├── nob.c                  ← Nob build system
│   └── nob.h                  ← Nob header
│
├── 📁 Source Code (src/)
│   ├── nostrogotho.h/c          ← Core data structures
│   ├── crypto.h/c             ← Cryptographic ops
│   ├── storage.h/c            ← SQLite3 layer
│   ├── server.c               ← WebSocket server
│   └── main.c                 ← Example main
│
├── 📁 Examples (examples/)
│   └── example.c              ← Usage examples
│
├── 📁 Third-party (thirdparty/)
│   ├── sqlite3.c/h            ← SQLite3 source
│   └── mongoose/              ← WebSocket library
```

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
