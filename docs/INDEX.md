# Documentation Index

- [README.md](README.md): relay capabilities, supported NIPs, limits, and all runtime options.
- [QUICKSTART.md](QUICKSTART.md): Windows build, local execution, deployment, and validation.
- [NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md): NIP implementation status and compatibility audit.

## 📚 Documentation

Start here based on your needs:

### For Beginners
1. **[QUICKSTART.md](QUICKSTART.md)** - Installation and basic usage
2. **[NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md)** - NIP implementation status
3. **[README.md](../README.md)** - Project overview and NIP support table

### For Developers
1. **[API_REFERENCE.md](API_REFERENCE.md)** - Complete API documentation
2. **[PLAN.md](../PLAN.md)** - Architecture refactor plan and completion criteria
3. Source code in `src/` directory

### For Integration
1. **[src/transport/server.c](../src/transport/server.c)** - Pure transport adapter
2. **[src/relay/relay.c](../src/relay/relay.c)** - Relay runtime + policy dispatch
3. **[NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md)** - NIP wiring status

---

## 📁 Project Structure

```
nostrogotho/
│
├── 📄 Root Documentation
│   ├── README.md              ← Project overview, NIP support, configuration
│   ├── QUICKSTART.md          ← Windows build, local execution, deployment
│   ├── NOSTR_COMPATABILITY.md ← NIP implementation status (living document)
│   ├── PLAN.md                ← Architecture refactor plan and status
│   ├── NOB_HOTRELOAD.md       ← Hot-reload build and supervisor
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
│   ├── relay.h/c              ← Relay runtime + policy dispatch
│   ├── connection_session.h/c ← Connection/session abstraction
│   ├── transport/server.h/c   ← Pure Mongoose transport adapter
│   ├── protocol/              ← Protocol parsing/serialization
│   ├── protocol/                 ← Generic event/tag utilities
│   ├── subscriptions/         ← Subscription lifecycle + matching
│   └── nips/                  ← NIP capability modules (01, 09, 11, 13, 17, 26, 40, 42, 45, 62, 67)
│       ├── nip_capability.c/h ← Capability registry + composition
│       └── nip_template.c     ← New-NIP scaffold (excluded from build)
│
├── 📁 Third-party (thirdparty/)
│   ├── sqlite3.c/h            ← SQLite3 source amalgamation
│   ├── mongoose/              ← WebSocket library (bundled)
│   └── secp256k1/             ← Schnorr signature library
│
└── 📄 Additional Files
    ├── TODO.md                ← TODO list
    ├── nob.c README.md        ← Nob build system documentation
    └── tests/                 ← Unit + integration tests
```

---

## 🎯 Quick Navigation

### Core Modules

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| **nostrogotho.h/c** | Data structures | `event_alloc`, `filter_alloc`, memory management |
| **crypto.h/c** | Cryptography | `sha256`, `signature_verify`, `check_event` |
| **storage.h/c** | Database | `insert_record`, `find_events`, `upsert_replaceable`, SQLite ops |
| **relay.h/c** | Relay runtime + policy dispatch | `relay_create`, `relay_run`, NIP capability composition |
| **connection_session.h/c** | Connection/session abstraction | Session creation/auth state management |
| **transport/server.h/c** | Pure Mongoose transport adapter | Event loop, WebSocket handling (no NIP logic) |
| **protocol/** | Protocol parsing/serialization | `protocol_parse_client_message`, `protocol_serialize_*` |
| **protocol/** | Generic event/tag utilities | `event_tag_get`, `event_tag_value`, `event_tag_has*` |
| **subscriptions/** | Subscription lifecycle + matching | Subscription creation/matching/delivery |
| **nips/** | NIP capability modules | Capability registration via constructor |

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
- Check [PLAN.md](../PLAN.md) for architecture overview and completion criteria
- Examine [API_REFERENCE.md](API_REFERENCE.md) for public C interfaces

### 3. NIP Support Status

- See [NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md) summary table for current NIP status
- All NIPs listed as ✅ Complete with detailed integration notes

---

## 📊 NIP Support Summary

Implemented NIPs (as of 2026-10-02):

| NIP | Title | Capabilities | Status |
|-----|-------|--------------|--------|
| 01 | Basic Protocol Flow | kind_handler (replaceable/addressable) | ✅ Complete |
| 09 | Event Deletion Request | kind_handler (kind 5 deletion) | ✅ Complete |
| 11 | Relay Information Document | lifecycle + metadata | ✅ Complete |
| 13 | Proof of Work | lifecycle + publication_policy (PoW) | ✅ Complete |
| 17 | Private Direct Messages | delivery_policy + protocol_response (auth hint) | ✅ Complete |
| 26 | Delegated Event Signing | publication_policy (delegation) | ✅ Complete |
| 40 | Expiration Timestamp | publication_policy + delivery_policy + maintenance (expiry/GC) | ✅ Complete |
| 42 | Client Authentication | lifecycle + connection + message_intercept + publication_policy + protocol_response (challenge) | ✅ Complete |
| 45 | Event Counts | protocol_response (COUNT) | ✅ Complete |
| 62 | Request to Vanish | kind_handler (kind 62 vanish) | ✅ Complete |
| 67 | EOSE Completeness Hint | protocol_response (EOSE hints) | ✅ Complete |

**Target `supported_nips`:** `[1, 9, 11, 13, 17, 26, 40, 42, 45, 62, 67]`

---

## 📦 Build Configuration

The project uses [nob](nob.c) - a two-stage build driver. Build from repository root:

```powershell
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
.\nob.exe
```

`nob` compiles the relay and SQLite amalgamation directly, linking bundled dependencies from `thirdparty/`.

**Output:** `build/main.exe`

**Configuration options** (via command-line or environment variables):
- `-database PATH`, `--db PATH` → `DATABASE_URL` → `./nostrogotho.sqlite`
- `-port PORT` → `7447` (default listener port)
- `-service-url URL` → `SERVICE_URL` (public URL for NIP-42 and NIP-62)
- `-min-pow BITS` → `MIN_POW_DIFFICULTY` → `0` (disable PoW)
- `-created-at-lower-limit SECONDS` → `CREATED_AT_LOWER_LIMIT` → `0` (disable age limit)
- `-created-at-upper-limit SECONDS` → `CREATED_AT_UPPER_LIMIT` → `900` (max future timestamp)

---

## 🔧 Development Workflow

### Adding a New Feature

1. Identify which module to modify (nostrogotho, crypto, storage, relay, protocol, subscriptions, transport, nips)
2. Update header file (.h) with new declarations
3. Implement in source file (.c)
4. Update [API_REFERENCE.md](API_REFERENCE.md)
5. Rebuild: `.\nob.exe`

### Adding a New NIP

1. Copy `src/nips/nip_template.c` → `src/nips/nipXX.c`
2. Rename `nipxx_` symbols
3. Keep only capability types your NIP needs
4. Build — no other edits needed

### Testing

```powershell
# Build and run the relay
.\nob.exe
.\build\main.exe --help
```

### Performance Profiling

Use standard Windows profiling tools or build with debug symbols for analysis.

---

## 🔧 Architecture Boundaries

The relay enforces these explicit architectural boundaries:

1. **Transport** - `transport/server.c`: Pure Mongoose event loop + WebSocket framing. No NIP logic, no SQLite, no subscription state, no filter matching, no policy decisions.

2. **Protocol** - `protocol/`: Message parsing, serialization, typed command dispatch via `relay_event_handler`. Nostr commands: EVENT, REQ, COUNT, CLOSE, AUTH.

3. **Model** - `protocol/`: Generic event/tag utilities (`event_has_tag`, `event_get_tag_value`, `event_tag_element`). Not in a NIP namespace.

4. **Validation** - `validation/`: Event validation pipeline with `validation_result_t`. Structure, ID, signature, delegation, relay timestamps, relay PoW. Separate from cryptographic primitives.

5. **Subscriptions** - `subscriptions/`: Connection association, lifecycle, matching, delivery using `connection_id_t`. Owns subscription state.

6. **Policy** - Capability interface `nip_capability.h`: Deterministic composition rules (AND/OR for publication/delivery/query, ALL maintenance, first-wins for metadata/protocol-response, first-accept for kind handlers).

7. **Storage** - `storage.h/c`: Abstract `storage_context_t` interface. SQLite backend in `storage.c`. `storage_insert_result_t` distinguishes STORAGE_OK / STORAGE_DUPLICATE / STORAGE_ERROR. No SQLite types leak above storage.c.

Data flow: Client → Transport → Protocol → Validation → Subscriptions → Policy (NIP capabilities) → Storage API → SQLite

---

## 📞 Reference

### External Resources
- [Nostr Protocol Spec](https://github.com/nostr-protocol/nostr)
- [SQLite3 Documentation](https://sqlite.org/docs.html)
- [secp256k1](https://github.com/bitcoin-core/secp256k1)
- [mongoose](https://mongoose.ws/)

### Internal References
- See API_REFERENCE.md for function signatures
- See src/*.c for implementation details
- See PLAN.md for architecture and completion criteria

---

## ✨ Project Status

**Status**: ✅ **Architecture refactor complete**. All 31 architectural completion criteria verified. Build successful: `nob win` compiles, `build/main.exe --help` works. NIP migration complete (11 NIPs via capability interface). Transport helpers removed. server.c pure transport. Storage boundary verified.

**Last Updated**: 2026-10-02
**Version**: 1.0.0-refactor
**Language**: C99
**License**: Experimental use