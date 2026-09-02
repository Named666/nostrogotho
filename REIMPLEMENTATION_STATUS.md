# C99 Nostr Relay Server Reimplementation - Status Report

## Overview
This document summarizes the progress on reimplementing the cagliostr Nostr relay server from C++ to C99. The goal is to create a production-ready relay server using only dependencies available in `thirdparty/` folder.

## Completed Tasks

### 1. ✅ Core Data Structures (cagliostr.h/c)
- **Status**: Fully implemented and documented
- **Components**:
  - `event_t`: Nostr event structure with all required fields
  - `filter_t`: Query filter for subscriptions (NIP-01)
  - `tag_t` / `tags_array_t`: Tag parsing and storage
  - Memory management: allocation, deallocation, and safety
- **Documentation**: Comprehensive inline comments explaining each structure

**Files**:
- [cagliostr.h](src/cagliostr.h) - 200+ lines of documented header
- [cagliostr.c](src/cagliostr.c) - Full memory management implementation

### 2. ✅ Cryptography (crypto.h/c)
- **Status**: Fully implemented and documented
- **Features**:
  - Event ID validation (SHA256 hash computation)
  - Schnorr signature verification (using libsecp256k1)
  - Delegation verification (NIP-26)
  - Proof-of-work calculation (NIP-13)
  - Hex encoding/decoding utilities
- **Correctness Fixes**:
  - Added `json_escape_string()` function for proper JSON serialization
  - Fixed event hash computation to properly escape special characters
  - Proper error handling and validation

**Files**:
- [crypto.h](src/crypto.h) - 200+ lines with detailed function documentation
- [crypto.c](src/crypto.c) - Full implementation with inline comments

### 3. ✅ Storage Backend (storage.h/c)
- **Status**: SQLite3 backend fully implemented
- **Features**:
  - Event CRUD operations
  - Flexible filter queries (NIP-01, NIP-67)
  - Event deletion by various criteria (NIP-09, NIP-16, NIP-33, NIP-62)
  - COUNT queries (NIP-13)
  - Optimized indexes for common queries
  - WAL mode for crash safety and concurrency
- **Database**:
  - Single `event` table with 7 columns (id, pubkey, created_at, kind, tags, content, sig)
  - 5 indexes for common query patterns
  - Configured with PRAGMA settings for performance

**Files**:
- [storage.h](src/storage.h) - 250+ lines with detailed API documentation
- [storage.c](src/storage.c) - 700+ lines of implementation

### 4. ✅ Documentation and Inline Comments
- **Added comprehensive documentation to ALL functions**:
  - Purpose and behavior
  - Parameter descriptions
  - Return values and error conditions
  - Memory management requirements
  - NIP references where applicable
  - Thread safety notes
  - Limitations and known issues

## Known Issues and Limitations

### Buffer Overflow Risks (MEDIUM PRIORITY)
1. **send_records() string building**: Uses `strcat()` without bounds checking
   - Fixed buffer sizes: 2048 bytes (conditions), 4096 bytes (sql)
   - Added validation to reject filters with >256 elements
   - **TODO**: Replace fixed buffers with dynamic allocation
   
2. **Addressed**: Proper null-termination after `strncpy()` calls
   - Fixed in `get_event_by_id()` - now adds explicit null terminators

### JSON Serialization (FIXED)
- ✅ Added `json_escape_string()` for proper character escaping
- ✅ Updated `check_event()` to escape content before hashing
- **Remaining**: send_records() response JSON should also be escaped (currently unescaped)

### Database Considerations
- Indexes optimized for common query patterns
- No full-text search beyond LIKE pattern matching
- Single SQLite connection (thread-unsafe at application level)

## Work Remaining

### 1. ❌ Server Implementation (server.c)
**Current State**: Skeleton using mongoose (incomplete)

**What's Needed**:
- Complete WebSocket server using mongoose
- Implement Nostr protocol message handling:
  - `["REQ", subscription_id, ...filters]` - subscription requests
  - `["CLOSE", subscription_id]` - close subscription
  - `["EVENT", event]` - event publication
  - `["COUNT", subscription_id, ...filters]` - count query
  - `["AUTH", event]` - NIP-42 authentication
- Subscriber connection management
- Event routing to subscriptions
- NIP-42 authentication support
- NIP-11 relay info metadata
- NIP-67 EOSE (End of Stored Events) completeness hints
- Rate limiting and DDoS protection

**Estimated Effort**: 500-800 lines of code

### 2. ❌ Main Entry Point (main.c)
**Current State**: Hello world stub

**What's Needed**:
- Command-line argument parsing:
  - `-database` or `DATABASE_URL` for connection string
  - `-port` or `PORT` for listen port (default 7447)
  - `-loglevel` for logging level
  - `-service-url` for relay URL
  - Configuration options from environment variables
- Signal handlers (SIGINT, SIGTERM)
- Initialize crypto subsystem
- Initialize storage subsystem
- Start WebSocket server
- Graceful shutdown

**Estimated Effort**: 200-300 lines of code

### 3. ⚠️ Output Formatting
**Issue**: Response JSON needs proper escaping for client compatibility
- Currently building JSON responses with raw event content
- Could contain unescaped quotes, backslashes, newlines
- **Fix**: Apply `json_escape_string()` to all string fields in responses

### 4. ⚠️ Protocol Message Parsing
**Need to implement**: JSON parsing for incoming Nostr messages
- Options:
  1. Simple handwritten parser (error-prone, ~300 lines)
  2. Lightweight JSON library (need to evaluate options in thirdparty/)
  3. Use available libraries in thirdparty/

## Architecture Summary

```
┌─────────────────────────────────────────┐
│         main.c (Entry Point)            │
│  - Parse args, Initialize subsystems    │
└──────────┬──────────────────────────────┘
           │
    ┌──────┼──────┬──────────┐
    │      │      │          │
    ▼      ▼      ▼          ▼
  ┌─────┐ ┌──────┐ ┌────────┐ ┌────────┐
  │     │ │      │ │        │ │        │
  │server│ │crypto│ │storage │ │cagliostr
  │.c   │ │.c    │ │.c      │ │.h/c   │
  │     │ │      │ │        │ │        │
  └─────┘ └──────┘ └────────┘ └────────┘
           │         │
           │      ┌──▼──────────┐
           │      │  SQLite3    │
           │      │  Database   │
           │      └─────────────┘
           │
    ┌──────▼──────────────┐
    │ libsecp256k1        │
    │ Signature Verify    │
    └─────────────────────┘
```

## Testing Strategy

### Unit Tests Needed
1. **Crypto**:
   - Event hash computation (compare with reference implementation)
   - Signature verification (valid and invalid sigs)
   - Delegation verification with various conditions
   - Proof-of-work calculation

2. **Storage**:
   - Insert and retrieve events
   - Filter queries (ids, authors, kinds, tags, time ranges)
   - Event deletion scenarios
   - Expiration tag handling

3. **Server**:
   - WebSocket connection handling
   - Message parsing and validation
   - Subscription management
   - Event broadcasting to subscribers

### Integration Tests
1. Full relay protocol flow
2. Multiple concurrent subscribers
3. Large event payload handling
4. Special character handling in content

## Dependencies

### Required from thirdparty/
- ✅ libsecp256k1 - Schnorr signature verification
- ✅ sqlite3 - Event storage
- ✅ mongoose - WebSocket server framework
- ? JSON parsing library (need to identify)

### Standard Library
- openssl/evp.h - SHA256 hashing
- string.h, stdlib.h - Memory/string operations
- time.h - Timestamp handling
- signal.h - Signal handling

## Performance Considerations

### Database Optimization
- ✅ WAL mode: Better concurrency, crash-safe
- ✅ Indexes: created_at (DESC), pubkey, kind, composite (kind, created_at)
- ✅ PRAGMA cache_size: 256MB for frequently accessed data
- ⚠️ No sharding: Single process, single database

### Server Scalability
- Single-threaded WebSocket event loop
- Connection-per-subscriber model
- Event broadcasting has O(N) complexity per event
- **Future**: Consider thread pool or async model

## Building and Running

```bash
# Build
mkdir build && cd build
cmake ..
make

# Run
./cagliostr -database file:relay.db -port 7447

# With options
./cagliostr \
  -database file:relay.db \
  -port 8080 \
  -service-url https://relay.example.com \
  -loglevel debug
```

## Next Steps (Priority Order)

1. **CRITICAL**: Complete server.c WebSocket implementation
2. **HIGH**: Implement message parsing in server.c
3. **HIGH**: Complete main.c with proper initialization
4. **MEDIUM**: Add JSON escaping to response generation
5. **MEDIUM**: Improve error handling and logging
6. **LOW**: Performance optimization and scaling

## References

- [Nostr Protocol (NIP-01)](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [Event Filtering (NIP-13, NIP-16, NIP-17, NIP-26, NIP-40, NIP-42, NIP-62, NIP-67)](https://github.com/nostr-protocol/nips)
- [mongoose Documentation](https://mongoose.ws/)
- [secp256k1 GitHub](https://github.com/bitcoin-core/secp256k1)
- [SQLite Documentation](https://www.sqlite.org/docs.html)

---

**Last Updated**: 2026-09-01
**Status**: ~60% Complete (Core functionality + documentation done, server/main pending)
