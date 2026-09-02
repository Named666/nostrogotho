# Quick Start Guide - Cagliostr C99

## Installation

### 1. Build Bundled Dependencies

All dependencies are source-vendored under `thirdparty/`. Build their static
libraries and install their generated headers under `thirdparty/install`:

```
thirdparty/install/
    include/openssl/configuration.h
    lib/libsecp256k1.a
    lib/libcrypto.a
```

### 2. Build the Relay

```powershell
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
.\nob.exe
```

This bootstraps `nob`, which builds `build/nostrogotho.exe` using GCC. The
project itself has no CMake configuration and does not link system copies of
its dependencies.

### 3. Run the Server

```bash
# Default (in-memory database, port 8080)
./nostr_server

# With persistent database
./nostr_server --db file:nostr.db --port 8080

# Help
./nostr_server --help
```

## Basic Usage

### Creating an Event

```c
#include "cagliostr.h"
#include "storage.h"

// Create event
event_t *event = event_alloc();
strncpy(event->id, "event_id_hex", MAX_ID_SIZE);
strncpy(event->pubkey, "pubkey_hex", MAX_PUBKEY_SIZE);
event->created_at = time(NULL);
event->kind = 1;
event->content = string_dup("Hello, Nostr!");
event->tags_json = string_dup("[]");
strncpy(event->sig, "signature_hex", MAX_SIG_SIZE);

// Store it
storage_context_t ctx = {0};
storage_context_init_sqlite3(&ctx);
ctx.init("file:nostr.db");
ctx.insert_record(event);
ctx.deinit();

event_free(event);
```

### Querying Events

```c
// Create filter
filter_t *filter = filter_alloc();
filter->limit = 100;
filter->since = time(NULL) - 86400;  // Last 24 hours

// Query
ctx.send_records(print_event, "subscription_id", filter, 1, false, NULL);

filter_free(filter);

// Callback function
void print_event(const char *json) {
    printf("%s\n", json);
}
```

### Verifying Events

```c
#include "crypto.h"

crypto_init();

if (check_event(event)) {
    printf("✓ Event is valid\n");
} else {
    printf("✗ Invalid event\n");
}

crypto_deinit();
```

## File Organization

```
nostrogotho/
├── src/
│   ├── cagliostr.h/c     # Core data structures
│   ├── crypto.h/c        # Cryptographic operations
│   ├── storage.h/c       # SQLite3 database layer
│   ├── server.c          # WebSocket server
│   └── main.c            # Test/example main
├── examples/
│   └── example.c         # Detailed usage examples
├── nob.c                 # Build bootstrap
├── src_build/nob_configed.c # Relay build definition
├── nostr-policy.json     # WebSocket policy
├── API_REFERENCE.md      # Full API documentation
├── IMPLEMENTATION.md     # Architecture details
└── COMPLETION_SUMMARY.md # Project summary
```

## API Highlights

### Event Management
```c
event_t *event_alloc(void);
void event_free(event_t *ev);
```

### Database Operations
```c
ctx.init(db_path);
ctx.insert_record(event);
event_t *ev = ctx.get_event_by_id(id);
ctx.send_records(callback, "sub", filters, count, false, &has_more);
ctx.deinit();
```

### Cryptography
```c
crypto_init();
bool valid = check_event(event);
bool sig_ok = signature_verify(sig_hex, pubkey_hex, digest);
void sha256(data, len, digest);
crypto_deinit();
```

## Common Tasks

### Task 1: Create and Validate an Event

```c
// 1. Create event structure
event_t *ev = event_alloc();
// 2. Fill in fields
ev->kind = 1;
ev->content = string_dup("My message");
// 3. Initialize crypto
crypto_init();
// 4. Validate
if (check_event(ev)) {
    // 5. Store if valid
    storage.insert_record(ev);
}
crypto_deinit();
event_free(ev);
```

### Task 2: Query Events by Author

```c
filter_t *f = filter_alloc();
f->authors = (char **)malloc(sizeof(char *));
f->authors[0] = "author_pubkey_hex";
f->authors_count = 1;
f->limit = 50;

ctx.send_records(callback, "sub1", f, 1, false, NULL);

filter_free(f);
```

### Task 3: Retrieve Single Event

```c
event_t *ev = ctx.get_event_by_id("event_id_hex");
if (ev) {
    printf("Found: %s\n", ev->content);
    event_free(ev);
}
```

## Debugging

### Enable Verbose Logging

Set environment variables before running:
```bash
# mongoose logging
export LLL=65535  # All levels

# Run server with logging
./nostr_server --log-level 7
```

### Check Database

```bash
# Open database
sqlite3 nostr.db

# View tables
.schema

# Query events
SELECT id, pubkey, created_at, kind FROM event LIMIT 10;
```

### Verify Signatures

```c
// Enable debug output
printf("Event ID: %s\n", event->id);
printf("Pubkey:   %s\n", event->pubkey);
printf("Sig:      %s\n", event->sig);

// Validate
if (check_event(event)) {
    printf("✓ Signature valid\n");
} else {
    printf("✗ Signature INVALID\n");
}
```

## Performance Tips

1. **Database**: Use WAL mode for concurrent access
2. **Queries**: Add `limit` to avoid large result sets
3. **Filtering**: Combine filters to narrow results
4. **Crypto**: Initialize once, use multiple times
5. **Memory**: Free structures after use to avoid leaks

## Troubleshooting

### Build Errors

```
error: sqlite3.h: No such file or directory
→ Install: sudo apt-get install libsqlite3-dev

error: openssl/evp.h: No such file or directory
→ Install: sudo apt-get install libssl-dev

error: secp256k1.h: No such file or directory
→ Install: sudo apt-get install libsecp256k1-dev
```

### Runtime Errors

```
"Failed to initialize crypto"
→ Ensure secp256k1 library is properly installed

"Database initialization failed"
→ Check file path is writable, or use :memory: for testing

"Connection refused"
→ Check port 8080 is available, or use --port option
```

## Next Steps

1. **Read**: [API_REFERENCE.md](API_REFERENCE.md) for complete API
2. **Study**: [examples/example.c](examples/example.c) for working code
3. **Explore**: [IMPLEMENTATION.md](IMPLEMENTATION.md) for architecture
4. **Integrate**: Add Nostr protocol message handlers to server.c

## Support

For detailed information:
- API Documentation: See [API_REFERENCE.md](API_REFERENCE.md)
- Implementation Details: See [IMPLEMENTATION.md](IMPLEMENTATION.md)
- Code Examples: See [examples/example.c](examples/example.c)
- Project Summary: See [COMPLETION_SUMMARY.md](COMPLETION_SUMMARY.md)

