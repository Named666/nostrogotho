# Cagliostr C99 API Reference

## Overview

Cagliostr provides a complete C99 implementation of a Nostr relay backend with cryptographic verification and SQLite3 storage.

## Core Modules

### 1. cagliostr.h - Data Structures

#### Event Structure
```c
typedef struct {
    char id[MAX_ID_SIZE + 1];              // 64-char hex event ID
    char pubkey[MAX_PUBKEY_SIZE + 1];      // 64-char hex public key
    time_t created_at;                     // Unix timestamp
    int kind;                              // Event kind/type
    char *tags_json;                       // JSON array as string
    size_t tags_json_len;                  // Length of tags JSON
    char *content;                         // Event content
    size_t content_len;                    // Length of content
    char sig[MAX_SIG_SIZE + 1];            // 128-char hex signature
} event_t;
```

#### Filter Structure
```c
typedef struct {
    char **ids;                    // Event IDs to search
    size_t ids_count;
    
    char **authors;                // Author pubkeys to search
    size_t authors_count;
    
    int *kinds;                    // Event kinds to search
    size_t kinds_count;
    
    tag_t *tags;                   // Tag filters
    size_t tags_count;
    
    time_t since;                  // Timestamp lower bound
    time_t until;                  // Timestamp upper bound
    int limit;                     // Result limit
    
    char *search;                  // Full-text search in content
} filter_t;
```

#### Tag Structure
```c
typedef struct {
    char **elements;               // Tag elements
    size_t count;                  // Number of elements
} tag_t;
```

#### Memory Management
```c
event_t *event_alloc(void);        // Create new event
void event_free(event_t *ev);      // Free event

filter_t *filter_alloc(void);      // Create new filter
void filter_free(filter_t *f);     // Free filter

tag_t *tag_alloc(size_t count);    // Create new tag with capacity
void tag_free(tag_t *tag);         // Free tag

char *string_dup(const char *str); // Duplicate string
void string_free(char *str);       // Free string
```

---

### 2. crypto.h - Cryptographic Operations

#### Initialization
```c
bool crypto_init(void);            // Initialize crypto context
void crypto_deinit(void);          // Cleanup crypto context
```

#### Hashing
```c
void sha256(const uint8_t *data, size_t len, uint8_t digest[32]);
```
Computes SHA256 hash of data.

#### Hex Conversion
```c
char *bytes_to_hex(const uint8_t *bytes, size_t len);
// Returns hex string (must be freed)

bool hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes,
                  size_t max_bytes, size_t *out_len);
// Converts hex string to bytes
```

#### Signature Verification
```c
bool signature_verify(const char *sig_hex, const char *pubkey_hex,
                      const uint8_t digest[32]);
// Verifies Schnorr signature (secp256k1)
```

#### Event Validation
```c
bool check_event(const event_t *ev);
// Validates event ID, signature, and delegation tags
// Returns true if event is valid
```

#### Delegation Verification
```c
bool check_delegation(const event_t *ev, const char *delegator_pubkey,
                      const char *conditions, const char *delegation_sig);
// Verifies NIP-26 delegation with conditions
```

#### Proof of Work
```c
int count_leading_zero_bits(const char *hex);
// Counts leading zero bits in a hex string
```

---

### 3. storage.h - Database Operations

#### Context Initialization
```c
void storage_context_init_sqlite3(storage_context_t *ctx);
// Initialize storage context with SQLite3 backend
```

#### Context Operations (via function pointers)
```c
storage_context_t ctx = {0};
storage_context_init_sqlite3(&ctx);

// Initialize database
bool success = ctx.init("file:nostr.db");

// Retrieve event
event_t *ev = ctx.get_event_by_id("event_id_hex");

// Insert event
bool success = ctx.insert_record(event);

// Delete operations
int rows = ctx.delete_record_by_id_and_pubkey(id, pubkey);
int rows = ctx.delete_record_by_kind_and_pubkey(kind, pubkey, created_at);
// ... and others

// Query events
bool success = ctx.send_records(callback_function, "sub_id", 
                               filters, filter_count,
                               false, &has_more);

// Cleanup
ctx.deinit();
```

#### Callback Functions
```c
typedef void (*send_records_callback_t)(const char *json_event);
// Called for each record matching query
// json_event is a JSON string in Nostr EVENT format
```

#### Utility Functions
```c
bool is_expired(const tags_array_t *tags);
// Checks if an event has an expiration tag in the past

char *escape_like(const char *str, size_t len);
// Escapes string for SQL LIKE clauses (must be freed)
```

---

## Usage Examples

### Example 1: Create and Store Event
```c
event_t *event = event_alloc();
strncpy(event->id, hex_id, MAX_ID_SIZE);
strncpy(event->pubkey, hex_pubkey, MAX_PUBKEY_SIZE);
event->created_at = time(NULL);
event->kind = 1;
event->content = string_dup("Hello world");
event->tags_json = string_dup("[]");
strncpy(event->sig, hex_sig, MAX_SIG_SIZE);

storage_context_t ctx = {0};
storage_context_init_sqlite3(&ctx);
ctx.init("file:nostr.db");
ctx.insert_record(event);
ctx.deinit();

event_free(event);
```

### Example 2: Query Events
```c
filter_t *filter = filter_alloc();
filter->kinds = (int *)malloc(sizeof(int));
filter->kinds[0] = 1;
filter->kinds_count = 1;
filter->limit = 100;

ctx.send_records(my_callback, "sub1", filter, 1, false, &has_more);

filter_free(filter);
```

### Example 3: Verify Event
```c
crypto_init();

if (check_event(event)) {
    printf("Event is valid!\n");
} else {
    printf("Event signature verification failed\n");
}

crypto_deinit();
```

---

## Constants

```c
#define MAX_ID_SIZE 64              // Event ID length (hex)
#define MAX_PUBKEY_SIZE 64          // Public key length (hex)
#define MAX_SIG_SIZE 128            // Signature length (hex)
#define MAX_CONTENT_SIZE 65536      // Maximum event content
#define MAX_TAGS_SIZE 65536         // Maximum tags JSON size
#define MAX_TAG_ELEMENTS 256        // Maximum elements per tag
#define MAX_TAG_SIZE 512            // Maximum tag size
```

---

## Error Handling

All functions that allocate memory return NULL on failure.

Database functions return:
- `true`/`false` for success/failure (insert, etc.)
- `-1` for error in delete operations, or count of rows affected
- Query results via callback function

---

## Thread Safety

Current implementation is NOT thread-safe:
- Single SQLite connection (not thread-safe by default)
- For multi-threaded use, either:
  1. Use connection pooling
  2. Compile SQLite3 with THREADSAFE option
  3. Add mutex locks around database operations

---

## Performance Considerations

- Database uses WAL mode for concurrency
- Proper indexes on id, pubkey, created_at, and kind
- LIKE searches on tags may be slow with large datasets
- Consider adding full-text search index for content in production
- Memory usage scales with event size and filter complexity

