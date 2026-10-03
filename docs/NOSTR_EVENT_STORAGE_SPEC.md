# Nostr Event Storage Specification

**Status:** Implemented  
**Scope:** C99 Nostr relay storage layer and SQLite-backed ORM  
**Primary goal:** Unified event storage API with composable primitives — no NIP-specific logic in storage

---

## 1. Design Philosophy

### 1.1 Core Principles

> **The storage layer answers one question: "Which event records does this scope select?" It does NOT answer: "Which NIP is asking, and what does that NIP's tag mean?"**

| Layer | Responsibility |
|-------|----------------|
| **NIP / Application Policy** | Authorization, expiration, replacement, retention, delegation verification, protocol semantics |
| **Event ORM** | Store, get, query, delete, transactions — generic database operations |
| **SQLite Backend** | SQL generation, prepared statements, schema, indexes, bindings, row serialization |

### 1.2 Five Primitives

```
EVENT      → structured record (id, pubkey, created_at, kind, tags, content, sig)
TAG        → opaque ordered tuple (name, value1, value2, ...)
PREDICATE  → field/tag comparison (equality, range, existence, prefix)
QUERY      → predicate tree + ordering + pagination
MUTATION   → insert / replace / delete
```

### 1.3 Separation of Concerns

```
Nostr Protocol
       │
       ▼
┌──────┴──────┐
│  NIP-01     │  NIP-09  │  NIP-62  │  NIP-40  │ ...
│ (replace)   │ (delete) │ (vanish) │ (expiry) │
└──────┬──────┘
       │
       ▼
storage_event_scope_t  ←── caller composes from protocol semantics
       │
       ▼
┌──────┴──────┐
│  FIND       │  DELETE
│ (SELECT)    │ (DELETE)
└──────┬──────┘
       │
       ▼
Shared WHERE Builder
       │
       ▼
SQLite ORM / libSQL / future backend
```

---

## 2. Canonical Data Model

### 2.1 Event Record

```c
typedef struct {
    char id[65];              // 32-byte hex + NUL
    char pubkey[65];          // 32-byte hex + NUL
    time_t created_at;        // Unix timestamp
    int kind;                 // Nostr kind
    char *tags_json;          // JSON array of tag arrays
    size_t tags_json_len;
    char *content;            // Event content
    size_t content_len;
    char sig[129];            // 64-byte hex + NUL
} event_t;
```

### 2.2 Tag Representation

Tags are stored as JSON in `tags_json` column and indexed in `event_tag_index` table:

```sql
CREATE TABLE event_tag_index (
    event_id TEXT NOT NULL REFERENCES event(id) ON DELETE CASCADE,
    tag_name TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (event_id, tag_name, tag_value)
);
CREATE INDEX event_tag_index_lookup ON event_tag_index(tag_name, tag_value, event_id);
```

**Tag helpers** (in `src/protocol/event_tags.h`):

```c
// Iteration
void event_tags_foreach(const event_t *event, event_tag_iter_cb cb, void *ctx);

// Lookup
char **event_tag_get(const event_t *event, const char *name);          // values array
char ***event_tag_get_all(const event_t *event, const char *name, size_t *out_count);
char *event_tag_value(const event_t *event, const char *name);         // first value

// Existence / Counting
bool event_tag_has(const event_t *event, const char *name);
bool event_tag_has_value(const event_t *event, const char *name, const char *value);
size_t event_tag_count(const event_t *event, const char *name);

// Free helpers
void event_tag_free(char **values);
void event_tag_free_all(char ***values, size_t count);
```

---

## 3. Selection Scope — The Unified Abstraction

### 3.1 Scope Definition

```c
typedef struct {
    // Exact ID match (single)
    const char *id;
    const char *after_id;

    // Multiple ID match (IN query)
    const char **ids;
    size_t ids_count;

    // Exact author match (single)
    const char *pubkey;

    // Multiple author match (IN query)
    const char **pubkeys;
    size_t pubkeys_count;

    // Kind filter (single)
    bool has_kind;
    int kind;

    // Multiple kind filter (IN query)
    int *kinds;
    size_t kinds_count;

    // Timestamp range (strict upper bound, <)
    bool has_created_at_before;
    time_t created_at_before;

    // Timestamp range (inclusive upper bound, <=)
    bool has_created_at_at_or_before;
    time_t created_at_at_or_before;

    // Timestamp range (strict lower bound, >)
    bool has_created_at_after;
    time_t created_at_after;

    // Timestamp range (inclusive lower bound, >=)
    bool has_created_at_at_or_after;
    time_t created_at_at_or_after;

    // Excluded kind (NIP-62)
    bool has_excluded_kind;
    int excluded_kind;

    // Multiple excluded kinds
    int *excluded_kinds;
    size_t excluded_kinds_count;

    // Tag filter: match events having ALL of these tag name/value pairs (AND)
    const char **tag_names;
    const char **tag_values;
    size_t tag_count;

    // Result limit (0 = backend default)
    size_t limit;

    // Offset for pagination (0 = no offset)
    size_t offset;
} storage_event_scope_t;
```

### 3.2 Scope Semantics

| Field | SQL Translation | Use Case |
|-------|----------------|----------|
| `id` | `id = ?` | Single event deletion |
| `ids` + `ids_count` | `id IN (?,?,...)` | `REQ {"ids": [...]}` |
| `pubkey` | `pubkey = ?` | Author-scoped operations |
| `pubkeys` + `pubkeys_count` | `pubkey IN (?,?,...)` | `REQ {"authors": [...]}` |
| `has_kind` + `kind` | `kind = ?` | Kind-specific operations |
| `kinds` + `kinds_count` | `kind IN (?,?,...)` | `REQ {"kinds": [...]}` |
| `created_at_before` | `created_at < ?` | Replaceable event cleanup |
| `created_at_at_or_before` | `created_at <= ?` | `REQ {"until": ...}`, NIP-62 vanish |
| `created_at_after` | `created_at > ?` | Incremental scans |
| `created_at_at_or_after` | `created_at >= ?` | `REQ {"since": ...}` |
| `excluded_kind` | `kind != ?` | NIP-62 exclusion |
| `excluded_kinds` + `excluded_kinds_count` | `kind NOT IN (?,?,...)` | Multi-kind exclusion |
| `tag_names` + `tag_values` + `tag_count` | `EXISTS (SELECT 1 FROM event_tag_index WHERE event_id=event.id AND tag_name=? AND tag_value=?) AND ...` | `REQ {"#e": [...], "#p": [...]}` compound |
| `limit` | `LIMIT ?` | Bounded results/deletes |
| `offset` | `OFFSET ?` | Pagination |

### 3.3 Design Rules

- **Explicit `has_*` flags** — avoids sentinel value collisions (e.g., `kind = 0` is valid)
- **Array fields for IN queries** — `ids`, `pubkeys`, `kinds`, `excluded_kinds` replace N separate calls
- **Compound tag filter** — `tag_names` + `tag_values` + `tag_count` = AND of tag existence (matches NIP-01 filter semantics)
- **No NIP names** — `nip09_*`, `nip62_*`, `replaceable_*`, `addressable_*` do not belong here
- **No predicate callbacks** — avoids second query language, opaque userdata, untestable logic
- **Timestamp operators explicit** — `before` = `<`, `at_or_before` = `<=`, `after` = `>`, `at_or_after` = `>=`

---

## 4. Storage API

### 4.1 Result Types

```c
typedef enum {
    STORAGE_OK = 0,
    STORAGE_DUPLICATE,
    STORAGE_NOT_FOUND,
    STORAGE_ERROR,
    STORAGE_INVALID_ARGUMENT
} storage_result_t;

typedef struct {
    storage_result_t result;
    int deleted_count;
    char error_message[256];
} storage_delete_result_t;

typedef struct {
    storage_result_t result;
    char error_message[256];
} storage_insert_result_t;

typedef struct {
    storage_result_t result;
    size_t count;
    char error_message[256];
} storage_count_result_t;
```

### 4.2 Find Operation

```c
bool storage_find_events(
    const storage_event_scope_t *scope,
    event_t ***out_events,
    size_t *out_count
);
```

**Contract:**
- `scope` may be NULL (no filtering) — subject to backend safety policy
- `out_events` receives caller-owned array of caller-owned `event_t *`
- `out_count` receives number of returned events
- Zero matches = success with count zero
- Database error = false
- Caller releases: `event_free()` each event, `free()` the array
- Deterministic ordering: `ORDER BY created_at DESC, id DESC`
- `limit == 0` = no explicit limit
- `offset` skips first N matching events (for pagination)

### 4.3 Count Operation

```c
bool storage_count_events(
    const storage_event_scope_t *scope,
    size_t *out_count
);
```

**Contract:**
- Same scope semantics as `storage_find_events`
- Returns total matching count without materializing events
- Useful for pagination UI (total pages = ceil(count / limit))
- Zero matches = success with `*out_count == 0`

### 4.4 Delete Operation

```c
bool storage_delete_events(
    const storage_event_scope_t *scope,
    size_t *out_deleted
);
```

**Contract:**
- Same scope semantics as `storage_find_events`
- Zero matches = success with `*out_deleted == 0`
- Database error = false
- `out_deleted` receives affected row count
- Atomic from storage call perspective
- No event materialization unless backend requires it
- `limit` controls maximum deleted rows (same symmetry as find)
- `offset` skips first N matching events before deleting

### 4.5 Transactional Delete Operation

```c
typedef struct storage_transaction_t storage_transaction_t;

storage_transaction_t *storage_transaction_begin(void);
bool storage_transaction_commit(storage_transaction_t *tx);
void storage_transaction_rollback(storage_transaction_t *tx);

bool storage_delete_events_tx(
    const storage_event_scope_t *scope,
    storage_transaction_t *tx,
    size_t *out_deleted
);

bool storage_find_events_tx(
    const storage_event_scope_t *scope,
    storage_transaction_t *tx,
    event_t ***out_events,
    size_t *out_count
);
```

**Contract:**
- Caller manages transaction lifecycle for multi-step operations
- `storage_delete_events_tx` / `storage_find_events_tx` participate in caller's transaction
- Pass `NULL` for `tx` to use implicit transaction (current behavior)
- Enables atomic find-then-delete without loading all events into memory

### 4.6 Replaceable Event Upsert

```c
storage_insert_result_t storage_upsert_replaceable(
    const event_t *ev,
    const storage_tag_match_t *indexed_tags,
    size_t indexed_tags_count
);
```

**Contract:**
- Atomically: delete older events with same `pubkey` + `kind` + `created_at < ev->created_at`, then insert `ev`
- For equal `created_at`: keeps event with lowest `id` (lexical), discards other
- Returns `STORAGE_DUPLICATE` if identical event already exists
- Indexed tags (`e`, `p`, `a` single-letter) are extracted and inserted into `event_tag_index`
- Use for kinds: 0, 3, 10000–20000 (replaceable per NIP-01)

### 4.7 Addressable Event Upsert

```c
storage_insert_result_t storage_upsert_addressable(
    const event_t *ev,
    const char *d_tag_value,
    const storage_tag_match_t *indexed_tags,
    size_t indexed_tags_count
);
```

**Contract:**
- Atomically: delete older events with same `pubkey` + `kind` + `d` tag value + `created_at < ev->created_at`, then insert `ev`
- `d_tag_value` is the `d` tag identifier (required for kinds 30000–40000)
- For equal `created_at`: keeps event with lowest `id`
- Returns `STORAGE_DUPLICATE` if identical event already exists
- Indexes `a` tag into `event_tag_index` as single-letter tag

### 4.8 Other Operations (Existing)

```c
// Single event by ID
event_t *storage_get_event_by_id(const char *id);

// Insert new event (generic, no replacement logic)
storage_insert_result_t storage_insert_record(
    const event_t *ev,
    const storage_tag_match_t *indexed_tags,
    size_t indexed_tags_count
);

// Compound tag index lookup (AND of multiple tag name/value pairs)
bool storage_find_ids_by_tags(
    const char *const *tag_names,
    const char *const *tag_values,
    size_t tag_count,
    char ***ids_out,
    size_t *count_out
);

void storage_free_id_list(char **ids, size_t count);
```

---

## 5. Shared WHERE Builder

### 5.1 Concept

```c
static char *build_where_clause(
    const storage_event_scope_t *scope,
    sql_bindings_t *bindings
);
```

**Invariant:** Every event-column condition in `storage_event_scope_t` has exactly ONE canonical SQL translation.

### 5.2 Generation Path

```
storage_find_events()
    │
    ├── build_where_clause()
    │
    ├── build SELECT
    │
    ├── bind parameters
    │
    ├── execute
    │
    └── materialize event_t[]

storage_delete_events()
    │
    ├── build_where_clause()
    │
    ├── build DELETE
    │
    ├── bind parameters
    │
    ├── execute
    │
    └── return affected rows
```

### 5.3 Parameter Binding

- Always use bound parameters — never interpolate
- `param_t` array with types: `PARAM_TYPE_NUMBER`, `PARAM_TYPE_STRING`, `PARAM_TYPE_OWNED_STRING`
- Owned strings freed via `params_release()` after `sqlite3_bind_text(..., SQLITE_TRANSIENT)`

---

## 6. Caller-Side Tag Filtering

### 6.1 Principle

> **Storage evaluates the scope; the caller evaluates tags.**

### 6.2 NIP-09 Addressable Deletion

```
parse "a" tag
    │
    ├── validate kind/pubkey authorization
    │
    ▼
build scope: { kind, pubkey, created_at_before }
    │
    ▼
storage_find_events(&scope, &events, &count)
    │
    ▼
for each event:
    if event_tag_has_value(event, "d", identifier):
        delete_scope = { .id = event->id }
        storage_delete_events(&delete_scope, &deleted)
```

### 6.3 NIP-40 / NIP-17 Gift Wrap

Same pattern: find by scope → inspect `p` tag / `expiration` tag → delete by ID.

---

## 7. Example Usage Patterns

### 7.1 Single Event by ID

```c
storage_event_scope_t scope = { .id = event_id };
size_t deleted = 0;
if (!storage_delete_events(&scope, &deleted)) return false;
```

### 7.2 Authorized Single Event

```c
storage_event_scope_t scope = {
    .id = event_id,
    .pubkey = authorized_pubkey
};
storage_delete_events(&scope, &deleted);
```

### 7.3 Replaceable Event (Kind 0, 3, 10000–20000) — Old Way (Caller-Managed)

```c
storage_event_scope_t scope = {
    .pubkey = event->pubkey,
    .has_kind = true,
    .kind = event->kind,
    .has_created_at_before = true,
    .created_at_before = event->created_at
};
storage_delete_events(&scope, &deleted);
```

### 7.4 Replaceable Event — New Atomic Upsert

```c
storage_insert_result_t result = storage_upsert_replaceable(event, indexed_tags, indexed_tags_count);
if (result.result == STORAGE_DUPLICATE) { /* already have this version */ }
else if (result.result != STORAGE_OK) { /* handle error */ }
```

### 7.5 Addressable Event (Kind 30000–40000) — Atomic Upsert

```c
char *d_value = event_tag_value(event, "d");
storage_insert_result_t result = storage_upsert_addressable(event, d_value, indexed_tags, indexed_tags_count);
```

### 7.6 NIP-62 Vanish

```c
storage_event_scope_t scope = {
    .pubkey = event->pubkey,
    .has_created_at_at_or_before = true,
    .created_at_at_or_before = event->created_at,
    .has_excluded_kind = true,
    .excluded_kind = event->kind
};
storage_delete_events(&scope, &deleted);
```

### 7.7 Find + Tag Filter + Delete (NIP-09 Addressable)

```c
storage_event_scope_t scope = {
    .pubkey = pubkey,
    .has_kind = true,
    .kind = kind,
    .has_created_at_before = true,
    .created_at_before = cutoff
};

event_t **events = NULL;
size_t count = 0;
if (!storage_find_events(&scope, &events, &count)) return false;

for (size_t i = 0; i < count; ++i) {
    if (!event_tag_has_value(events[i], "d", identifier)) continue;

    storage_event_scope_t del_scope = { .id = events[i]->id };
    size_t deleted = 0;
    storage_delete_events(&del_scope, &deleted);
}

for (size_t i = 0; i < count; ++i) event_free(events[i]);
free(events);
```

### 7.8 REQ with Multiple Filters (IN Queries)

```c
// REQ {"ids": ["id1", "id2", "id3"], "authors": ["pk1", "pk2"], "kinds": [1, 7], "#e": ["eid1", "eid2"], "since": 1000, "until": 2000, "limit": 50}

const char *ids[] = {"id1", "id2", "id3"};
const char *pubkeys[] = {"pk1", "pk2"};
int kinds[] = {1, 7};
const char *tag_names[] = {"e", "e"};
const char *tag_values[] = {"eid1", "eid2"};

storage_event_scope_t scope = {
    .ids = ids, .ids_count = 3,
    .pubkeys = pubkeys, .pubkeys_count = 2,
    .kinds = kinds, .kinds_count = 2,
    .tag_names = tag_names, .tag_values = tag_values, .tag_count = 2,
    .has_created_at_at_or_after = true, .created_at_at_or_after = 1000,
    .has_created_at_at_or_before = true, .created_at_at_or_before = 2000,
    .limit = 50
};

event_t **events = NULL;
size_t count = 0;
storage_find_events(&scope, &events, &count);
```

### 7.9 Pagination with COUNT

```c
storage_event_scope_t scope = { .pubkey = pk, .has_kind = true, .kind = 1 };
size_t total = 0;
storage_count_events(&scope, &total);

size_t page_size = 20;
for (size_t offset = 0; offset < total; offset += page_size) {
    scope.limit = page_size;
    scope.offset = offset;
    event_t **page = NULL;
    size_t count = 0;
    storage_find_events(&scope, &page, &count);
    // render page
    for (size_t i = 0; i < count; ++i) event_free(page[i]);
    free(page);
}
```

### 7.10 Atomic Find-Then-Delete (Transactional)

```c
storage_transaction_t *tx = storage_transaction_begin();

// Find events matching complex criteria
storage_event_scope_t find_scope = {
    .pubkey = pk,
    .kinds = kinds, .kinds_count = n_kinds,
    .tag_names = tag_names, .tag_values = tag_values, .tag_count = n_tags
};

event_t **events = NULL;
size_t count = 0;
if (!storage_find_events_tx(&find_scope, tx, &events, &count)) {
    storage_transaction_rollback(tx);
    return false;
}

// Delete them all in same transaction
storage_event_scope_t delete_scope = find_scope;  // same criteria
size_t deleted = 0;
bool ok = storage_delete_events_tx(&delete_scope, tx, &deleted);

if (ok && deleted == count) {
    storage_transaction_commit(tx);
} else {
    storage_transaction_rollback(tx);
}

// Cleanup
for (size_t i = 0; i < count; ++i) event_free(events[i]);
free(events);
```

### 7.11 Compound Tag Query (AND)

```c
// Find events that have BOTH #e=abc AND #p=xyz
const char *tag_names[] = {"e", "p"};
const char *tag_values[] = {"abc", "xyz"};

char **ids = NULL;
size_t count = 0;
storage_find_ids_by_tags(tag_names, tag_values, 2, &ids, &count);
// ids now contains event IDs matching BOTH tags
storage_free_id_list(ids, count);
```

---

## 8. What This Replaces

| Current Mechanism | New Mechanism |
|------------------|---------------|
| `delete_matching(scope, predicate, userdata, ...)` | `storage_delete_events(scope, &deleted)` |
| `find_ids_by_tag(tag_name, tag_value, ...)` | `storage_find_ids_by_tag` (single) / `storage_find_ids_by_tags` (compound) |
| `delete_record_by_id_and_pubkey` | `storage_delete_events` with `.id` + `.pubkey` |
| `delete_record_by_kind_and_pubkey` | `storage_delete_events` with `.kind` + `.pubkey` + timestamp |
| `delete_record_by_kind_and_pubkey_and_dtag` | `storage_upsert_addressable` / find + `event_tag_has_value("d", ...)` + delete by ID |
| `delete_record_by_id_and_kind_and_ptag` | find by ID/kind + caller tag validation + delete by ID |
| `delete_all_events_by_pubkey` | `storage_delete_events` with `.pubkey` + timestamp + `.excluded_kind` / `.excluded_kinds` |
| Multiple SQL WHERE implementations | **One shared WHERE builder** |
| NIP-shaped storage methods | Backend-neutral database capabilities |
| Caller loops for multi-ID/pubkey/kind REQ | Single call with `.ids`/`.pubkeys`/`.kinds` arrays |
| Separate replaceable event delete+insert | `storage_upsert_replaceable` (atomic) |
| Separate addressable event delete+insert | `storage_upsert_addressable` (atomic) |
| Load-then-delete for complex criteria | `storage_delete_events_tx` in transaction |

---

## 9. Migration Status

All phases complete — storage layer is now unified under `storage_event_scope_t` with:
- ✅ Shared WHERE generation
- ✅ Find / Count / Delete with identical scope semantics
- ✅ IN query arrays for ids, pubkeys, kinds, excluded_kinds
- ✅ Compound tag AND filter
- ✅ Transaction API
- ✅ Atomic upserts (replaceable + addressable)
- ✅ Pagination (limit + offset)
- ✅ Tag index lookup (single + compound)

---

## 10. Testing Requirements

### 10.1 Scope Matching Matrix

Fixture DB with events varying by: id, pubkey, kind, created_at, tags. Verify all scope combinations.

### 10.2 Boundary Tests

```
before(100):      99→match, 100→no match
at_or_before(100): 99→match, 100→match, 101→no match
after(100):       99→no match, 100→no match, 101→match
at_or_after(100): 99→no match, 100→match, 101→match
```

### 10.3 Find/Delete Equivalence

```c
matching = find(scope);
deleted = delete(scope);
assert(deleted == matching.count);
assert(none of matching IDs remain);
```

### 10.4 Nonmatching Preservation

After delete: all non-matching rows unchanged (IDs, content, tags, counts).

### 10.5 Combined Scopes

All conditions ANDed: `pubkey=A AND kind=1 AND created_at>100 AND created_at<300 AND excluded_kind=2`

### 10.6 ID + Pubkey Authorization

`id=X + pubkey=A` does NOT delete event X if author is B.

### 10.7 NIP-09 Tests

Direct auth, delegated, unauthorized, unknown target, `e` tag, `a` tag, malformed `a` tag, replaceable, addressable, matching/nonmatching `d` tag, optional `k` tags, multiple targets.

### 10.8 NIP-62 Tests

Same pubkey + older/equal/newer timestamp, different pubkey, excluded kind, other kinds.

### 10.9 Replaceable Event Tests

Old removed, new stored, newer replaces older, equal timestamp tie-break preserved, different pubkey/kind unaffected.

### 10.10 Tag Helper Tests

`event_tag_has()`, `event_tag_has_value()` against NIP-09 test events.

### 10.11 Memory Ownership

ASan/UBSan: returned event ownership, empty result allocation, failed query cleanup, prepared statement cleanup, scope string ownership, delete without unnecessary materialization.

### 10.12 SQL Injection

All string scope fields bound: `' OR 1=1 --`, `"; DROP TABLE events; --` treated as literals.

### 10.13 Transactions

`BEGIN → DELETE → ERROR → ROLLBACK` leaves DB unchanged. Success commits per storage model.

### 10.14 IN Query Tests (Arrays)

- `ids` array: 1, 2, 5, 10, 100 IDs — verify all match, no others
- `pubkeys` array: same
- `kinds` array: same
- `excluded_kinds` array: verify exclusion works
- Empty arrays: treated as no-op (match all)
- NULL arrays: treated as no-op

### 10.15 Compound Tag Query Tests

- `tag_names` + `tag_values` with count=1: single tag match
- `tag_names` + `tag_values` with count>1: AND of all tags (all must match)
- Duplicate tag names with different values: OR within same name, AND across names
- Non-existent tag name/value: zero matches
- Mixed with other scope fields: AND with pubkey, kind, time range

### 10.16 Count Operation Tests

- `storage_count_events` matches `storage_find_events` count for same scope
- Count with limit/offset: count returns total, not limited
- Count with complex scope (all field types)

### 10.17 Pagination Tests

- `limit` + `offset` produces correct pages
- Last page may have fewer than `limit`
- `offset` beyond total returns empty (not error)
- Count + paginated find: sum of page counts = total count

### 10.18 Atomic Upsert Tests (Replaceable)

- Insert new replaceable event: stored
- Insert newer same kind/pubkey: old deleted, new stored
- Insert older same kind/pubkey: rejected or ignored (caller policy)
- Equal timestamp: lower ID wins
- Different pubkey/kind: unaffected
- Duplicate event (same ID): `STORAGE_DUPLICATE`

### 10.19 Atomic Upsert Tests (Addressable)

- Insert new addressable event: stored
- Insert newer same kind/pubkey/d-tag: old deleted, new stored
- Insert older same kind/pubkey/d-tag: rejected
- Equal timestamp: lower ID wins
- Missing `d` tag: error
- Different pubkey/kind/d-tag: unaffected

### 10.20 Transaction Tests

- `storage_transaction_begin` / `commit` / `rollback` lifecycle
- `find_tx` + `delete_tx` in same transaction: atomic
- Rollback after find: no side effects
- Rollback after delete: DB unchanged
- Nested transactions: error or savepoint behavior (define)

### 10.21 Tag Index Tests (Generic)

- `event_tag_index` populated on insert/upsert for all single-letter tags (`e`, `p`, `a`, etc.)
- Query by `tag_name` + `tag_value` returns correct event IDs
- `a` tag indexed as full composite value (e.g., `"30023:pubkey:d-value"`)
- Deleted events removed from index (CASCADE)
- Compound tag query (`storage_find_ids_by_tags`) works for `#a` filter

---

## 11. Open Decisions (Resolved)

| # | Decision | Resolution |
|---|----------|------------|
| 1 | `limit` semantics for DELETE | Limit = max deleted rows (symmetry with FIND) |
| 2 | `offset` for DELETE | Allow (skip N before deleting) — useful for "delete all but newest N" |
| 3 | DELETE transaction boundary | Implicit transaction per call; caller manages composites via `*_tx` API |
| 4 | `out_deleted` NULL acceptance | Allow NULL (deliberately ignore count) |
| 5 | NULL scope behavior | FIND: allowed. DELETE: rejected unless explicit opt-in |
| 6 | Backend interface exposure | Add to `storage_context_t` function pointers |
| 7 | SQLite indexes | `(pubkey, kind, created_at)`, `(pubkey, created_at)`, `(kind, pubkey, created_at)` |
| 8 | NIP-40 integration | Keep `purge_expired()` separate; don't force into scope |
| 9 | WHERE builder signature | Use existing `param_t` mechanism, not new `sql_bindings_t` |
| 10 | Error distinction | `bool` return + output count (project style); `storage_delete_result_t` if needed later |
| 11 | Array field ownership | Caller owns arrays; scope struct is stack-allocated, arrays point to caller data |
| 12 | Compound tag query: OR within same tag name? | No — AND across all pairs. For OR, caller makes multiple calls. |
| 13 | `storage_upsert_replaceable` on older event | Return `STORAGE_ERROR` with "stale" message; caller decides retry |
| 14 | Transaction API: savepoints? | Start simple: flat transactions. Add savepoints if needed. |

---

## 12. Implementation Guardrails

### Do Not

- ❌ Add generic predicate callback
- ❌ Add NIP names or logic to storage API
- ❌ Add tag-specific fields to scope (except compound tag filter arrays)
- ❌ Rewrite entire Nostr query/filter system
- ❌ Change event serialization
- ❌ Change DB schema unnecessarily
- ❌ Optimize tag indexing prematurely
- ❌ Silently change timestamp inclusivity
- ❌ Remove old APIs before migration complete
- ❌ Conflate "zero matches" with storage error
- ❌ Add OR logic to compound tag filter (keep it AND only)
- ❌ Make transaction API mandatory for simple operations

### Do

- ✅ Preserve behavior with regression tests
- ✅ Use designated initializers (C99)
- ✅ Use prepared statements
- ✅ Share WHERE generation
- ✅ Keep NIP semantics in NIP modules
- ✅ Keep SQLite details inside backend
- ✅ Make ownership contracts explicit
- ✅ Make timestamp operators explicit
- ✅ Make delete counts explicit
- ✅ Test find/delete equivalence
- ✅ Test IN query arrays (empty, NULL, single, multiple)
- ✅ Test compound tag AND semantics
- ✅ Test atomic upsert race conditions
- ✅ Test transaction rollback scenarios

---

## 13. Target Architecture

```
                          Nostr Protocol
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
          NIP-01              NIP-09              NIP-62
            │                   │                   │
            │                   │                   │
            └───────────────────┼───────────────────┘
                                │
                                ▼
                      storage_event_scope_t
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
storage_find_events()  storage_delete_events()  storage_count_events()
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
                    ▼                       ▼
           Storage Backend          Transaction API
                    │                       │
                    ▼                       ▼
           Shared WHERE Builder      storage_transaction_t
                    │                       │
                    ▼                       ▼
              SQLite ORM ─────────────► SQLite Tx
                    │
      ┌─────────┴─────────┐
       │                   │
   events             event_tags
       │                   │
       │            ┌──────┴──────┐
       │            │             │
       ▼            ▼             ▼
    event_id      tag_name      tag_value
```

**Key property:** All event-column matching converges at one point.

---

## 14. Final Design Principle

The storage layer is a **small SQL ORM** whose primary domain object happens to be a Nostr event, with **one unified selection model shared by reads, counts, and destructive operations**.

```
For reads:     scope → SELECT → event_t[]
For counts:    scope → COUNT  → total
For writes:    scope → DELETE → affected_count
For upserts:   event → UPSERT → atomic replace/insert
For tags:      scope → FIND → event_t[] → event_tag_has/value → follow-up
               tags  → INDEX  → event_ids (single or compound AND)
```

This produces a **composable, backend-neutral C99 storage interface** while preserving the protocol layer's responsibility for Nostr semantics.