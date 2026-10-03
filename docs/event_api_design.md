# Event Tag API - Design & Implementation

## Goal

Create a minimal, future-proof API for accessing Nostr event tags. Events are the primary object; tags are structured metadata inside them. The API must handle any tag format (current and future NIPs) without needing updates.

---

## Event Model Recap

```json
{
  "id": "32-byte hex",
  "pubkey": "32-byte hex",
  "created_at": 1234567890,
  "kind": 1,
  "tags": [
    ["e", "event-id", "wss://relay", "reply", "pubkey"],
    ["p", "pubkey", "wss://relay"],
    ["a", "30023:pubkey:d-value", "wss://relay"],
    ["d", "identifier"],
    ["k", "7"],
    ["t", "hashtag"],
    ["alt", "reply"],
    ["expiration", "1234567890"],
    ["delegation", "delegator", "conditions", "sig"],
    ["custom", "anything", "goes", "here"]
  ],
  "content": "hello",
  "sig": "64-byte hex"
}
```

**Key insight**: Every tag is a JSON array of strings. First element = name. Rest = values. No fixed schema.

---

## Implemented API (`src/protocol/event_tags.h`)

### Core: Iteration & Discovery

```c
// Iterate ALL tags in an event. Callback gets (name, values_array, count).
// values_array = tag[1..] (NULL-terminated).
// Return false to stop early.
typedef bool (*event_tag_iter_cb)(const char *name, char **values, size_t count, void *ctx);

void event_tags_foreach(const event_t *event, event_tag_iter_cb cb, void *ctx);
```

**Why**: Single function to scan everything. NIPs can filter/process as needed.

---

### Core: Lookup by Name

```c
// Get FIRST tag matching name. Returns malloc'd array of values (tag[1..], NULL-terminated).
// Example: ["e", "id", "relay", "reply", "pubkey"] -> values = ["id", "relay", "reply", "pubkey", NULL]
// Free with event_tag_free().
char **event_tag_get(const event_t *event, const char *name);

// Get ALL tags matching name. Returns malloc'd array of value-arrays (NULL-terminated outer).
// Example: multiple "p" tags -> [ ["pk1", "relay1", NULL], ["pk2", NULL], NULL ]
// Free with event_tag_free_all().
char ***event_tag_get_all(const event_t *event, const char *name, size_t *out_count);
```

**Why**: Most NIPs just need "give me the e-tag" or "all p-tags". No parsing logic in API.

---

### Core: Existence & Counting

```c
bool event_tag_has(const event_t *event, const char *name);
bool event_tag_has_value(const event_t *event, const char *name, const char *value);
size_t event_tag_count(const event_t *event, const char *name);
```

---

### Core: First Value (Most Common Case)

```c
// Convenience: get first value (tag[1]) directly. Returns strdup'd string or NULL.
// Free with free().
char *event_tag_value(const event_t *event, const char *name);
```

---

### Free Helpers (Match Return Types)

```c
// For event_tag_get() - single tag's values
void event_tag_free(char **values);

// For event_tag_get_all() - multiple tags' values
void event_tag_free_all(char ***values, size_t count);

// For event_tag_value() - single string
void free(void *ptr); // standard free()
```

---

## Complete Function List (10 functions)

| Function | Purpose | Returns | Free With |
|----------|---------|---------|-----------|
| `event_tags_foreach` | Scan all tags | void (via callback) | N/A |
| `event_tag_get` | First tag by name | `char**` (values) | `event_tag_free()` |
| `event_tag_get_all` | All tags by name | `char***` (tags) | `event_tag_free_all()` |
| `event_tag_value` | First value (tag[1]) | `char*` | `free()` |
| `event_tag_has` | Exists? | `bool` | N/A |
| `event_tag_has_value` | Name + value match | `bool` | N/A |
| `event_tag_count` | How many | `size_t` | N/A |

**Total: 7 core functions + 3 free helpers = 10 public functions**

---

## Usage Examples

### NIP-01: Basic Protocol (e, p tags)

```c
// Get all event references
char **e_refs = event_tag_get(event, "e"); // ["id", "relay", "marker", "pubkey"]
if (e_refs) {
    char *referenced_id = e_refs[0];
    char *relay = e_refs[1];
    char *marker = e_refs[2]; // "root" or "reply" (NIP-10)
    event_tag_free(e_refs);
}

// Get all pubkey references
char ***p_refs = event_tag_get_all(event, "p", &count);
for (size_t i = 0; i < count; i++) {
    char *pubkey = p_refs[i][0];
    char *relay = p_refs[i][1];
}
event_tag_free_all(p_refs, count);
```

### NIP-10: Threading (e-tag markers)

```c
char **e_tag = event_tag_get(event, "e");
if (e_tag && e_tag[2]) { // elements[2] = marker
    if (strcmp(e_tag[2], "root") == 0) { /* root of thread */ }
    else if (strcmp(e_tag[2], "reply") == 0) { /* direct reply */ }
}
event_tag_free(e_tag);
```

### NIP-09: Deletion (a, e tags)

```c
// Coordinate references
char ***a_refs = event_tag_get_all(event, "a", &count);
for (size_t i = 0; i < count; i++) {
    // a_refs[i] = ["30023:pubkey:d-value", "relay"]
    char *coord = a_refs[i][0]; // parse "kind:pubkey:d"
}
event_tag_free_all(a_refs, count);

// Event ID references
char **e_refs = event_tag_get(event, "e");
if (e_refs) { char *target_id = e_refs[0]; event_tag_free(e_refs); }
```

### NIP-33: Addressable Events (d-tag)

```c
char *d = event_tag_value(event, "d"); // first value of ["d", "identifier"]
if (d) { /* addressable event */ free(d); }
```

### NIP-25/72: Reactions (k-tag)

```c
int reacted_kind = -1;
char *k = event_tag_value(event, "k");
if (k) { reacted_kind = atoi(k); free(k); }
```

### NIP-18: Quote Repost (q-tag)

```c
char **q = event_tag_get(event, "q");
if (q) {
    char *ref = q[0];        // event-id or coordinate
    char *relay = q[1];
    char *pubkey = q[2];
    event_tag_free(q);
}
```

### NIP-12: Hashtags (t-tags)

```c
char ***t_tags = event_tag_get_all(event, "t", &count);
for (size_t i = 0; i < count; i++) {
    char *hashtag = t_tags[i][0];
}
event_tag_free_all(t_tags, count);
```

### NIP-40: Expiration

```c
char *exp = event_tag_value(event, "expiration");
if (exp) { time_t expiry = atol(exp); free(exp); }
```

### NIP-26: Delegation

```c
char **del = event_tag_get(event, "delegation");
if (del && del[1] && del[2] && del[3]) {
    char *delegator = del[1];
    char *conditions = del[2];
    char *sig = del[3];
    event_tag_free(del);
}
```

### Future NIP: Any Custom Tag

```c
// No API change needed - works for ANY tag
char **custom = event_tag_get(event, "custom");
if (custom) { /* parse custom[0], custom[1], ... */ event_tag_free(custom); }
```

---

## Implementation Notes

### `src/protocol/event_tags.c`

- Single `tag_iter_t` pass per function
- Uses existing `tag_iter.c` primitives
- No allocations beyond return values
- ~200 lines total

### Memory Ownership

| Function | Caller Must Free |
|----------|------------------|
| `event_tag_get` | `event_tag_free()` |
| `event_tag_get_all` | `event_tag_free_all()` |
| `event_tag_value` | `free()` |
| Callback values in `foreach` | Valid only during callback |

---

## What This Replaces

| Old API | New API |
|---------|---------|
| `event_d_value(e)` | `event_tag_value(e, "d")` |
| `event_k_value(e)` | `event_tag_value(e, "k")` + `atoi()` |
| `event_has_d(e, id)` | `event_tag_has_value(e, "d", id)` |
| `event_tag_get_all` (complex) | `event_tag_get_all(e, "p", &n)` |
| `event_tag_free_values` | `event_tag_free()` / `event_tag_free_all()` |
| `tag_find`, `tag_find_all_values`, etc. | `event_tag_get`, `event_tag_get_all` |

---

## Why This Works Forever

1. **No tag-specific code** - NIPs pass tag name as string
2. **Variable-length tags** - Returns full value array, NIP parses
3. **No schema assumptions** - Works for any JSON array of strings
4. **Extensible** - New NIPs = new tag names, zero API changes
5. **Minimal surface** - 7 core functions, easy to learn

---

## Migration Status

- [x] Update `event_tags.h/c` with new signatures
- [x] Update all NIPs (`nip01.c`, `nip09.c`, `nip17.c`, `nip40.c`, `nip42.c`, `nip62.c`, etc.)
- [x] Update `crypto.c` (delegation check)
- [x] Update `subscription_manager.c` (filter matching)
- [x] Update `nip_template.c`
- [x] Verify build passes

---

## Non-Goals

- No typed structs for tags (e.g., `event_ref_t`) - NIPs define their own
- No validation of tag content - NIPs validate
- No automatic parsing of coordinates - NIP-09 parses "kind:pubkey:d"
- No relay URL normalization - NIPs handle