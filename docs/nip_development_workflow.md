# NIP Development Workflow

This document describes the process for creating a new NIP (Nostr Implementation Possibility) in the nostrogotho relay.

## Overview

A NIP is a self-contained C file in `src/nips/` that registers capabilities via a constructor. The build system automatically discovers and compiles all `src/nips/*.c` files (except `nip_template.c`). Each NIP is loaded:
- **Monolithic builds**: At startup via constructor before `main()`
- **Hot-reload (`-hr`) builds**: On every module reload without dropping sockets

## Creating a New NIP

### Step 1: Copy the Template

```bash
cp src/nips/nip_template.c src/nips/nipXX.c
```

Replace `XX` with your NIP number.

### Step 2: Rename Symbols

Replace all `nipxx_` prefixes with your NIP identifier (e.g., `nip42_` for NIP-42):

```c
// Before
typedef struct { ... } nipxx_ctx_t;
static nipxx_ctx_t nipxx_ctx;
static void nipxx_lifecycle_init(...) { ... }

// After
typedef struct { ... } nip42_ctx_t;
static nip42_ctx_t nip42_ctx;
static void nip42_lifecycle_init(...) { ... }
```

Update:
- Context struct and instance name
- All function names
- Capability descriptors in `nipxx_caps[]`
- Registration function `nipxx_register()`
- Constructor function `nipxx_register_provider()`

### Step 3: Implement Only Required Capabilities

The template includes all capability types. **Delete unused ones** — keep only what your NIP needs.

#### Available Capability Types

| Type | Purpose | Composition Rule |
|------|---------|------------------|
| `NIP_CAP_LIFECYCLE` | Init/shutdown per process or module generation | Runs once per generation |
| `NIP_CAP_CONNECTION` | Connection open/close hooks | All run |
| `NIP_CAP_MESSAGE_INTERCEPT` | Intercept parsed messages (custom verbs) | First `true` wins |
| `NIP_CAP_PUBLICATION_POLICY` | Accept/reject EVENT before kind dispatch | **ALL must permit** (AND) |
| `NIP_CAP_KIND_HANDLER` | Handle specific event kinds | ALL matched; reject wins (AND on accepted) |
| `NIP_CAP_DELIVERY_POLICY` | Filter event delivery per connection | **ANY may veto** |
| `NIP_CAP_QUERY_POLICY` | Authorize REQ queries | **ALL must permit** |
| `NIP_CAP_MAINTENANCE` | Periodic timer callbacks | **ALL run** each tick |
| `NIP_CAP_METADATA` | NIP-11 info document fragment | First non-NULL wins |
| `NIP_CAP_PROTOCOL_RESPONSE` | Build EOSE/COUNT/auth responses | First non-NULL wins |

### Step 4: Implement Capability Hooks

Each capability has specific function signatures defined in `nip_capability.h`. Key rules:

- **Never use Mongoose or SQLite directly** — use opaque `connection_id_t` and `storage_context_t`
- **Never send OK/EOSE/CLOSED** — return policy decisions; relay core handles framing (exception: NIP-42 message-intercept MUST send `OK` for AUTH and MAY push `AUTH` challenges via `nip_env_send_json`)
- **State management**: Use static context struct (dies with module generation on reload) for re-derivable config; persistent auth lives in host-owned sessions via `nip_env_session_*`. Avoid heap allocation unless freed in shutdown.

#### Example: Publication Policy Hook

```c
static bool nip42_accept_publish(connection_id_t id, const event_t *event,
                                 char *reason, size_t reason_size, void *ctx) {
    // Check auth requirement
    if (event_requires_auth(event) && !connection_is_authed(id)) {
        snprintf(reason, reason_size, "auth-required: %s", nip42_get_auth_challenge());
        return false;
    }
    return true;
}
```

#### Example: Kind Handler

```c
static bool nip42_handles_kind(int kind, void *ctx) {
    return kind == 22242;  // NIP-42 uses kind 22242
}

static nip01_process_result_t nip42_process_event(connection_id_t id, const event_t *event,
                                                  storage_context_t *storage,
                                                  const char *relay_url, void *ctx) {
    nip01_process_result_t r = {0};
    storage_insert_result_t sr = storage->insert_record(event, NULL, 0);
    if (sr.result == STORAGE_OK || sr.result == STORAGE_DUPLICATE) {
        r.accepted = true;
        r.should_store = true;
        r.should_broadcast = true;
    } else {
        snprintf(r.response_msg, sizeof(r.response_msg), "error: %s", sr.error_message);
    }
    return r;
}
```

### Step 5: Register Capabilities

Trim the `nipxx_caps[]` array to only your implemented capabilities, then register with `NIP_REGISTER`:

```c
static nip_capability_t nip42_caps[] = {
    {
        .name = "nip42-lifecycle",
        .type = NIP_CAP_LIFECYCLE,
        .ctx = &nip42_ctx,
        .caps.lifecycle = { .init = nip42_lifecycle_init, .shutdown = nip42_lifecycle_shutdown },
    },
    {
        .name = "nip42-publication",
        .type = NIP_CAP_PUBLICATION_POLICY,
        .ctx = &nip42_ctx,
        .caps.publication_policy = { .accept_publish = nip42_accept_publish },
    },
    {
        .name = "nip42-kind",
        .type = NIP_CAP_KIND_HANDLER,
        .ctx = &nip42_ctx,
        .caps.kind_handler = { .handles_kind = nip42_handles_kind, .process_event = nip42_process_event },
    },
};

NIP_REGISTER(nip42, nip42_caps)
```

The `NIP_REGISTER` macro expands to both the registration function and the constructor — no manual boilerplate needed.

## Build & Test

### Monolithic Build

```bash
nob
```

### Hot-Reload Development

```bash
nob win -hr    # Windows
nob linux -hr  # Linux
```

Save your file — the module reloads without dropping connections.

## Architecture Rules (Enforced)

1. **No transport access**: NIPs never see `struct mg_connection` or SQLite
2. **No direct protocol responses**: Return decisions; relay core serializes + sends
3. **Stateless across reloads**: Module statics reset on `-hr` reload; use `connection_session_t` for persistent state
4. **Deterministic composition**: Rules are architecture-enforced, not convention:
   - Publication: ALL must permit (AND)
   - Delivery: ANY may veto
   - Kind handlers: ALL matched consulted; any rejection wins (AND on accepted)
   - Maintenance: ALL run
   - EOSE/COUNT/Metadata: First non-NULL wins

## Capability Interface Reference

See `src/nips/nip_capability.h` for:
- `nip_capability_type_t` enum
- `nip_capability_t` struct with all capability unions
- `nip_registry_t` and registration functions
- Composition functions (`nip_composition_*`)

## Example NIPs to Reference

- `src/nips/nip01.c` — Core event handling (replaceable/addressable)
- `src/nips/nip42.c` — Authentication (publication + delivery + query policy, AUTH intercept, kind 22242 guard; OK/AUTH sends are the sanctioned exception to "no direct responses")
- `src/nips/nip11.c` — Metadata (info document)
- `src/nips/nip09.c` — Event deletion (kind 5 handler)
- `src/nips/nip17.c` — Gift-wrap gating (delivery policy + auth-hint)
- `src/nips/nip40.c` — Expiration (publication + delivery + maintenance)
- `src/nips/nip62.c` — Vanish (kind handler)
- `src/nips/nip45.c` — Count (protocol response)
- `src/nips/nip67.c` — EOSE hint (protocol response)
- `src/nips/nip26.c` — Delegation (publication policy)
- `src/nips/nip13.c` — PoW (publication policy + lifecycle)

## Common Patterns

### Using Storage from NIP Code

```c
#include "storage.h"
#include "protocol/event_tags.h"

// Find events matching scope
storage_event_scope_t scope = {
    .pubkey = pubkey,
    .has_kind = true,
    .kind = 1,
    .limit = 50
};
event_t **events = NULL;
size_t count = 0;
if (storage->find_events(&scope, &events, &count)) {
    for (size_t i = 0; i < count; i++) {
        // process events[i]
        event_free(events[i]);
    }
    free(events);
}

// Atomic upsert for replaceable events (kinds 0, 3, 10000-19999)
storage_insert_result_t result = storage->upsert_replaceable(event, indexed_tags, indexed_tags_count);

// Atomic upsert for addressable events (kinds 30000-39999)
char *d_tag = event_tag_value(event, "d");
storage_insert_result_t result = storage->upsert_addressable(event, d_tag, indexed_tags, indexed_tags_count);
free(d_tag);
```

### Using Event Tags

```c
#include "protocol/event_tags.h"

// Get first value
char *d = event_tag_value(event, "d");
if (d) { /* ... */ free(d); }

// Get all values for first tag
char **values = event_tag_get(event, "p");
if (values) {
    for (size_t i = 0; values[i]; i++) { /* process values[i] */ }
    event_tag_free(values);
}

// Get all tags with name
char ***all_p = event_tag_get_all(event, "p", &count);
for (size_t i = 0; i < count; i++) {
    for (size_t j = 0; all_p[i][j]; j++) { /* process all_p[i][j] */ }
}
event_tag_free_all(all_p, count);
```

### Sending JSON Responses

```c
#include "protocol/protocol.h"
#include "nips/nip_env.h"

// Send OK
char *ok = protocol_serialize_ok(event_id, true, "");
nip_env_send_json(conn_id, ok);
protocol_free_string(ok);

// Send EVENT
char *ev_json = protocol_serialize_event(sub_id, event);
nip_env_send_json(conn_id, ev_json);
protocol_free_string(ev_json);

// Send EOSE
char *eose = protocol_serialize_eose(sub_id, has_more, auth_hint);
nip_env_send_json(conn_id, eose);
protocol_free_string(eose);

// Send COUNT
char *count = protocol_serialize_count(sub_id, count_val);
nip_env_send_json(conn_id, count);
protocol_free_string(count);
```

### NIP-42 Session Auth (from NIP code)

```c
#include "nips/nip_env.h"

// Get/set challenge
const char *challenge = nip_env_session_challenge(conn_id);
nip_env_session_set_challenge(conn_id, new_challenge);

// Multi-pubkey auth (NIP-42 extension)
nip_env_session_add_auth(conn_id, pubkey);
bool is_authed = nip_env_session_has_auth(conn_id, pubkey);
size_t count = nip_env_session_auth_count(conn_id);
const char *pk = nip_env_session_auth_at(conn_id, index);

// Clear all auth
nip_env_session_clear_auth(conn_id);
```

## Template Reference (`src/nips/nip_template.c`)

The template file shows all capability types with commented implementations. Copy it, rename, and uncomment only what you need. The template is excluded from the build glob (`nob_common.h:nob_add_nip_sources()` skips it).