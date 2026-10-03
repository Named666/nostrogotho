# Nostrogotho API Reference

Source of truth: headers under `src/`. Field names, signatures, and ownership notes mirror them verbatim.

## Architecture Overview

```
Clients
   │
   ▼
Transport (`src/transport/server.h`: Mongoose HTTP/WebSocket loop only)
   │
   ▼
Protocol (`src/protocol/protocol.h`: parse/dispatch/serialize)
   │
   ├──▶ Crypto/validation (`src/crypto.h`: structure, ID, sig, NIP-26 delegation)
   │
   ├──▶ Subscriptions (`src/subscriptions/subscription_manager.h`: lifecycle, matching, delivery)
   │
   ▼
Policy (`src/relay/relay.h` + `src/nips/nip_capability.h`: relay core + NIP capabilities)
   │
   ▼
Storage API (`src/storage.h`: abstract interface, SQLite backend in `src/storage.c`)
```

**Key principle**: Nostr protocol semantics must not depend on how the relay transports or stores data. NIP code never sees `struct mg_connection` or SQLite; it uses opaque `connection_id_t` (`src/relay/connection_session.h`) and `storage_context_t`.

There is no `src/validation/` module. Validation is `check_event()` / `check_event_core()` / `check_delegation()` in `src/crypto.h`, called via `nip_env_accepts_event()` from NIP code.

---

## Core Types (`src/nostrogotho.h`)

### `event_t` — a single Nostr event

```c
typedef struct {
    char id[MAX_ID_SIZE + 1];         // 64 hex + NUL
    char pubkey[MAX_PUBKEY_SIZE + 1]; // 64 hex + NUL
    time_t created_at;
    int kind;
    char *tags_json;      // malloc'd JSON array string, may be NULL
    size_t tags_json_len;
    char *content;        // malloc'd, may be NULL
    size_t content_len;
    char sig[MAX_SIG_SIZE + 1]; // 128 hex + NUL
} event_t;
```

Bounds (`src/nostrogotho.h:29-36`): `MAX_ID_SIZE 64`, `MAX_PUBKEY_SIZE 64`, `MAX_SIG_SIZE 128`, `MAX_CONTENT_SIZE 65536`, `MAX_TAGS_SIZE 65536`, `MAX_TAG_ELEMENTS 256`, `MAX_TAG_SIZE 512`.

### `filter_t` — NIP-01 subscription filter

```c
typedef struct {
    char **ids; size_t ids_count;
    char **authors; size_t authors_count;
    int *kinds; size_t kinds_count;
    tag_t *tags; size_t tags_count;
    time_t since;
    time_t until;
    int limit;
    char *search;
} filter_t;
```

Multiple filters in one REQ are OR'd; criteria inside one filter are AND'd.

### `tag_t` / `tags_array_t`

```c
typedef struct { char **elements; size_t count; size_t capacity; } tag_t;
typedef struct { tag_t *tags; size_t count; } tags_array_t;
```

### Memory management (`src/nostrogotho.h:161-222`)

| Alloc | Release fields only (stack object) | Free object + fields (heap object) |
|---|---|---|
| `event_t *event_alloc(void)` | `event_release(event_t*)` | `event_free(event_t*)` |
| `filter_t *filter_alloc(void)` | `filter_release(filter_t*)` | `filter_free(filter_t*)` |
| `tag_t *tag_alloc(size_t n)` | — (no public `tag_release`; static in `src/nostrogotho.c:188`) | `tag_free(tag_t*)` |
| `tags_array_t *tags_array_alloc(size_t n)` | — | `tags_array_free(tags_array_t*)` |

All free functions are NULL-safe. `event_release` / `filter_release` do NOT free the struct itself — use them for stack objects (e.g. `protocol_message_t` payloads filled by `json_parse_event()`).

Example:

```c
#include "nostrogotho.h"

event_t *ev = event_alloc();
if (!ev) return false;
/* fill id/pubkey/created_at/kind/tags_json/content/sig ... */
event_free(ev); // frees tags_json + content + struct

filter_t stack_f; // filled by json_parse_filter()
filter_release(&stack_f); // do NOT filter_free() a stack object
```

---

## Configuration (`src/relay/config.h`, `src/relay/config.c`, `src/relay/config_file.c`, `src/main.c`)

Single authoritative struct. String fields are fixed-size buffers owned by the struct (never borrowed `argv`/`env` pointers).

```c
typedef struct {
    char database_path[1024];   // default "./nostrogotho.sqlite"
    int port;                   // default 7447
    char service_url[256];      // default "wss://relay.example.com" (MUST be changed)
    int verbosity;              // log_verbosity_t 0-3, default 0; replaces old bool debug_logging
    int min_pow_difficulty;     // default 0 = disabled
    time_t created_at_lower_limit; // default 0 = disabled
    time_t created_at_upper_limit; // default 900
    int max_ws_message_length;  // default 5*1024*1024
    int max_event_content_length; // default 65536
    int max_event_tags;         // default 100
    int max_subscriptions_per_connection; // default 50
    int max_filters_per_subscription;     // default 10
    int max_subscription_id_length;       // default 100
    int max_query_limit;        // default 500
    bool hot_reload_enabled;    // default false
    char hot_reload_module_path[1024]; // "build/nostrogotho.dll" (Windows) / "build/nostrogotho.so" (Linux)
    storage_context_t *storage; // runtime state, never loaded from file
} relay_config_t;
```

API:

```c
void relay_config_init(relay_config_t *config);
bool relay_config_validate(const relay_config_t *config, char *err, size_t errsz);
bool relay_config_load(const char *path, relay_config_t *config, char *err, size_t errsz);
bool relay_config_write_defaults(const char *path); // never overwrites
void relay_config_warn_unknown(const char *path);
```

Precedence (applied in `src/main.c:main`): `compiled defaults < file < environment < CLI`. Missing file is created with defaults; unknown keys warn via `relay_config_warn_unknown()`; wrong-type values are hard errors.

Changing config — three supported ways (highest wins):

```c
// 1. File: ./config.json (or --config path / CONFIG_PATH)
{ "port": 7447, "service_url": "wss://relay.example.com",
  "limits": { "max_query_limit": 500, "min_pow_difficulty": 0 } }

// 2. Env: DATABASE_URL, SERVICE_URL, MIN_POW_DIFFICULTY,
//    CREATED_AT_LOWER_LIMIT, CREATED_AT_UPPER_LIMIT,
//    NHR_MODULE_PATH, VERBOSITY

// 3. CLI: -database/--db, -port/--port, -service-url, --debug[=0..3],
//    --hot-reload, --module, -min-pow, -created-at-lower-limit,
//    -created-at-upper-limit  (src/main.c:print_usage)
```

Validation notes (`src/relay/config.c:72-113`): `port` 1-65535; `verbosity` 0-3; limits non-negative with stated maxima; `database_path` non-empty; `service_url` non-empty and not the placeholder. NIP-42 auth is always on — there are no `nip42.*` toggles.

NIPs read config read-only in lifecycle `init(const relay_config_t*, void*)` and should copy what they need into their static ctx (see template below).

---

## Event Tag Helpers (`src/protocol/event_tags.h`, low level in `src/protocol/tag_iter.h`)

Generic, future-proof: every tag is `["name", value1, value2, ...]`. No tag-specific code in the API.

```c
typedef bool (*event_tag_iter_cb)(const char *name, char **values, size_t count, void *ctx);
void event_tags_foreach(const event_t *event, event_tag_iter_cb cb, void *ctx);

char **event_tag_get(const event_t *event, const char *name); // first tag's values (tag[1..]), free with event_tag_free()
char ***event_tag_get_all(const event_t *event, const char *name, size_t *out_count); // free with event_tag_free_all()
char *event_tag_value(const event_t *event, const char *name); // strdup'd tag[1] or NULL, free with free()

bool event_tag_has(const event_t *event, const char *name);
bool event_tag_has_value(const event_t *event, const char *name, const char *value);
size_t event_tag_count(const event_t *event, const char *name);

void event_tag_free(char **values);
void event_tag_free_all(char ***values, size_t count);
```

Examples:

```c
#include "protocol/event_tags.h"

// NIP-09: all "e" targets of a kind-5 deletion
size_t n = 0;
char ***es = event_tag_get_all(event, "e", &n);
for (size_t i = 0; i < n; i++) { const char *target_id = es[i][0]; /* ... */ }
event_tag_free_all(es, n);

// NIP-33: addressable identifier
char *d = event_tag_value(event, "d");
if (d) { /* ... */ free(d); }

// NIP-40: expiry
char *exp = event_tag_value(event, "expiration");
if (exp) { time_t expiry = (time_t)atol(exp); free(exp); }
```

---

## Crypto (`src/crypto.h`)

Windows CNG for SHA-256; bundled secp256k1 for Schnorr.

```c
bool crypto_init(void);   // once at startup, before any other crypto call
void crypto_deinit(void); // once at shutdown

void sha256(const uint8_t *data, size_t len, uint8_t digest[32]);
char *bytes_to_hex(const uint8_t *bytes, size_t len); // caller free()s
bool hex_to_bytes(const char *hex, size_t hex_len, uint8_t *bytes, size_t max_bytes, size_t *out_len);

bool signature_verify(const char *sig_hex, const char *pubkey_hex, const uint8_t digest[32]);
bool check_event(const event_t *ev);      // ID + signature + delegation
bool check_event_core(const event_t *ev); // ID + signature only
bool check_event_id(const event_t *ev);
bool check_signature(const event_t *ev);
bool check_delegation(const event_t *ev, const char *delegator_pubkey,
                      const char *conditions, const char *delegation_sig);

size_t event_build_hash_input(const event_t *ev, char *buffer, size_t buffer_size);
size_t event_hash_input_size(const event_t *ev);
char *event_compute_id(const event_t *ev); // caller free()s
size_t json_escape(const char *src, char *dst, size_t dst_size);
int count_leading_zero_bits(const char *hex); // NIP-13 PoW
```

NIP code must NOT include `crypto.h` directly. Use the host-env forwarders in `src/nips/nip_env.h` (same call in monolithic and module builds):

```c
bool nip_env_accepts_event(const event_t *event); // full check_event()
unsigned nip_env_count_leading_zero_bits(const char *hex); // NIP-13
```

Example (host-side validation before storage):

```c
#include "crypto.h"
crypto_init();
if (check_event(ev)) { /* store */ }
crypto_deinit();
```

NIP-26 delegation helpers used by the core (`src/nips/nip26.h`): `nip26_check_delegation()`, `nip26_extract_index_tags()` / `nip26_free_index_tags()`, `nip26_query_index_tags()`.

---

## Protocol (`src/protocol/protocol.h`, `src/protocol/parser.h`, `src/protocol/filter_builder.h`, `src/json_util.h`)

### Parsed messages

```c
typedef enum {
    PROTOCOL_CMD_UNKNOWN = 0,
    PROTOCOL_CMD_EVENT,
    PROTOCOL_CMD_REQ,
    PROTOCOL_CMD_CLOSE,
    PROTOCOL_CMD_AUTH,
    PROTOCOL_CMD_COUNT
} protocol_command_t;

typedef struct {
    protocol_command_t command;
    union {
        struct { event_t event; } event; // OWNED
        struct { char *subscription_id; filter_t *filters; size_t filters_count; } req; // OWNED until REQ success transfers filters to subscription_manager
        struct { char *subscription_id; } close; // OWNED
        struct { char *challenge; bool has_event; event_t event; } auth; // OWNED
        struct { char *subscription_id; filter_t *filters; size_t filters_count; } count; // OWNED, never transferred
    } payload;
} protocol_message_t;

#define PROTOCOL_MAX_FILTERS 10 // wire-safety cap; relay policy may enforce a smaller max_filters_per_subscription

bool protocol_parse_client_message(const char *data, size_t length,
                                   const relay_config_t *config,
                                   protocol_message_t *out,
                                   char *reject_reason, size_t reason_size);
// On success caller owns out and must call protocol_message_free() exactly once.
void protocol_message_free(protocol_message_t *msg);
bool protocol_collect_filters(json_value_t *values, size_t count,
                              filter_t **out, size_t *out_count, size_t max_filters);
```

Size limits from `relay_config_t` are enforced before allocation.

### Serialization (all return heap strings; free with `protocol_free_string()`)

```c
char *protocol_serialize_ok(const char *event_id, bool accepted, const char *reason);
char *protocol_serialize_event(const char *subscription_id, const event_t *event);
char *protocol_serialize_eose(const char *subscription_id, bool has_more, bool auth_hint);
char *protocol_serialize_count(const char *subscription_id, unsigned long count);
char *protocol_serialize_closed(const char *subscription_id, bool ok, const char *reason);
char *protocol_serialize_notice(const char *message);
char *protocol_serialize_auth(const char *challenge);
void protocol_free_string(char *str);
```

NIP code builds frames with these and sends via `nip_env_send_json()` — never via Mongoose. Normal EVENT/REQ flow returns policy decisions; the relay core owns OK/EOSE/CLOSED framing. The sanctioned exception is NIP-42: its message-intercept MUST send `OK` for AUTH and MAY push `AUTH` challenges via `nip_env_send_json()`.

### Filter builder (`src/protocol/filter_builder.h`)

Fluent helper for constructing `filter_t` in tests/tools:

```c
filter_builder_t *filter_builder_new(void);
filter_builder_t *filter_builder_ids(filter_builder_t*, const char **ids, size_t n);
filter_builder_t *filter_builder_kinds(filter_builder_t*, const int *kinds, size_t n);
filter_builder_t *filter_builder_authors(filter_builder_t*, const char **pubkeys, size_t n);
filter_builder_t *filter_builder_d_tags(filter_builder_t*, const char **values, size_t n);
filter_builder_t *filter_builder_k_tags(filter_builder_t*, const int *kinds, size_t n);
filter_builder_t *filter_builder_tag(filter_builder_t*, const char *name, const char **values, size_t n);
filter_builder_t *filter_builder_since(filter_builder_t*, time_t since);
filter_builder_t *filter_builder_until(filter_builder_t*, time_t until);
filter_builder_t *filter_builder_limit(filter_builder_t*, size_t limit);
filter_t *filter_builder_build(filter_builder_t*); // heap filter; caller frees with filter_release()+free or filter_free()
void filter_builder_free(filter_builder_t*);
```

### JSON utilities (`src/json_util.h`)

Low-level Nostr JSON: `json_array_parse()` / `json_array_free()`, `json_parse_filter()` / `json_parse_event()`, `json_builder_*` + `json_builder_dup()`, `json_serialize_event()` / `json_serialized_event_size()`. `JSON_BUILDER_BUFFER_SIZE` is 65536 — events that cannot serialize within it must be rejected before storage.

---

## NIP Capability Interface (`src/nips/nip_capability.h`)

NIPs declare capabilities; the relay core handles transport. Registry deep-copies each descriptor (`nip_registry_register()`); `ctx` stays owned by the registrant (prefer a file-static struct, never heap-allocate per register — the registry never frees `ctx`).

### Capability types and composition (deterministic, enforced)

| Type | Hooks | Composition |
|------|-------|-------------|
| `NIP_CAP_LIFECYCLE` | `init(config, ctx)`, `shutdown(ctx)` | all run, once per process / module generation |
| `NIP_CAP_CONNECTION` | `on_connect(id, ctx)`, `on_disconnect(id, ctx)` | all run |
| `NIP_CAP_MESSAGE_INTERCEPT` | `on_message(id, msg, ctx) -> bool` | first `true` consumes |
| `NIP_CAP_PUBLICATION_POLICY` | `accept_publish(id, event, reason, reason_size, ctx) -> bool` | ALL must permit (AND) |
| `NIP_CAP_KIND_HANDLER` | `handles_kind(kind, ctx) -> bool`, `process_event(id, event, storage, relay_url, ctx) -> nip01_process_result_t` | ALL matched consulted; any rejection wins (AND on `accepted`; `should_broadcast`/`should_store` are OR) |
| `NIP_CAP_DELIVERY_POLICY` | `can_deliver(event, id, ctx) -> bool` | ANY may veto |
| `NIP_CAP_QUERY_POLICY` | `authorize_query(id, filters, count, reason, reason_size, ctx) -> bool` | ALL must permit (AND). No `modify_results` hook (removed, ABI v7) |
| `NIP_CAP_MAINTENANCE` | `timer(storage, ctx)`, `interval_ms` | ALL run each tick (smallest interval drives the timer) |
| `NIP_CAP_METADATA` | `info_document(ctx) -> const char*` | first non-NULL wins (NIP-11) |
| `NIP_CAP_PROTOCOL_RESPONSE` | `build_eose(sub, has_more, auth_hint, ctx)`, `build_count(sub, count, ctx)`, `needs_auth_hint(filters, n, id, ctx)`, `send_auth_challenge(id, ctx)` | `build_*`: first non-NULL wins; `needs_auth_hint`: ANY (OR); `send_auth_challenge`: ALL run |

Kind-handler decision (`src/nips/nip_capability.h:31-36`):

```c
typedef struct {
    bool accepted;
    bool should_broadcast;
    bool should_store;
    char response_msg[256];
} nip01_process_result_t;
```

Composition entry points used by the relay core (`nip_composition_check_publication`, `nip_composition_check_delivery`, `nip_composition_process_kind`, `nip_composition_authorize_query`, `nip_composition_run_maintenance`, `nip_composition_build_eose/count`, `nip_composition_get_info_document`, `nip_composition_needs_auth_hint`, `nip_composition_send_auth_challenge`, `nip_composition_run_init/shutdown`, `nip_composition_notify_connect/disconnect`, `nip_composition_on_message`).

### Registration — the ONLY boilerplate

`NIP_REGISTER(name, caps_array)` (`src/nips/nip_capability.h:311-319`) expands to `name_register()` plus the constructor. Self-registration via `nip_capability_add_provider()` means adding/removing a NIP is adding/deleting its `.c` file — no list edits. `nip_template.c` is excluded from the build glob.

```c
#include "nip_capability.h"
#include "nips/nip_env.h" // send/session/validate — same call in all builds

typedef struct { char service_url[256]; } nip42_ctx_t;
static nip42_ctx_t nip42_ctx;

static void nip42_lifecycle_init(const relay_config_t *config, void *ctx) {
    snprintf(((nip42_ctx_t*)ctx)->service_url,
             sizeof(((nip42_ctx_t*)ctx)->service_url), "%s", config->service_url);
}
static bool nip42_accept_publish(connection_id_t id, const event_t *event,
                                 char *reason, size_t reason_size, void *ctx) {
    (void)id; (void)event; (void)ctx;
    return true; // or: snprintf(reason, reason_size, "auth-required: ..."); return false;
}

static nip_capability_t nip42_caps[] = {
    { .name = "nip42-lifecycle", .type = NIP_CAP_LIFECYCLE, .ctx = &nip42_ctx,
      .caps.lifecycle = { .init = nip42_lifecycle_init, .shutdown = NULL }, },
    { .name = "nip42-publication", .type = NIP_CAP_PUBLICATION_POLICY, .ctx = &nip42_ctx,
      .caps.publication_policy = { .accept_publish = nip42_accept_publish }, },
};

NIP_REGISTER(nip42, nip42_caps)
```

Rules (see `src/nips/nip_template.c:18-37`):

- Never include `relay/relay.h`, `crypto.h`, or `nhr_module.h`; never test `NHR_BUILD_MODULE`. Use `nips/nip_env.h` only.
- Connections are `connection_id_t` (`uintptr_t`); storage is `storage_context_t*`; replies use `protocol_serialize_*` + `nip_env_send_json()`.
- Persistent auth lives in host-owned sessions via `nip_env_session_*`; module statics die on every `-hr` reload (re-derivable config only).

Reference NIPs: `nip01.c` (replaceable/addressable), `nip42.c` (auth), `nip11.c` (metadata), `nip09.c` (kind-5 deletion), `nip17.c` (gift-wrap gating). Full workflow: `docs/nip_development_workflow.md`.

---

## NIP Host Environment (`src/nips/nip_env.h`)

The only API NIP `.c` files may use for transport, session-auth, and validation:

```c
void nip_env_send_json(connection_id_t id, const char *json); // no-op when unknown

const char *nip_env_session_challenge(connection_id_t id);
bool nip_env_session_set_challenge(connection_id_t id, const char *challenge);
const char *nip_env_session_auth_pubkey(connection_id_t id); // first pubkey (compat)
bool nip_env_session_set_auth(connection_id_t id, const char *pubkey);
bool nip_env_session_add_auth(connection_id_t id, const char *pubkey);
bool nip_env_session_has_auth(connection_id_t id, const char *pubkey);
size_t nip_env_session_auth_count(connection_id_t id);
const char *nip_env_session_auth_at(connection_id_t id, size_t index);
void nip_env_session_clear_auth(connection_id_t id);
size_t nip_env_session_snapshot(connection_snapshot_t *out, size_t capacity);

bool nip_env_accepts_event(const event_t *event);
unsigned nip_env_count_leading_zero_bits(const char *hex);
```

Borrowed session strings are valid until the next session mutation for that connection — copy them if retained. `nip_env.c` selects the backend (direct relay calls vs. `Nhr_Host` shims) so NIP code never branches on build mode.

Connection/session lifecycle itself (`src/relay/connection_session.h`, host-side only): `connection_session_create/destroy/get`, auth-pubkey add/has/count/at, challenge get/set, `auth_state_t` (`AUTH_STATE_NONE/CHALLENGED/AUTHENTICATED`), snapshot/restore for hot reload. NIP-42's connection-ID API (`src/nips/nip42.h`): `nip42_open_by_id`, `nip42_authenticate_by_id`, `nip42_is_pubkey_authenticated`, `nip42_send_auth_challenge`, `nip42_close_by_id`.

---

## Storage API (`src/storage.h`, backend `src/storage.c`)

Abstract `storage_context_t` (function pointers; init once, `deinit` at shutdown; NOT thread-safe). Ownership: `find_*` / `get_event_by_id` / `find_ids_by_tags` TRANSFER ownership to the caller; `insert` / `delete` / `count` BORROW their inputs.

### Result types

```c
typedef enum {
    STORAGE_OK = 0, STORAGE_DUPLICATE, STORAGE_NOT_FOUND,
    STORAGE_ERROR, STORAGE_INVALID_ARGUMENT
} storage_result_t;

typedef struct { storage_result_t result; char error_message[256]; } storage_insert_result_t;
typedef struct { storage_result_t result; int deleted_count; char error_message[256]; } storage_delete_result_t;
typedef struct { storage_result_t result; size_t count; char error_message[256]; } storage_count_result_t;
```

### Selection scope (unified read/count/delete selector)

`storage_event_scope_t` (`src/storage.h:64-122`): `id`, `after_id`, `ids[]`, `pubkey`, `pubkeys[]`, `has_kind/kind`, `kinds[]`, `has_created_at_before/created_at_before` (`<`), `has_created_at_at_or_before/*` (`<=`), `has_created_at_after/*` (`>`), `has_created_at_at_or_after/*` (`>=`), `has_excluded_kind/excluded_kind`, `excluded_kinds[]`, `tag_names[]/tag_values[]/tag_count` (AND of pairs), `limit` (0 = backend default), `offset`.

### Context operations (`src/storage.h:159-298`)

```c
bool (*init)(const char *dsn); // SQLite: "file:nostrogotho.sqlite" or ":memory:"
void (*deinit)(void);

event_t *(*get_event_by_id)(const char *id); // caller event_free()s
storage_insert_result_t (*insert_record)(const event_t*, const storage_tag_match_t*, size_t);
storage_delete_result_t (*delete_record_by_id_and_pubkey)(const char *id, const char *pubkey);
storage_delete_result_t (*delete_record_by_kind_and_pubkey)(int kind, const char *pubkey, time_t created_at);

bool (*find_events)(const storage_event_scope_t*, event_t ***out, size_t *n); // caller event_free()s each + free()s array
bool (*count_events)(const storage_event_scope_t*, size_t *n);
bool (*delete_events)(const storage_event_scope_t*, size_t *deleted);

storage_transaction_t *(*transaction_begin)(void);
bool (*transaction_commit)(storage_transaction_t*);
void (*transaction_rollback)(storage_transaction_t*);
bool (*delete_events_tx)(const storage_event_scope_t*, storage_transaction_t*, size_t*);
bool (*find_events_tx)(const storage_event_scope_t*, storage_transaction_t*, event_t***, size_t*);

storage_insert_result_t (*upsert_replaceable)(const event_t*, const storage_tag_match_t*, size_t);
storage_insert_result_t (*upsert_addressable)(const event_t*, const char *d_tag_value,
                                              const storage_tag_match_t*, size_t);
bool (*find_ids_by_tags)(const char *const *names, const char *const *values, size_t n,
                         char ***ids_out, size_t *count_out); // caller free_id_list()s
void (*free_id_list)(char **ids, size_t count);
```

Free functions with the same signatures exist for host code that bypasses the context (`storage_find_events`, `storage_count_events`, `storage_delete_events`, `storage_*_tx`, `storage_upsert_replaceable/addressable`, `storage_find_ids_by_tags`, `storage_free_id_list`), plus `storage_context_init_sqlite3()` and `escape_like()`.

Removed APIs (do not use): `delete_matching` + `storage_event_predicate_t`, `find_ids_by_tag` (singular), `send_records`. Tag policy lives in NIP code via `event_tag_has_value()`; storage evaluates the scope only.

Examples:

```c
#include "storage.h"

storage_context_t ctx = {0};
storage_context_init_sqlite3(&ctx);
ctx.init("./nostrogotho.sqlite");

// Insert (borrowed)
storage_tag_match_t *idx = NULL; size_t idx_n = 0;
// ... extract via nip26_extract_index_tags() or generic single-letter indexer ...
storage_insert_result_t ir = ctx.insert_record(ev, idx, idx_n);

// Find newest 50 kind-1 events by one author (transferred)
storage_event_scope_t scope = {
    .pubkey = pk, .has_kind = true, .kind = 1, .limit = 50,
};
event_t **out = NULL; size_t n = 0;
if (ctx.find_events(&scope, &out, &n)) {
    for (size_t i = 0; i < n; i++) event_free(out[i]);
    free(out);
}

// Atomic replaceable upsert (kinds 0, 3, 10000-19999)
storage_insert_result_t up = ctx.upsert_replaceable(ev, idx, idx_n);

// Addressable upsert (kinds 30000-39999)
char *d = event_tag_value(ev, "d");
storage_insert_result_t ua = ctx.upsert_addressable(ev, d, idx, idx_n);
free(d);

// NIP-09 delete by id + author check
storage_delete_result_t dr = ctx.delete_record_by_id_and_pubkey(id, pubkey);

// NIP-62 vanish: everything by author at/before T except the vanish event kind
storage_event_scope_t vanish = {
    .pubkey = ev->pubkey,
    .has_created_at_at_or_before = true, .created_at_at_or_before = ev->created_at,
    .has_excluded_kind = true, .excluded_kind = ev->kind,
};
size_t deleted = 0;
ctx.delete_events(&vanish, &deleted);
ctx.deinit();
```

Storage details (ordering `created_at DESC, id DESC`, `limit`/`offset`, `IN` arrays, compound tag AND): `docs/NOSTR_EVENT_STORAGE_SPEC.md`.

---

## Relay Runtime (`src/relay/relay.h`) and Transport (`src/transport/server.h`)

`relay_t` (`src/relay/relay.h:21-39`) aggregates: `config` (by value), `storage*`, `mg_mgr`, `stop_requested`, `subscriptions*`, `nip_registry*`, `verbosity` snapshot, `host_runtime` (`Nhr_Runtime*`), connection-ID counter, and hot-reload watch state. It does NOT hold a per-connection `connection_session_t*` — sessions live in the global session table keyed by `connection_id_t`.

```c
relay_t *relay_create(const relay_config_t *config, storage_context_t *storage);
void relay_destroy(relay_t *relay);
void relay_stop(relay_t *relay);
void relay_schedule_maintenance(relay_t *relay); // smallest NIP interval drives the timer; every tick runs ALL timers
void relay_on_connect(relay_t*, struct mg_connection*);
void relay_on_disconnect(relay_t*, struct mg_connection*);
bool relay_handle_http(relay_t*, struct mg_connection*, struct mg_http_message*); // NIP-11
void relay_send_json(connection_id_t id, const char *json); // transport bridge used by nip_env; no-op when unknown
void relay_event_handler(struct mg_connection*, int event, void *event_data); // Mongoose callback for transport

// Hot reload (see below)
bool relay_init_hot_reload(relay_t*, const char *module_path);
void relay_arm_hot_watch(relay_t*);
void relay_hot_swap_capabilities(relay_t*);
```

Transport owns the event loop only (`src/transport/server.h`):

```c
bool server_run(int port, relay_t *relay);
bool server_run_hot(int port, relay_t *relay, const char *published_module_path);
void server_stop(relay_t *relay);
void transport_send_json(struct mg_connection *connection, const char *json);
```

Host-side subscription API (`src/subscriptions/subscription_manager.h`): `subscription_manager_create(max_subs, max_filters, max_id_len)` (limits from `relay_config_t`; 0 keeps built-in default), `subscription_manager_create_subscription()` (TAKES filter ownership on success — caller NULLs its pointer; does NOT take it on failure), `close_subscription`, `remove_connection`, `match_and_deliver`, `subscription_manager_query()` (BORROWS filters; threads delivery policy, EOSE/COUNT builders, auth-hint, and query-authorize policy through), `count_for_connection`, `destroy`.

Logging (`src/log.h`): `log_init()`, `log_set_verbosity()` / `log_get_verbosity()`, `log_v()` plus `log_debug/info/warn/error` and `log_conn_*/log_sub_*/log_event_*/log_storage_*/log_nip_*/log_nhr_*/log_proto_*` helpers. Verbosity is `log_verbosity_t`: 0 ERROR, 1 +WARN, 2 +INFO, 3 all.

---

## Hot Reload (NHR) (`src/nhr.h`, `src/nhr_module.h`, `src/nhr_loader.h`)

Developer commands (Windows / Linux):

```bash
nob win -hr -- [relay args...]
nob linux -hr -- [relay args...]
```

What survives reload: WebSocket connections + Mongoose manager, SQLite connection/schema/data, subscriptions + filters, NIP-42 auth state in host-owned `connection_session_t`, configuration.

What reloads: NIP capability registry via `relay_hot_swap_capabilities()` (clear + re-register the new generation; synchronous on the event-loop thread) and module code (capabilities + stateless helpers).

Module ABI v7 (`src/nhr.h:41`, `168-175`): 6 exports generated by `NHR_MODULE_FUNCTIONS(X)`:

```c
uint32_t nhr_module_abi_version(void);
bool nhr_module_init(const Nhr_Host *host, const relay_config_t *config, void *storage_handle);
void nhr_module_shutdown(void);
Nhr_State nhr_module_pre_reload(void);
bool nhr_module_post_reload(const Nhr_Host *host, const relay_config_t *config, void *storage_handle, Nhr_State state);
void nhr_module_register_capabilities(nip_registry_t *registry);
```

New NIP powers never widen the ABI — they add `nip_capability_t` entries consumed through `register_capabilities`. `Nhr_Host` carries `send_json`, synchronous storage services (`find/count/delete(_tx)`, upserts, `find_ids_by_tags`), crypto services, connection snapshot/ID, and v2/v3 session-auth services. See `src/nhr.h:53-161` for the full table.

---

## Build System (`nob.c`, `src_build/nob_win.c`, `src_build/nob_linux.c`, `src_build/nob_common.h`)

```bash
# Windows
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
.\nob.exe                    # monolithic -> build/main.exe
.\nob.exe -test              # C + Node suites
.\nob.exe win -hr -- -port 7447

# Linux
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob
./nob                        # monolithic -> build/main
./nob -test
./nob -asan                  # Linux-only ASan+UBSan -> build/main_asan
./nob linux -hr -- -port 7447
```

`nob_common.h:nob_add_nip_sources()` auto-discovers `src/nips/*.c` (excluding `nip_template.c`). Same sources work in both modes — only the aggregation differs (monolithic host globs NIPs in; hot host links only `nip_capability.c` and loads implementations from `build/nostrogotho.dll` / `build/nostrogotho.so`).

---

## Adding a New NIP

1. Copy `src/nips/nip_template.c` → `src/nips/nipXX.c`.
2. Rename every `nipxx_` symbol (ctx struct/instance, hooks, `nipxx_caps`, `NIP_REGISTER` name).
3. Delete every capability entry you do NOT need (template ships all ten commented out); keep only what the NIP requires.
4. Use only `nip_capability.h` + `nips/nip_env.h` + `protocol/*` includes; send via `nip_env_send_json()`, auth via `nip_env_session_*`, validation via `nip_env_accepts_event()`.
5. Rebuild (`nob` / `nob win|linux`) or save under `-hr` — the constructor wires the NIP into both monolithic and hot-reload builds with no other edits.

Full step-by-step with hook examples: `docs/nip_development_workflow.md`.