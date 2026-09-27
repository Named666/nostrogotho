# Nostrogotho Unified Specification: Hot Reload + NIP Capability Architecture

**Status:** Design specification merging NHR hot-reload with NIP capability refactor  
**Target:** Single cohesive API for module developers and NIP implementers

---

## 1. Core Concepts

### 1.1 Terminology

| Term | Definition |
|------|------------|
| **Host** | Permanent executable owning process lifetime, transport, storage, event loop |
| **Module** | Hot-reloadable dynamic library containing NIP capabilities |
| **Capability** | Self-contained unit of NIP behavior (lifecycle, publication policy, kind handler, etc.) |
| **Registry** | Host-owned container managing all registered capabilities |
| **Generation** | A specific compiled Module instance (unique filename per reload) |
| **Connection ID** | Opaque `uintptr_t` identifying a client connection (stable across reloads) |

### 1.2 Architectural Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      HOST PROCESS                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Transport  │  │   Protocol   │  │    Relay Core    │  │
│  │  (Mongoose)  │──▶│ (parse/serial)│──▶│  (relay_t)       │  │
│  └──────────────┘  └──────────────┘  │  - config        │  │
│                                       │  - storage       │  │
│                                       │  - subscriptions │  │
│                                       │  - nip_registry  │  │
│                                       │  - sessions      │  │
│                                       └────────┬─────────┘  │
│                                                │            │
│                                       ┌────────▼─────────┐  │
│                                       │  MODULE (DLL/.so)│  │
│                                       │                  │  │
│                                       │  nip_capability_t│  │
│                                       │  1..N capabilities│ │
│                                       └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Dependency Rule:** Host → Protocol → Relay Core → Capabilities  
**Never:** Capabilities → Transport (Mongoose), Capabilities → SQLite directly

---

## 2. Module ABI (Hot Reload Interface)

### 2.1 Minimal Module Exports

The hot-reloadable Module exports **only** these symbols via X-macro:

```c
/* nhr_module.h - Single authoritative ABI header */

#define NHR_MODULE_FUNCTIONS(X) \
    X(uint32_t, abi_version, (void)) \
    X(bool, init, (const Nhr_Host *host, const relay_config_t *config, void *storage)) \
    X(void, shutdown, (void)) \
    X(Nhr_State, pre_reload, (void)) \
    X(bool, post_reload, (const Nhr_Host *host, const relay_config_t *config, void *storage, Nhr_State state)) \
    X(void, register_capabilities, (nip_registry_t *registry))

/* Generated: */
NHR_EXPORT uint32_t NHR_CALL nhr_module_abi_version(void);
NHR_EXPORT bool NHR_CALL nhr_module_init(const Nhr_Host*, const relay_config_t*, void*);
NHR_EXPORT void NHR_CALL nhr_module_shutdown(void);
NHR_EXPORT Nhr_State NHR_CALL nhr_module_pre_reload(void);
NHR_EXPORT bool NHR_CALL nhr_module_post_reload(const Nhr_Host*, const relay_config_t*, void*, Nhr_State);
NHR_EXPORT void NHR_CALL nhr_module_register_capabilities(nip_registry_t*);
```

### 2.2 Host Services Table (`Nhr_Host`)

Authoritative definition is `src/nhr.h` (ABI v2). Summary of the actual
table (names must match — the module and host are compiled separately):

```c
typedef struct Nhr_Host {
    uint32_t abi_version;   /* must equal NHR_ABI_VERSION (2) */
    uint32_t struct_size;   /* host sets sizeof(*host); module rejects smaller */
    void *userdata;         /* Nhr_Runtime*, passed back to every service */

    /* Transport (sole frame sender; module never calls Mongoose directly) */
    void (NHR_CALL *send_json)(void *userdata, void *connection,
                               const char *json, size_t length);

    /* Storage (opaque handles, synchronous; predicate callbacks never retained) */
    storage_insert_result_t (NHR_CALL *storage_insert_record)(void *userdata, const event_t*, const storage_tag_match_t*, size_t);
    bool (NHR_CALL *storage_get_event_copy)(void *userdata, const char*, event_t*, char**, char**); /* host-owned out buffers, free via free */
    int (NHR_CALL *storage_delete_by_id_and_pubkey)(void *userdata, const char*, const char*);
    int (NHR_CALL *storage_delete_by_kind_and_pubkey)(void *userdata, int, const char*, time_t);
    bool (NHR_CALL *storage_delete_matching)(void *userdata, const storage_event_scope_t*, storage_event_predicate_t, void*, size_t*, char*, size_t, bool*);
    bool (NHR_CALL *storage_send_records)(void *userdata, send_records_callback_t, const char*, const filter_t*, size_t, bool, bool*, int*, const storage_tag_match_t*, size_t, void*);

    /* Crypto (host-owned secp256k1 context; module holds no crypto state) */
    bool (NHR_CALL *crypto_check_event)(void *userdata, const event_t*);
    void (NHR_CALL *crypto_sha256)(void *userdata, const uint8_t*, size_t, uint8_t[32]);
    bool (NHR_CALL *crypto_signature_verify)(void *userdata, const char*, const char*, const uint8_t[32]);
    unsigned (NHR_CALL *crypto_count_leading_zero_bits)(void *userdata, const char*);

    /* Connection enumeration (live relay sessions, not a module list) */
    size_t (NHR_CALL *connection_snapshot)(void *userdata, connection_snapshot_t*, size_t);
    uintptr_t (NHR_CALL *connection_id)(void *userdata, void *connection);

    /* Session-auth state (ABI v2, host-owned connection_session_t).
     * Borrowed strings valid until next session mutation — copy if retained.
     * set_* with NULL clears. Check non-NULL before calling (older host). */
    const char *(NHR_CALL *connection_get_challenge)(void *userdata, uintptr_t);
    bool (NHR_CALL *connection_set_challenge)(void *userdata, uintptr_t, const char*);
    const char *(NHR_CALL *connection_get_auth_pubkey)(void *userdata, uintptr_t);
    bool (NHR_CALL *connection_set_auth)(void *userdata, uintptr_t, const char*);
    void (NHR_CALL *connection_clear_auth)(void *userdata, uintptr_t);

    /* Allocator (host-owned, cross-boundary safe incl. Windows CRT) */
    void *(NHR_CALL *alloc)(size_t);
    void (NHR_CALL *free)(void*);
} Nhr_Host;
```

### 2.3 Module State (`Nhr_State`)

```c
typedef struct {
    uint32_t version;
    void *data;      /* Host-allocated, host-freed */
    size_t size;
} Nhr_State;
```

**Migration Protocol (actual, `src/nhr.c` + `src/nhr_module.c`):**
1. Host calls `old_module->pre_reload()` → returns a versioned *empty*
   `Nhr_State` (`{NHR_STATE_VERSION, NULL, 0}`); the shape check in
   `nhr_runtime_activate_candidate` requires the version but allows
   empty payload
2. Host calls old `shutdown`, unloads old image, fresh-loads the candidate
   image (preflight image is discarded so constructors rebuild clean state),
   ABI-validates it
3. Host calls `new_module->post_reload(host, config, storage, state)` —
   which is just `init`: rebuilds the module registry and re-derives
   per-generation ctx via lifecycle `init`
4. Host frees `state.data` after `post_reload` returns (success or rollback;
   always NULL today, but an older generation's blob is tolerated and ignored)

**State rule (ABI v2 — why there is no blob):** sockets, Mongoose
manager, SQLite, subscriptions, sessions, and config are host-owned and
never cross the unload boundary. NIP-42 challenge/pubkey state lives in
host-owned `connection_session_t`, so authentication survives a reload with
no copy — activation runs synchronously on the event-loop thread, so no
session can change mid-swap and there is nothing to snapshot or restore.
(The `nip42_save/restore_state` helpers remain in `nip42.c` as unused
rolling-update compat; nothing calls them.) New NIPs must follow the same
rule: re-derivable or session-owned state, never reliance on module
statics surviving unload.

---

## 3. NIP Capability Interface (Transport-Agnostic)

### 3.1 Capability Types

```c
typedef enum {
    NIP_CAP_LIFECYCLE        = 1,  /* init, shutdown */
    NIP_CAP_CONNECTION       = 2,  /* on_connect, on_disconnect */
    NIP_CAP_MESSAGE_INTERCEPT = 3, /* intercept protocol messages */
    NIP_CAP_PUBLICATION_POLICY = 4, /* accept/reject EVENT */
    NIP_CAP_KIND_HANDLER     = 5,  /* handle specific event kinds */
    NIP_CAP_DELIVERY_POLICY  = 6,  /* filter event delivery */
    NIP_CAP_QUERY_POLICY     = 7,  /* authorize/modify REQ/COUNT */
    NIP_CAP_MAINTENANCE      = 8,  /* periodic timer work */
    NIP_CAP_METADATA         = 9,  /* NIP-11 info document */
    NIP_CAP_PROTOCOL_RESPONSE = 10, /* build EOSE/COUNT responses */
} nip_capability_type_t;
```

### 3.2 Capability Structures

```c
/* Lifecycle */
typedef struct {
    void (*init)(const relay_config_t *config, void *ctx);
    void (*shutdown)(void *ctx);
} nip_lifecycle_capability_t;

/* Connection (uses opaque connection_id_t) */
typedef struct {
    void (*on_connect)(connection_id_t, void *ctx);
    void (*on_disconnect)(connection_id_t, void *ctx);
} nip_connection_capability_t;

/* Message Intercept (operates on parsed protocol messages) */
typedef struct {
    bool (*on_message)(connection_id_t, const protocol_message_t*, void *ctx);
} nip_message_intercept_capability_t;

/* Publication Policy */
typedef struct {
    bool (*accept_publish)(connection_id_t, const event_t*, char* reason, size_t, void *ctx);
} nip_publication_policy_capability_t;

/* Kind Handler */
typedef struct {
    bool (*handles_kind)(int kind, void *ctx);
    nip01_process_result_t (*process_event)(connection_id_t, const event_t*,
                                             storage_context_t*, const char*, void *ctx);
} nip_kind_handler_capability_t;

/* Delivery Policy */
typedef struct {
    bool (*can_deliver)(const event_t*, connection_id_t, void *ctx);
} nip_delivery_policy_capability_t;

/* Query Policy */
typedef struct {
    bool (*authorize_query)(connection_id_t, filter_t*, size_t, void *ctx);
    bool (*modify_results)(connection_id_t, const filter_t*, size_t, bool, int, void *ctx);
} nip_query_policy_capability_t;

/* Maintenance */
typedef struct {
    void (*timer)(storage_context_t*, void *ctx);
    unsigned interval_ms;
} nip_maintenance_capability_t;

/* Metadata */
typedef struct {
    const char* (*info_document)(void *ctx);
} nip_metadata_capability_t;

/* Protocol Response */
typedef struct {
    char* (*build_eose)(const char* sub, bool has_more, bool auth_hint, void *ctx);
    char* (*build_count)(const char* sub, unsigned long count, void *ctx);
} nip_protocol_response_capability_t;
```

### 3.3 Unified Capability Struct

```c
struct nip_capability {
    const char *name;           /* Debug name: "nip42-publication-policy" */
    nip_capability_type_t type;
    void *ctx;                  /* Per-capability state */

    union {
        nip_lifecycle_capability_t lifecycle;
        nip_connection_capability_t connection;
        nip_message_intercept_capability_t message_intercept;
        nip_publication_policy_capability_t publication_policy;
        nip_kind_handler_capability_t kind_handler;
        nip_delivery_policy_capability_t delivery_policy;
        nip_query_policy_capability_t query_policy;
        nip_maintenance_capability_t maintenance;
        nip_metadata_capability_t metadata;
        nip_protocol_response_capability_t protocol_response;
    } caps;

    struct nip_capability *next;
};
```

### 3.4 Registry & Composition

```c
typedef struct {
    nip_capability_t *capabilities;
    size_t count;
} nip_registry_t;

/* Registry ops */
nip_registry_t *nip_registry_create(void);
void nip_registry_destroy(nip_registry_t*);
void nip_registry_register(nip_registry_t*, nip_capability_t*);
nip_capability_t *nip_registry_get_by_type(nip_registry_t*, nip_capability_type_t);
void nip_registry_iterate(nip_registry_t*, nip_capability_type_t, nip_capability_iter_fn, void*);

/* Deterministic Composition Rules */
bool nip_composition_check_publication(nip_registry_t*, connection_id_t, const event_t*, char*, size_t);  /* ALL must permit */
bool nip_composition_check_delivery(nip_registry_t*, const event_t*, connection_id_t);                      /* ANY may veto */
nip_kind_composition_result_t nip_composition_process_kind(nip_registry_t*, connection_id_t, const event_t*, storage_context_t*, const char*);  /* ALL applicable run */
void nip_composition_run_maintenance(nip_registry_t*, storage_context_t*);                                    /* ALL run */
bool nip_composition_authorize_query(nip_registry_t*, connection_id_t, filter_t*, size_t);                   /* ALL must permit */
char* nip_composition_build_eose(nip_registry_t*, const char*, bool, bool);                                  /* FIRST non-NULL wins */
char* nip_composition_build_count(nip_registry_t*, const char*, unsigned long);                              /* FIRST non-NULL wins */
const char* nip_composition_get_info_document(nip_registry_t*);                                              /* FIRST non-NULL wins */
```

---

## 4. Module Implementation Pattern

### 4.1 Standard Module Entry Point

`src/nhr_module.c` is the module entry point. It does NOT list NIPs
explicitly. Each `nipXX.c` self-registers a provider via
`__attribute__((constructor))` → `nip_capability_add_provider()`, and the
module calls `nip_registry_register_providers()` at `init`/`post_reload`
time. Adding a file enables a NIP; deleting it removes the capability —
in both monolithic and hot-reload builds, with no registration list to edit.

```c
/* nhr_module.c - Module entry point (simplified; see source for full shims) */

#include "nhr_module.h"
#include "nip_capability.h"

static const Nhr_Host *g_host = NULL;
static relay_config_t g_config = {0};
static storage_context_t g_module_storage_adapter = {0}; /* host-service adapter */
static nip_registry_t *g_module_registry = NULL;

/* Module lifecycle (6 ABI exports; see NHR_MODULE_FUNCTIONS in src/nhr.h) */
uint32_t NHR_CALL nhr_module_abi_version(void) { return NHR_ABI_VERSION; }

bool NHR_CALL nhr_module_init(const Nhr_Host *host, const relay_config_t *config, void *storage) {
    if (!host || host->abi_version != NHR_ABI_VERSION
        || host->struct_size < sizeof(*host) || !config) return false;
    g_host = host;
    g_config = *config;
    module_storage_adapter_init();  /* storage_context_t façade over host services */

    g_module_registry = nip_registry_create();
    if (!g_module_registry) return false;

    /* Every provider linked into this image (constructors ran at load). */
    nip_registry_register_providers(g_module_registry);

    for (nip_capability_t *cap = g_module_registry->capabilities; cap; cap = cap->next)
        if (cap->type == NIP_CAP_LIFECYCLE && cap->caps.lifecycle.init)
            cap->caps.lifecycle.init(config, cap->ctx);
    return true;
}

void NHR_CALL nhr_module_shutdown(void);  /* lifecycle shutdowns + registry destroy */

/* Stateless reload: versioned empty state out, init on the way back in. */
Nhr_State NHR_CALL nhr_module_pre_reload(void);   /* returns {NHR_STATE_VERSION, NULL, 0} */
bool NHR_CALL nhr_module_post_reload(const Nhr_Host*, const relay_config_t*,
                                     void*, Nhr_State); /* ignores state; calls init */

/* THE KEY INTEGRATION POINT: deep-copy module generation into host registry */
void NHR_CALL nhr_module_register_capabilities(nip_registry_t *host_registry) {
    for (nip_capability_t *cap = g_module_registry->capabilities; cap; cap = cap->next)
        nip_registry_register(host_registry, cap);  /* deep-copy; host owns nodes */
}
```

### 4.2 Capability Implementation Pattern

Each NIP capability is a **standalone single file** (`nipXX.c` — logic,
table, and constructor together; no per-NIP header). Canonical shape
(see `src/nips/nip_template.c`):

```c
/* nip42.c (abridged) */
#include "nip_capability.h"

typedef struct { char service_url[256]; } nip42_ctx_t;
static nip42_ctx_t nip42_ctx;   /* static: per-generation, no cross-reload leak */

static void nip42_lifecycle_init(const relay_config_t *config, void *ctx) { /* ... */ }
static void nip42_connection_on_connect(connection_id_t id, void *ctx) { /* AUTH challenge via relay/nhr send shim */ }
static bool nip42_message_intercept_fn(connection_id_t id, const protocol_message_t *msg, void *ctx) {
    if (!msg || msg->command != PROTOCOL_CMD_AUTH) return false;
    /* ... authenticate, reply OK via opaque-ID send, return true (consumed) ... */
}
static bool nip42_publication_policy_fn(connection_id_t id, const event_t *e, char *r, size_t rs, void *ctx) { /* ... */ }

static nip_capability_t nip42_caps[] = {
    {
        .name = "nip42-lifecycle", .type = NIP_CAP_LIFECYCLE, .ctx = &nip42_ctx,
        .caps.lifecycle = { .init = nip42_lifecycle_init, .shutdown = NULL },
        .next = NULL,
    },
    /* ... one entry per capability type this NIP implements ... */
};

void nip42_register(nip_registry_t *registry) {
    for (size_t i = 0; i < sizeof(nip42_caps)/sizeof(nip42_caps[0]); i++)
        nip_registry_register(registry, &nip42_caps[i]);  /* deep-copy */
}

__attribute__((constructor)) static void nip42_register_provider(void) {
    nip_capability_add_provider(nip42_register);
}
```

Transport rule: capability code takes `connection_id_t` and
`protocol_message_t` / `event_t` / `storage_context_t` only. Sending goes
through `relay_send_json()` (host) / `nhr_module_send_json()` (module) —
never `mg_ws_send`. Storage goes through `storage_context_t` — never SQLite.

---

## 5. Host Integration

### 5.1 Relay Core (`relay_t`)

```c
struct relay {
    relay_config_t config;
    storage_context_t *storage;
    struct mg_mgr manager;
    subscription_manager_t *subscriptions;
    nip_registry_t *nip_registry;      /* Single unified registry */
    connection_session_t *sessions;
    Nhr_Runtime *hot_reload;           /* Optional NHR runtime */
};

/* Creation */
relay_t *relay_create(const relay_config_t *config, storage_context_t *storage) {
    relay_t *r = calloc(1, sizeof(*r));
    r->config = *config;
    r->storage = storage;
    r->nip_registry = nip_registry_create();
    r->subscriptions = subscription_manager_create();
    r->sessions = connection_session_create();

    /* Register BUILTIN capabilities (always present, not hot-reloadable) */
    nip01_builtin_capability_register(r->nip_registry);  /* Core NIP-01 kinds */
    /* ... other builtins ... */

    return r;
}

/* Hot reload initialization */
bool relay_init_hot_reload(relay_t *relay, const char *module_path) {
    relay->hot_reload = calloc(1, sizeof(Nhr_Runtime));
    if (!nhr_runtime_init(relay->hot_reload, relay->storage, &relay->config, module_path)) {
        return false;
    }

    /* 1. Load module and validate ABI */
    if (!nhr_runtime_load_module(relay->hot_reload)) return false;

    /* 2. Call module init (which prepares module-local registry) */
    if (!nhr_module_init(relay->hot_reload->services, &relay->config, relay->storage)) {
        return false;
    }

    /* 3. Module registers capabilities INTO HOST REGISTRY */
    nhr_module_register_capabilities(relay->nip_registry);

    /* 4. Start file watcher timer */
    mg_timer_add(&relay->manager, 1000, MG_TIMER_REPEAT, nhr_check_candidate_timer, relay);
    return true;
}
```

### 5.2 Reload Sequence

```c
/* nhr_check_candidate_timer - called periodically from event loop */
static void nhr_check_candidate_timer(void *arg) {
    relay_t *relay = arg;
    if (!module_file_changed(relay->watched_path)) return;

    /* 1. Build candidate module (host builds, not module) */
    Nhr_Library candidate;
    if (!nhr_runtime_build_candidate(relay->hot_reload, relay->watched_path, &candidate)) return;

    /* 2. Validate candidate ABI (no init yet) */
    if (!nhr_runtime_validate_candidate(relay->hot_reload, &candidate)) return;

    /* 3. PREPARE: old module pre_reload (versioned empty state; sessions
     * stay host-owned, nothing migrates) */
    Nhr_State state = nhr_module_pre_reload();

    /* 4. UNLOAD: old module shutdown + unload */
    nhr_module_shutdown();
    nhr_runtime_unload_module(relay->hot_reload);

    /* 5. LOAD: new module */
    if (!nhr_runtime_load_module(relay->hot_reload, &candidate)) {
        /* Rollback: reload previous good module */
        nhr_runtime_rollback(relay->hot_reload);
        nhr_module_post_reload(...);  /* with same state */
        return;
    }

    /* 6. INIT: new module init (builds fresh capability set) */
    if (!nhr_module_init(relay->hot_reload->services, &relay->config, relay->storage)) {
        nhr_runtime_rollback(relay->hot_reload);
        return;
    }

    /* 7. REGISTER: new capabilities replace old in host registry */
    nip_registry_clear(relay->nip_registry);  /* Remove old caps */
    nhr_module_register_capabilities(relay->nip_registry);

    /* 8. RESTORE: post_reload re-inits the generation (state carries
     * nothing; lifecycle init re-derives per-generation ctx) */
    if (!nhr_module_post_reload(relay->hot_reload->services, &relay->config,
                                relay->storage, state)) {
        nhr_runtime_rollback(relay->hot_reload);
        return;
    }

    /* 9. Commit: update watched file metadata */
    relay->watched_mtime = new_mtime;
}
```

---

## 6. Monolithic Build (Non-Hot-Reload)

When `NOB_HOT_RELOAD` is **not** defined, the same capabilities are compiled directly into the host:

```c
/* main.c - Monolithic build */

#include "relay.h"

int main(int argc, char **argv) {
    relay_config_t config;
    relay_config_init(&config);
    parse_args(argc, argv, &config);

    storage_context_t *storage = storage_open(config.database_path);
    /* relay_create() calls nip_registry_register_providers(): every nipXX.c
     * linked into the host contributes its table via its constructor.
     * Registering capabilities directly (no module boundary). */
    relay_t *relay = relay_create(&config, storage);

    relay_run(relay);
    relay_destroy(relay);
    storage_close(storage);
    return 0;
}
```

**Key Point:** The capability code is **identical** in both modes. The only difference is *who triggers registration* (host `relay_create` via constructors vs module `init`/`post_reload` via constructors + `register_capabilities` into the host registry).

---

## 7. Adding a New NIP (Developer Guide)

> The normative step-by-step tutorial lives in
> `docs/creating_nip_plugin.md` (scaffold → hooks → build → troubleshoot).
> This section states only the spec-level contract that tutorial implements.

### 7.1 One file per NIP

```
src/nips/
  nipXX.c    # logic + capability table + constructor (this is all you need)
```

Copy `src/nips/nip_template.c` → `src/nips/nipXX.c`, rename the
`nipxx_` symbols, keep only the hooks your NIP needs (see the
`nipXX_register` + constructor pattern in `docs/creating_nip_plugin.md`).
No header, no registration list, no build-file edit: `nob` globs
`src/nips/*.c` (`nip_template.c` excluded), and the constructor wires the
NIP into both monolithic and `-hr` builds. Deleting the file removes the NIP.

Composition contract (deterministic — never registration order):
- publication policy: ALL must permit (AND)
- delivery policy: ANY may veto
- kind handlers: disjoint kinds; first ACCEPT wins, rejections collected
- maintenance: ALL run every tick (smallest `interval_ms` drives the timer)
- EOSE/COUNT/metadata: FIRST non-NULL wins

### 7.2 Hot-reload guarantees (what the developer gets for free)

- `nob [win|linux] -hr -- [relay args]` builds host + module, watches
  `src/nips/*.c` (minus template) plus module inputs, debounces saves,
  rebuilds module-only, publishes atomically, reloads at the event-loop
  boundary (`nhr_check_candidate_timer` in `src/relay/relay.c`).
- WebSocket connections, subscriptions, sessions, SQLite, and config are
  host-owned: a reload swaps only the capability table
  (`relay_hot_swap_capabilities`: clear + `register_capabilities`),
  synchronously on the event-loop thread, so no socket drops and no dispatch
  runs mid-swap. Failed build/load/activation keeps the active generation;
  failed activation falls back and re-registers the fallback's capabilities.
- NIP code must therefore: use `connection_id_t` (never `mg_connection*`),
  send via `relay_send_json` / `nhr_module_send_json`, persist via
  `storage_context_t`, and keep reload-surviving state in
  `connection_session_t` or re-derivable `init` — never in module statics.

### 7.3 Build integration

None per-NIP. Monolithic `nob [win|linux]` compiles the same
`nipXX.c` into the host; `-hr` compiles it into the module. Registration
flows through constructors in both modes — only the aggregator differs
(host `nip_registry_register_providers` at `relay_create` vs module
at `nhr_module_init`/`post_reload` + `register_capabilities` into the
host registry).

---

## 8. Conformance Checklist (Spec ↔ Code, 2026-09-27)

| Component | Spec (this file) | Code |
|-----------|------------------|------|
| `nhr.h` exports | 6 functions + `register_capabilities` (§2.1) | ✅ `NHR_MODULE_FUNCTIONS` in `src/nhr.h` |
| `Nhr_Host` table | §2.2 (names match `nhr.h`, ABI v2 + session-auth) | ✅ `src/nhr.h`, wired in `src/nhr.c` |
| Module entry | Provider constructors + `register_providers` (§4.1) | ✅ `src/nhr_module.c` |
| Host registry | Host owns nodes (deep-copy), module keeps its own (§4.1) | ✅ `nip_registry_register` / `relay_hot_swap_capabilities` |
| NIP files | One `nipXX.c` (logic + table + constructor), no list edits (§7.1) | ✅ all NIPs + `nip_template.c` |
| `nip_plugin.h` (flat `nip_plugin_t`) | Removed; dispatch uses `nip_capability_t` only | ✅ deleted; dead dispatch removed; single-file `nipXX.c` per NIP |
| Capability tables | Single static table, static-or-NULL ctx, no per-register alloc | ✅ all NIPs (NIP-42 `send_auth_challenge` rewired — was set on a dead intermediate, never registered) |
| State migration | Stateless reload protocol: versioned empty `Nhr_State`, session-owned auth (§2.3) | ✅ `nhr_module_pre/post_reload` trivial; `connection_session_t` carries auth |
| Kind composition | Disjoint kinds; first ACCEPT wins (§7.1) | ✅ `nip_composition_process_kind` |

---

## 9. Acceptance Criteria

1. ✅ **Single capability model** — Both monolithic and hot-reload builds use `nip_capability_t`
2. ✅ **Transport-agnostic** — No `mg_connection*` in capability signatures
3. ✅ **Deterministic composition** — AND/OR/first-wins rules documented and enforced
4. ✅ **Hot reload works** — Module reload replaces capabilities in host registry atomically
5. ✅ **State migration** — Auth/session state is host-owned and survives reload; empty `Nhr_State` is valid
6. ✅ **No duplicate logic** — `nip_plugin_t` + dead dispatch removed; one single-file `nipXX.c` per NIP
6. ✅ **Build system unity** — Same `nipXX.c` works in both build modes
7. ✅ **Developer experience** — New NIP = copy `nip_template.c` → `nipXX.c`; no list edits, no NHR ABI changes

---

## 10. File Organization (Target)

```
src/
  main.c                          # Monolithic entry point
  nhr_module.h                    # Minimal NHR ABI (6 exports)
  nhr_module.c                    # Module entry point (delegates to capabilities)
  nhr.h                           # Host services + loader (internal)
  nhr_loader.h/c                  # Platform loader (internal)
  relay/
    relay.h/c                     # relay_t, lifecycle, hot reload integration
    connection_session.h/c        # Opaque connection IDs
  protocol/
    protocol.h/c                  # Parsing, serialization, protocol_message_t
  model/
    event.h/c, filter.h/c, tag.h/c # Transport-agnostic data structures
  validation/
    event_validation.h/c          # Structural, ID, signature, delegation
  subscriptions/
    subscription_manager.h/c      # Lifecycle, matching, delivery
  storage/
    storage.h/c                   # Abstract API
    sqlite.h/c                    # SQLite backend
  nips/
    nip_capability.h/c            # Capability system (registry, composition,
                                  # shared nip26/nip42 cross-file decls)
    nip_template.c                # New-NIP scaffold (excluded from build)
    nipXX.c                       # One single file per NIP: logic + table +
                                  # nipXX_register + constructor (no per-NIP header)
```

---

## 11. Appendix: Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Module exports `register_capabilities` not individual hooks | Keeps NHR ABI stable; new capabilities don't require ABI bump |
| Host owns registry, module populates it | Single source of truth; host controls composition |
| Capabilities use `connection_id_t` not `mg_connection*` | Transport-agnostic; survives reload; testable |
| `Nhr_Host` provides allocator | Cross-boundary allocation safety (Windows CRT) |
| Static-or-NULL ctx, registry deep-copies descriptors | No per-register alloc → nothing leaks across reloads; no ctx lifetime to document per NIP |
| One static table per NIP file | Single place to read/change a NIP's powers; kills intermediate-struct drift (e.g. NIP-42's unwired challenge hook) |
| Composition rules explicit in `nip_composition_*` | Predictable behavior; no registration-order bugs |
| Monolithic = direct registration; Hot reload = module registration | Same capability code, different wiring |