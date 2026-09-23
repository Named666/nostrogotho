# Creating a New NIP Plugin for Nostr Server

This guide explains how to create and integrate a new NIP plugin into the Nostr server.

## Plugin Architecture Overview

The Nostr server uses a plugin system where each NIP is implemented as a self-contained module. The architecture consists of:

- **Plugin Registry**: A linked list that maintains all registered plugins
- **Constructor Registration**: Plugins register themselves at startup using `__attribute__((constructor))`
- **Plugin Interface**: A standardized interface with various hooks for different lifecycle events
- **Kind Listening**: Declared *inside* the plugin struct — there is no separate listener registry

The key idea: **one plugin, one registration call, one constructor**. A plugin declares the event kinds it handles in `kinds[]`, provides an `on_event` callback, and `nip_plugin_register()` wires everything up. The NIP-01 dispatcher walks the plugin registry and calls `on_event` for every event whose kind matches a declared range.

## Quick Start

The fastest way to create a new plugin is to copy the scaffold:

```bash
cp src/nips/nip_template.c src/nips/nipxx.c
```

Then rename every `nip_xx_` / `nipXX` symbol to your NIP number, fill in the hooks you need, and rebuild. The build tool globs `src/nips/*.c`, so the file is compiled in automatically — no edits to the build script or `server.c` are needed.

## Step-by-Step Guide

### 1. Create the Plugin File

Create a new file in `src/nips/` with the naming convention `nipXX.c` (e.g., `nipxx.c` for NIP-XX):

```c
// src/nips/nipxx.c
#include "nip_plugin.h"
#include "nip01.h"
#include "nip_event.h"
#include <string.h>

// Per-plugin state (instead of file-scope static globals)
typedef struct {
    const char *service_url;
} nipxx_state_t;

static nipxx_state_t nipxx_state;

// Kind listener: called for every event whose kind is in plugin.kinds[]
static nip01_process_result_t nipxx_on_event(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;
    (void)relay_url;

    // Use the ergonomic result constructors:
    return nip_plugin_store_and_broadcast(storage, event);
}

// Plugin initialization function
void nipxx_init(const relay_config_t *config, void *ctx) {
    nipxx_state_t *state = (nipxx_state_t *) ctx;
    state->service_url = config->service_url;
}

// Plugin registration structure — the ONLY registration call needed
static nip_plugin_t nipxx_plugin = {
    .name = "nipxx",
    .ctx = &nipxx_state,
    .kinds = { NIP_PLUGIN_KIND(47) },   // listen for kind 47
    .kinds_count = 1,
    .on_event = nipxx_on_event,
    .init = nipxx_init,
    // ...other hooks as needed (NULL = unused)...
};

// Register the plugin at startup
__attribute__((constructor)) static void nipxx_register_at_startup(void) {
    nip_plugin_register(&nipxx_plugin);
}
```

### 2. Register the Plugin

The plugin automatically registers itself at startup due to the `__attribute__((constructor))` declaration. This ensures the plugin is available when the server starts up. `nip_plugin_register()` is the **single** registration entry point — it links the plugin into the registry and wires any declared kinds into the NIP-01 dispatcher.

### 3. Implement Your NIP Logic

Implement the specific functionality for your NIP in the appropriate hooks:

- **`on_event`**: Process events of your declared kinds (store, replace, reject, …)
- **`on_message`**: Process incoming messages (e.g., handle authentication)
- **`accept_publish`**: Validate event publishing requests
- **`can_deliver`**: Control event delivery to clients
- **`build_eose`/`build_count`**: Customize subscription responses
- **`timer`**: Perform periodic maintenance tasks

### 4. Build and Test

After implementing your plugin:

1. Rebuild the project: `.\nob.exe`
2. Start the server: `.\build\main.exe`
3. Test your plugin by sending appropriate messages

## Plugin Hooks Reference

Every hook receives the plugin's `ctx` as its last argument, so a plugin can keep all state in a struct instead of file-scope globals.

| Hook | Purpose |
|------|---------|
| `init(config, ctx)` | Initialize plugin with runtime configuration |
| `on_connect(connection, ctx)` | Handle new client connections |
| `on_disconnect(connection, ctx)` | Handle client disconnections |
| `on_message(connection, values, count, ctx)` | Process incoming messages |
| `accept_publish(connection, event, reason, reason_size, ctx)` | Validate publish requests |
| `can_deliver(event, connection, ctx)` | Control event delivery |
| `eose_auth_hint(connection, filters, count, ctx)` | Add auth hints to EOSE |
| `build_eose(sub, has_more, auth_hint, ctx)` | Customize EOSE responses |
| `build_count(sub, count, ctx)` | Customize COUNT responses |
| `timer(storage, ctx)` | Perform periodic maintenance |
| `info_document(ctx)` | Provide relay information |

## Kind Listening

Kind listening is part of the plugin itself. Declare the kinds (or kind ranges) your plugin handles in `kinds[]` and provide an `on_event` callback. There is no separate listener registry and no second registration call.

### Declaring Kinds

```c
static nip_plugin_t nipxx_plugin = {
    .name = "nipxx",
    .kinds = {
        NIP_PLUGIN_KIND(47),        // single kind: 47
        { 10000, 19999 },           // or an inclusive range
    },
    .kinds_count = 2,
    .on_event = nipxx_on_event,
};
```

- `NIP_PLUGIN_KIND(k)` is shorthand for `{ k, k }` (a single kind).
- `{ min, max }` declares an inclusive range.
- Up to `NIP_PLUGIN_MAX_KIND_RANGES` (4) ranges per plugin.
- `kinds_count` of 0 means the plugin has no kind listener.

### Listener Function Signature

Kind listeners follow this signature:

```c
nip01_process_result_t nipxx_on_event(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url);
```

The listener receives the event and can:
- Accept or reject the event
- Store the event in the relay's storage
- Broadcast the event to connected clients
- Return a response message

### Ergonomic Result Constructors

Instead of hand-rolling the `nip01_process_result_t` struct, use the helpers from `nip_plugin.h`:

| Helper | Behavior |
|--------|----------|
| `nip_plugin_accept()` | Accepted + broadcast, empty message |
| `nip_plugin_reject("invalid: ...")` | Rejected with the given reason |
| `nip_plugin_store_and_broadcast(storage, event)` | Insert + accept + broadcast; returns a "duplicate" result if the event already exists |
| `nip_plugin_store_only(storage, event)` | Insert + accept, no broadcast (e.g. NIP-09 deletions) |
| `nip_plugin_store(storage, event)` | Bare `insert_record` wrapper returning bool |

### Example Kind Listener Implementation

```c
nip01_process_result_t nipxx_on_event(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;
    (void)relay_url;

    // Custom logic for kind 47 events
    // ...

    return nip_plugin_store_and_broadcast(storage, event);
}
```

### Dispatcher Semantics

The dispatcher in `nip01_process_event()` walks the plugin registry in registration order and calls `on_event` on every plugin whose declared ranges cover the event's kind. The first listener to return `accepted = true` wins; if every matching listener rejects, the event is rejected. If no plugin claims the kind, it falls back to default NIP-01 behavior (store + broadcast, except ephemeral kinds 20000–29999 which are broadcast without storage).

### Registration Order Matters

Plugins are checked in registration order. The first plugin whose kind range covers the event's kind gets to process it. This means:

- More specific ranges should be registered before more general ones
- The built-in NIP-16/NIP-33 replaceable/addressable plugin is registered from `nip01.c`
- Custom plugins should register before or after the built-in ones depending on priority needs

### Auto-Registration Pattern

```c
__attribute__((constructor)) static void nipxx_register_at_startup(void) {
    nip_plugin_register(&nipxx_plugin);
}
```

This is the **only** registration call a plugin needs. It runs before `main()` on MinGW/GCC, so the full plugin set is known by the time `server_configure()` runs.

## Best Practices

- Use standardized naming conventions for your plugin (e.g., `NIP-XX`)
- Keep hooks focused on their specific responsibilities
- Keep per-plugin state in a struct and point `plugin.ctx` at it — no file-scope globals
- Use `json_builder_t` for constructing JSON responses
- Handle memory management carefully (free allocated strings)
- Use `nip_plugin_send_json` and `nip_plugin_send_status` for sending responses
- Set appropriate `timer_interval_ms` values based on your needs
- Use the ergonomic result constructors instead of hand-rolling `nip01_process_result_t`

## Troubleshooting

If your plugin isn't working:

1. Check that the file is in `src/nips/`
2. Verify the constructor registration is present
3. Ensure the plugin name is unique
4. Check build logs for compilation errors
5. Use `server_debug_logging` to trace execution flow

By following this guide, you can easily extend the Nostr server with new NIP implementations while maintaining compatibility with the existing plugin architecture.