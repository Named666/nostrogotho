# Creating a New NIP Capability

This guide explains how to extend the relay with a new NIP. A NIP is one
self-contained file in `src/nips/` that declares **capabilities**; the relay
core owns transport, dispatch, and storage framing.

## Quick Start

Copy the scaffold and rename every `nipxx_` symbol to your NIP number:

```bash
cp src/nips/nip_template.c src/nips/nipXX.c
```

Rebuild (`nob`, or just save while `nob [win|linux] -hr` watches). No build
script edits, no registration lists, no transport changes. Deleting the file
removes the NIP. That is the whole integration.

## What a NIP File Looks Like

One static table, one register function, one constructor:

```c
#include "nip_capability.h"

static nip_capability_t nip47_caps[] = {
    {
        .name = "nip47-kind", .type = NIP_CAP_KIND_HANDLER, .ctx = NULL,
        .caps.kind_handler = { .handles_kind = nip47_handles_kind,
                               .process_event = nip47_process_event },
        .next = NULL,
    },
};

void nip47_register(nip_registry_t *registry) {
    if (!registry) return;
    for (size_t i = 0; i < sizeof(nip47_caps) / sizeof(nip47_caps[0]); i++)
        nip_registry_register(registry, &nip47_caps[i]);
}

__attribute__((constructor)) static void nip47_register_provider(void) {
    nip_capability_add_provider(nip47_register);
}
```

`nip_registry_register()` deep-copies each entry, so the table is safe as a
static. Implement only the capability types your NIP needs; delete the rest.

## Capability Types

| Type | Hooks | Purpose |
|------|-------|---------|
| `NIP_CAP_LIFECYCLE` | `init(config, ctx)`, `shutdown(ctx)` | Per-startup/generation config capture |
| `NIP_CAP_CONNECTION` | `on_connect(id, ctx)`, `on_disconnect(id, ctx)` | Session open/close (e.g. NIP-42 AUTH challenge) |
| `NIP_CAP_MESSAGE_INTERCEPT` | `on_message(id, msg, ctx)` → bool | Consume a parsed `protocol_message_t` (custom verbs, AUTH); `false` = default dispatch |
| `NIP_CAP_PUBLICATION_POLICY` | `accept_publish(id, event, reason, size, ctx)` → bool | Reject an EVENT before kind dispatch |
| `NIP_CAP_KIND_HANDLER` | `handles_kind(kind, ctx)`, `process_event(id, event, storage, url, ctx)` | Own disjoint event kinds; storage via `storage_context_t` |
| `NIP_CAP_DELIVERY_POLICY` | `can_deliver(event, id, ctx)` → bool | Suppress delivery on stored queries AND live broadcasts |
| `NIP_CAP_QUERY_POLICY` | `authorize_query(...)`, `modify_results(...)` | Authorize/modify REQ/COUNT |
| `NIP_CAP_MAINTENANCE` | `timer(storage, ctx)` + `interval_ms` | Periodic work (e.g. expiry GC); smallest interval drives the loop |
| `NIP_CAP_METADATA` | `info_document(ctx)` | NIP-11 info document fragment |
| `NIP_CAP_PROTOCOL_RESPONSE` | `build_eose`, `build_count`, `needs_auth_hint`, `send_auth_challenge` | Own one response concern (NIP-67 EOSE, NIP-45 COUNT, NIP-42 challenges) |

## Rules (Enforced by the Architecture)

- **No transport in NIP code.** Connections are opaque `connection_id_t`
  (`0` = invalid). Never `struct mg_connection*`, never `mg_ws_send`.
  Reply via `relay_send_json(id, json)` (host) or
  `nhr_module_send_json(id, json, len)` (module) — see `nip_template.c`.
- **No storage internals.** Persistence goes through `storage_context_t`
  only — never SQLite. Return a policy decision; the relay core owns the
  OK response, broadcast, and framing.
- **State must survive hot reload.** Module statics die with the old
  `.so`/`.dll`. Keep config in a static ctx re-derived in lifecycle
  `init`, and per-connection auth in host-owned `connection_session_t`.
  Never rely on a static surviving a reload. Empty migration state is valid.
- **Composition is deterministic** (never registration order):
  publication = ALL must permit; delivery = ANY may veto; kind handlers =
  disjoint kinds, first ACCEPT wins; maintenance = ALL run; EOSE/COUNT/
  metadata = FIRST non-NULL wins.

## Hot Reload Behavior

Under `nob [win|linux] -hr`, saving a NIP file rebuilds only the module and
swaps the capability table (clear + re-register) synchronously on the
event-loop thread. Sockets, subscriptions, sessions, SQLite, and config are
host-owned and survive. A failed build/load/activation keeps the running
generation — the relay never drops connections because of a bad edit.

## Troubleshooting

1. File must live in `src/nips/` and not be named `nip_template.c`.
2. The `__attribute__((constructor))` provider must be present, else the
   file compiles but registers nothing.
3. Capability `name` strings must be unique (they are debug labels).
4. Hooks that need no state use `.ctx = NULL`; stateful ones share one
   static ctx re-derived in `init` — never `calloc` per register (it leaks
   across reloads; the registry never frees `ctx`).
5. `connection_id_t` from an event callback is valid only for that call —
   never store it beyond the hook except via the session APIs.

See `src/nips/nip_template.c` (start here), `src/nips/nip40.c`
(publication + delivery + maintenance), and `src/nips/nip42.c`
(connection + message intercept + stateful ctx).
