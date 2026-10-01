# nostrogotho

`nostrogotho` is a C99 Nostr relay with SQLite persistence. It uses bundled
Mongoose for HTTP/WebSocket transport and bundled libsecp256k1 for Schnorr
signature verification. The current build targets Windows with GCC/MinGW.

## Repository Structure

```
nostrogotho/
├── .git/                    Version control
├── .venv/                   Python virtual environment
├── build/                   Generated build output
├── nob.c                    Two-stage build driver
├── nob.h                    Nob header
├── nostrogotho.sqlite       SQLite database (WAL mode)
├── nob.c README.md          Nob build system documentation
├── QUICKSTART.md            Quick start guide
├── README.md                Project overview and NIP support
├── NOSTR_COMPATABILITY.md   NIP implementation status (living document)
├── INDEX.md                 Documentation index
├── TODO.md                  TODO list
├── src/                     Source code (C99)
│   ├── nostrogotho.h/c      Core data structures
│   ├── crypto.h/c           Cryptographic ops
│   ├── storage.h/c          SQLite3 layer
│   ├── relay.h/c            Relay runtime + policy dispatch
│   ├── connection_session.h/c  Connection/session abstraction
│   ├── transport/server.h/c   Pure Mongoose transport adapter
│   ├── protocol/            Protocol parsing/serialization
│   ├── protocol/               Generic event/tag utilities
│   ├── validation/          Event validation pipeline
│   ├── subscriptions/       Subscription lifecycle + matching
│   └── nips/                NIP capability modules (01, 09, 11, 13, 17, 26, 40, 42, 45, 62, 67)
│       ├── nip_capability.c/h  Capability registry + composition
│       └── nip_template.c      New-NIP scaffold (excluded from build)
├── thirdparty/              Bundled dependencies
│   ├── sqlite3.c/h          SQLite3 amalgamation
│   ├── mongoose/            WebSocket library
│   └── secp256k1/           Schnorr signature library
└── tests/                   C + Node.js test suites (run with `nob -test`)
```

## Quick Build & Run (Windows PowerShell)

```powershell
# Build the nob driver
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe

# Run the nob builder
.\nob.exe

# Run the relay with default settings
.\build\main.exe

# Or with custom service URL
.\build\main.exe -service-url wss://relay.example.com
```

**Default listener:** `0.0.0.0:7447`
**Default database:** `./nostrogotho.sqlite`

Put public relays behind a TLS-terminating reverse proxy and configure the external
`wss://` address with `-service-url`.

See [QUICKSTART.md](QUICKSTART.md) for detailed local setup and deployment guidance.

## Testing

One command runs the entire regression suite (C unit/integration tests plus
Node.js end-to-end tests), verifying every suite's exit code:

```powershell
.\nob.exe -test
```

`nob -test` builds the relay first (the JS suites spawn it themselves),
then runs each suite and fails if **any** suite exits nonzero. Prerequisites
are the same C compiler `nob` uses, plus Node 18+ for the JS phase
(`tests/node_modules` is installed automatically when missing). Stop any
dev relay on the test ports first; each suite uses fixed ports and cleans
up its own database files.

### C suites (compiled with relay-identical flags)

| Suite | File | What it proves |
|---|---|---|
| crypto | `tests/test_crypto.c` | 83 checks: SHA-256 NIST vectors; hex conversion edge cases; event-ID canonical serialization byte-identical to OS-hashed vectors; in-test libsecp256k1 signing vs `crypto.c` verification with tamper matrix; full `check_event` incl. NIP-26 delegation; `json_escape` table; NIP-13 difficulty |
| sha256 | `tests/test_sha256.c` | FIPS 180-4 vectors (`""`, `"abc"`, 56-byte, 1M `'a'`) through the public `sha256()` API |
| storage | `tests/test_storage.c` | `escape_like` boundaries; `filter_free` ownership |
| json_util | `tests/test_json_util.c` | 7 security regressions: 40-id filter intactness, ~65 KB builder boundedness, oversized-tag rejection, size prediction, hex64 enforcement, empty-filter defaults, builder number format |
| json_fuzz | `tests/test_json_fuzz.c` | Deterministic structured fuzzing of `json_array_parse`, `json_parse_event`, `json_parse_filter` (200k mutated frames; bounds, free-safety, determinism, heap integrity). Reproduce case N: `build/test_json_fuzz 1 <seed> -v <N>` |
| composition | `tests/test_nip_composition.c` | 47 checks of `nip_capability.c` rules with two conflicting mock policies per type |
| hotreload | `tests/test_hotreload.c` + `tests/hr_test_policy.c` | Real module DLL build → load with ABI-symbol validation → policy check → rebuild with flipped policy while loaded → reload → new policy active; bad-ABI and missing-file refusal |
| relay | `tests/test_relay.c` | Boot smoke test: storage init + `relay_create` + listen on `:7457` |

### Node.js suites (`node tests/<script>`, helpers in `tests/relay.js`)

| Suite | File | What it proves |
|---|---|---|
| auth | `test_auth.js` | NIP-42 AUTH challenge round trip |
| nip13 | `test_nip13.js` | NIP-13 PoW: mined event accepted, unmined rejected (`-min-pow 8`) |
| integration | `test_integration.js` | 15 scenarios: publish/subscribe, filters, tags, subscription/filter limits, COUNT, NIP-09 deletion, NIP-40 expiry, stored/live equivalence, invalid events, malformed messages, concurrency, duplicates, PoW, wrong-relay AUTH, kind-4 DM gating |
| hotreload_integration | `test_hotreload_integration.js` | Linux: two live module publications preserve socket + REQ/EOSE (self-skips elsewhere) |
| ws | `test_ws.js` | AUTH + REQ/EOSE round trip (own relay on `:7472`; `--uri` probes a running one) |
| ws2 | `test_ws2.js` | REQ + id-filtered REQ + COUNT with response assertions (own relay on `:7473`) |
| hotreload_ws | `test_hotreload_ws.js` | Live reload over WS: hot host up, REQ/EOSE pre-reload, module rebuilt, new `nhr_<pid>_*` generation observed, same socket REQ/EOSE post-reload |

`tests/hotreload_live_smoke.js` is intentionally **not** part of `-test`: it is
interactive (idles 20s for a manual module rebuild). Its automated counterpart
is `test_hotreload_ws.js`. See [tests/README.md](tests/README.md) for
contributor conventions (deterministic vectors, mock-over-reimplementation,
fixed test ports).

The suites have caught real bugs: a NIP-26 delegation-verification bypass
(off-by-one tag index), `json_escape` silent truncation, order-dependent
kind-handler composition, unindexed stored tag queries, and silent filter-list
truncation -- all fixed with regression coverage above.

## Configuration

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `-database PATH`, `--db PATH` | `DATABASE_URL` | `./nostrogotho.sqlite` | SQLite database path or URI. |
| `-port PORT`, `--port PORT` | None | `7447` | Listener TCP port. |
| `-service-url URL` | `SERVICE_URL` | Empty | Public URL used by NIP-42 and NIP-62. |
| `-min-pow BITS` | `MIN_POW_DIFFICULTY` | `0` | Required NIP-13 difficulty; `0` disables it. |
| `-created-at-lower-limit SECONDS` | `CREATED_AT_LOWER_LIMIT` | `0` | Maximum accepted event age; `0` disables it. |
| `-created-at-upper-limit SECONDS` | `CREATED_AT_UPPER_LIMIT` | `900` | Maximum allowed future timestamp; `0` disables it. |

Run `.\build\main.exe --help` for the built executable's options.

## NIP Support Status

The relay implements 11 NIPs via the capability interface. Status as of 2026-09-26:

| NIP | Title | Capabilities | Status |
|-----|-------|--------------|--------|
| 01 | Basic Protocol Flow | kind_handler (replaceable/addressable) | ✅ Complete |
| 09 | Event Deletion Request | kind_handler (kind 5 deletion) | ✅ Complete |
| 11 | Relay Information Document | lifecycle + metadata | ✅ Complete |
| 13 | Proof of Work | lifecycle + publication_policy (PoW) | ✅ Complete |
| 17 | Private Direct Messages | delivery_policy + protocol_response (auth hint) | ✅ Complete |
| 26 | Delegated Event Signing | publication_policy (delegation) | ✅ Complete |
| 40 | Expiration Timestamp | publication_policy + delivery_policy + maintenance (expiry/GC) | ✅ Complete |
| 42 | Client Authentication | lifecycle + connection + message_intercept + publication_policy + delivery_policy (kind-4 DM gating) + query_policy (DM early-reject) + protocol_response (challenge) | ✅ Complete |
| 45 | Event Counts | protocol_response (COUNT) | ✅ Complete |
| 62 | Request to Vanish | kind_handler (kind 62 vanish) | ✅ Complete |
| 67 | EOSE Completeness Hint | protocol_response (EOSE hints) | ✅ Complete |

**Target `supported_nips`:** `[1, 9, 11, 13, 17, 26, 40, 42, 45, 62, 67]`

All NIPs are implemented as single-file capability providers in `src/nips/nipXX.c` with self-registration. No per-NIP headers, no `*_capability.*` split, no `nip_plugin_t` — deleted. `nip_capability.h` holds the registry plus the kind-handler result type and the nip26/nip42 decls shared with core code.

## Capabilities

The relay supports the client messages `EVENT`, `REQ`, `COUNT`, `CLOSE`, and `AUTH`. It uses SQLite persistence with indexes for event IDs, authors, kinds, creation timestamps, and `e`/`p`/`a` tags. Filters support exact 64-char lowercase-hex IDs/authors (prefixes are rejected per NIP-01), kinds, tags, time ranges, and content search; stored events are delivered before EOSE. Over-limit filter lists are rejected (`NOTICE: error: invalid filter`); the server sends no acknowledgement for client `CLOSE` (the subscription is silently removed).

Protocol policy is handled through the NIP capability interface (`nip_capability.h`) rather than transport-layer plugins. The core dispatch lives in `relay.c` (protocol parsing/validation/subscription matching/policy evaluation) with pure transport in `transport/server.c` (Mongoose event loop + WebSocket framing).

The capability interface defines deterministic composition rules:
- Publication policies: ALL must permit (AND)
- Delivery policies: ANY may veto (OR)
- Query policies: ALL must permit (AND)
- Kind handlers: ALL matched handlers are consulted; ANY reject wins (AND).
  A later accept never flips a prior reject back to true.
- Maintenance handlers: ALL run
- Lifecycle/connection/message-intercept: all run
- Metadata/protocol-response: first non-NULL wins

## Development

| Guide | Use it for |
| --- | --- |
| [QUICKSTART.md](QUICKSTART.md) | Building and operating a local relay. |
| [API_REFERENCE.md](API_REFERENCE.md) | Public C data structures and interfaces. |
| [PLAN.md](PLAN.md) | Architecture refactor plan with completion criteria. |
| [NOB_HOTRELOAD.md](NOB_HOTRELOAD.md) | Hot-reload build and supervision. |

The build definition uses [nob](nob.c). Before submitting a change, run the validation command in [PLAN.md](PLAN.md).

## Capabilities

The relay supports the client messages `EVENT`, `REQ`, `COUNT`, `CLOSE`, and
`AUTH`. It uses SQLite persistence with indexes for event IDs, authors, kinds,
creation timestamps, and `e`/`p`/`a` tags. Filters support exact 64-char
lowercase-hex IDs/authors (prefixes are rejected per NIP-01), kinds, tags,
time ranges, and content search; stored events are delivered before EOSE.

| NIP | Status | Relay support |
|-----|--------|---------------|
| 01 | Supported | Validates event IDs and Schnorr signatures; accepts publishes, queries, subscriptions, closes, notices, `OK`, and EOSE responses. |
| 09 | Supported | Processes deletion requests for event IDs and addressable-event coordinates, including recipient-authorized gift-wrap deletion. |
| 11 | Supported | Returns a relay information document when clients request `application/nostr+json`. |
| 13 | Supported | Enforces an optional, configurable minimum proof-of-work difficulty. |
| 16 | Supported | Replaces older events for replaceable event kinds. |
| 17 | Supported | Restricts gift-wrap delivery, including stored query replay, to authenticated `p`-tag recipients. |
| 26 | Supported | Verifies delegation signatures and delegation conditions. |
| 33 | Supported | Replaces parameterized replaceable events using their `d` tag. |
| 40 | Supported | Omits expired events from stored event queries. |
| 42 | Supported | Issues cryptographically random single-use challenges and verifies signed client authentication events with relay-tag binding (wrong-relay and tagless AUTH is rejected; replays fail). Kind-4 DMs are gated per-event to authenticated participants (author or `p` tag) across live, stored, and COUNT queries, with query-time early rejection. |
| 45 | Supported | Handles `COUNT` queries. |
| 62 | Supported | Processes Request to Vanish events targeting this relay or `ALL_RELAYS`. |
| 67 | Supported | Emits an EOSE completeness hint when a query exceeds its configured limit. |
| AC | Supported | Handled WebRTC signaling for peer-to-peer communication. |

## Protocol Modules

Protocol policy is isolated under [src/nips](src/nips). `server.c` owns the
Mongoose event loop, WebSocket framing, subscription lifecycle, and dispatch;
NIP modules own protocol-specific decisions. Every supported server-side NIP has
its own implementation and header: `nip09`, `nip11`, `nip13`, `nip17`, `nip33`,
`nip62`, and `nip40`/`nip45`/`nip67`. Shared event-tag inspection lives in
`nip_event`. Add new NIP behavior in this directory and expose a small,
documented interface rather than growing the transport loop.

## Social Network Roadmap

The following items would make the relay a stronger foundation for a
large-scale social network. They are future work, not current support claims.

| Priority | NIPs and capability | TODO |
| --- | --- | --- |
| High | NIP-02, NIP-10, NIP-25, NIP-51, NIP-65 | Add social graph, thread, reaction, list, and relay-list indexing for feed construction and profile features. |
| High | NIP-50 | Replace the SQLite `LIKE` search with a bounded full-text index, ranking, query limits, and abuse controls. |
| High | NIP-45, NIP-77 | Add bounded approximate counts and Negentropy synchronization for efficient client refresh and relay migration. |
| High | Relay operations | Add per-IP and per-pubkey rate limits, connection quotas, backpressure limits, event retention policies, metrics, structured logs, backups, and database migrations. |
| Medium | NIP-29, NIP-72, NIP-86 | Add group/community events plus a relay-management API with authenticated administration and audit logging. |
| Medium | NIP-05, NIP-19, NIP-21, NIP-27 | Add identifier, entity, URI, and reference-aware indexing to improve discovery and link resolution. |
| Medium | NIP-44, NIP-46, NIP-47, NIP-98 | Support modern encrypted payload, remote signer, wallet-connect, and HTTP authentication workflows where relay-side handling is appropriate. |
| Medium | NIP-66, NIP-70 | Publish liveness/discovery metadata and enforce protected-event access rules. |
| Later | Scale and federation | Read replicas, durable job queues, sharding/partitioning, multi-relay replication, and a documented operational deployment model. |

## Build

The project uses [nob](nob.c) and GCC; it does not use a project CMake build. Build the bootstrap executable and invoke it from the repository root:

```powershell
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
.\nob.exe
```

`nob` compiles the relay and SQLite amalgamation directly. It links the other bundled dependencies from `thirdparty/`, which must contain the configured headers and static libraries for mongoose, secp256k1, and OpenSSL. The output executable is `build/main.exe`.
