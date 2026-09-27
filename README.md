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
│   ├── server.c             WebSocket server + NIP plugins
│   └── main.c               Example main entry point
├── thirdparty/              Bundled dependencies
│   ├── sqlite3.c/h          SQLite3 amalgamation
│   ├── mongoose/            WebSocket library
│   └── secp256k1/           Schnorr signature library
└── src/nips/                NIP protocol plugins
    ├── nip01.c            Basic Protocol Flow
    ├── nip09.c            Event Deletion Request
    ├── nip11.c            Relay Information Document
    ├── nip13.c            Proof of Work
    ├── nip17.c            Private Direct Messages
    ├── nip26.c            Delegated Event Signing
    ├── nip40.c            Expiration Timestamp
    ├── nip42.c            Client Authentication
    ├── nip45.c            Event Counts
    ├── nip62.c            Request to Vanish
    ├── nip67.c            EOSE Completeness Hint
    ├── nip_template.c        New-NIP scaffold (excluded from build)
    └── nip_capability.c/h       Capability registry + composition
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

The relay implements 13 NIPs. Status as of the 2026-09-03 audit:

| NIP | Title | Status | Wired into server |
|-----|-------|--------|-------------------|
| 01 | Basic Protocol Flow | ✅ Complete | Yes |
| 09 | Event Deletion Request | ✅ Complete | Yes |
| 11 | Relay Information Document | ✅ Complete | Yes (HTTP) |
| 13 | Proof of Work | ✅ Complete | Yes |
| 16 | Event Treatment | ✅ Complete (→ NIP-01) | Yes |
| 17 | Private Direct Messages | ✅ Complete | Yes |
| 26 | Delegated Event Signing | ✅ Complete | Yes |
| 33 | Parameterized Replaceable Events | ✅ Complete (→ NIP-01) | Yes |
| 40 | Expiration Timestamp | ✅ Complete | Yes |
| 42 | Client Authentication | ✅ Complete | Yes |
| 45 | Event Counts | ✅ Complete | Yes |
| 62 | Request to Vanish | ✅ Complete | Yes |
| 67 | EOSE Completeness Hint | ✅ Complete | Yes |

**Target `supported_nips`:** `[1, 9, 11, 13, 16, 17, 26, 33, 40, 42, 45, 62, 67]`

## Limits And Operations

- WebSocket frames: 5 MiB maximum.
- Events: 100 tags and 16 KiB content maximum.
- Client subscriptions: 20 maximum, with 10 filters per subscription.
- Query limit: 500 events per filter by default.
- Storage: one process and one SQLite connection. Back up the database and test
  retention, reverse-proxy, rate-limit, and monitoring policies before a public
  deployment.

## Development

| Guide | Use it for |
| --- | --- |
| [QUICKSTART.md](QUICKSTART.md) | Building and operating a local relay. |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Architecture, behavior boundaries, and contribution workflow. |
| [API_REFERENCE.md](API_REFERENCE.md) | Public C data structures and interfaces. |
| [NOSTR.md](NOSTR.md) | Nostr message types and supported-NIP reference. |

The build definition uses [nob](nob.c). Before submitting a change, run the
validation command in [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Capabilities

The relay supports the client messages `EVENT`, `REQ`, `COUNT`, `CLOSE`, and
`AUTH`. It uses SQLite persistence with indexes for event IDs, authors, kinds,
and creation timestamps. Filters support ID and author prefixes, kinds, tags,
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
| 42 | Supported | Issues cryptographically random challenges and verifies signed client authentication events. |
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

`nob` compiles the relay and SQLite amalgamation directly. It links the other
bundled dependencies from `thirdparty/install`, which must contain the
configured headers and static libraries for mongoose, secp256k1, and
OpenSSL. The output executable is `build/nostrogotho.exe`.
