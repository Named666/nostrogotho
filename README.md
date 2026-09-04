# nostrogotho

`nostrogotho` is a C99 Nostr relay with SQLite persistence. It uses bundled
Mongoose for HTTP/WebSocket transport and bundled libsecp256k1 for Schnorr
signature verification. The current build targets Windows with GCC/MinGW.

## Run A Relay

1. Clone the repository with `thirdparty/` intact.
2. From the repository root, build the two-stage `nob` driver and relay:

   ```powershell
   gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
   .\nob.exe
   ```

3. Run the generated executable:

   ```powershell
   .\build\main.exe -service-url wss://relay.example.com
   ```

The default listener is `0.0.0.0:7447`; the default database is
`./nostrogotho.sqlite`. Put public relays behind a TLS-terminating reverse proxy
and configure the external `wss://` address with `-service-url`.

See [QUICKSTART.md](QUICKSTART.md) for local setup and deployment guidance.

## Configuration

| Option | Environment | Default | Description |
| --- | --- | --- | --- |
| `-database PATH`, `--db PATH` | `DATABASE_URL` | `./nostrogotho.sqlite` | SQLite database path or URI. |
| `-port PORT`, `--port PORT` | None | `7447` | Listener TCP port. |
| `-service-url URL` | `SERVICE_URL` | Empty | Public URL used by NIP-42 and NIP-62. |
| `-min-pow BITS` | `MIN_POW_DIFFICULTY` | `0` | Required NIP-13 difficulty; `0` disables it. |
| `-created-at-lower-limit SECONDS` | `CREATED_AT_LOWER_LIMIT` | `0` | Maximum accepted event age; `0` disables it. |
| `-created-at-upper-limit SECONDS` | `CREATED_AT_UPPER_LIMIT` | `900` | Maximum allowed future timestamp; `0` disables it. |

Run `.\build\main.exe --help` for the built executable's options.

## NIP Support

| NIP | Status | Behavior |
| --- | --- | --- |
| NIP-01 | Supported | Validates signed events and supports `EVENT`, `REQ`, `CLOSE`, `NOTICE`, `OK`, `EVENT`, and `EOSE` frames. |
| NIP-09 | Supported | Processes event-ID and addressable-event deletion requests, including gift-wrap recipient authorization. |
| NIP-11 | Supported | Serves relay metadata for requests accepting `application/nostr+json`. |
| NIP-13 | Supported | Enforces configurable proof of work. |
| NIP-16 | Supported | Replaces older replaceable events. |
| NIP-17 | Supported | Restricts gift-wrap delivery to NIP-42-authenticated `p`-tag recipients. |
| NIP-26 | Supported | Verifies delegation signatures and supported conditions. |
| NIP-33 | Supported | Replaces parameterized replaceable events by `d` tag. |
| NIP-40 | Supported | Omits expired events from stored queries. |
| NIP-42 | Supported | Issues random challenges and validates signed client authentication events. |
| NIP-45 | Supported | Handles `COUNT` queries. |
| NIP-62 | Supported | Processes vanish events targeting this relay or `ALL_RELAYS`. |
| NIP-67 | Supported | Adds `more` or `finish` EOSE completeness hints. |

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

The build definition is [src_build/nob_configed.c](src_build/nob_configed.c).
Before submitting a change, run the validation command in
[IMPLEMENTATION.md](IMPLEMENTATION.md).# nostrogotho
A Nostr relay server written in C99 using bundled mongoose, secp256k1,
SQLite, and OpenSSL sources.

## Capabilities

The relay supports the client messages `EVENT`, `REQ`, `COUNT`, `CLOSE`, and
`AUTH`. It uses SQLite persistence with indexes for event IDs, authors, kinds,
and creation timestamps. Filters support ID and author prefixes, kinds, tags,
time ranges, and content search; stored events are delivered before EOSE.

| NIP | Status | Relay support |
| --- | --- | --- |
| NIP-01 | Supported | Validates event IDs and Schnorr signatures; accepts publishes, queries, subscriptions, closes, notices, `OK`, and EOSE responses. |
| NIP-09 | Supported | Processes deletion requests for event IDs and addressable-event coordinates, including recipient-authorized gift-wrap deletion. |
| NIP-11 | Supported | Returns a relay information document when clients request `application/nostr+json`. |
| NIP-13 | Supported | Enforces an optional, configurable minimum proof-of-work difficulty. |
| NIP-16 | Supported | Replaces older events for replaceable event kinds. |
| NIP-17 | Supported | Restricts gift-wrap delivery, including stored query replay, to authenticated `p`-tag recipients. |
| NIP-26 | Supported | Verifies delegation signatures and delegation conditions. |
| NIP-33 | Supported | Replaces parameterized replaceable events using their `d` tag. |
| NIP-40 | Supported | Omits expired events from stored event queries. |
| NIP-42 | Supported | Issues cryptographically random challenges and verifies signed client authentication events. |
| NIP-45 | Supported | Handles `COUNT` queries. |
| NIP-62 | Supported | Processes Request to Vanish events targeting this relay or `ALL_RELAYS`. |
| NIP-67 | Supported | Emits an EOSE completeness hint when a query exceeds its configured limit. |

Runtime configuration supports the database path, listener port, public service
URL, proof-of-work difficulty, and accepted `created_at` window through
command-line arguments or environment variables.

## Protocol Modules

Protocol policy is isolated under [src/nips](src/nips). `server.c` owns the
Mongoose event loop, WebSocket framing, subscription lifecycle, and dispatch;
NIP modules own protocol-specific decisions. Every supported server-side NIP
has its own implementation and header: `nip09`, `nip11`, `nip13`, `nip16`,
`nip17`, `nip33`, and `nip62`. Shared event-tag inspection lives in
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

The project uses [nob](nob.c) and GCC; it does not use a project CMake build.
Build the bootstrap executable and invoke it from the repository root:

```powershell
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
.\nob.exe
```

`nob` compiles the relay and SQLite amalgamation directly. It links the other
bundled dependencies from `thirdparty/install`, which must contain the
configured headers and static libraries for mongoose, secp256k1, and
OpenSSL. The output executable is `build/nostrogotho.exe`.
