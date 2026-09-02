# nostrogotho
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
| Later | Scale and federation | Add PostgreSQL support, read replicas, durable job queues, sharding/partitioning, multi-relay replication, and a documented operational deployment model. |

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
