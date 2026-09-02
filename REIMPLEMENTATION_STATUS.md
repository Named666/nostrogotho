# Current Status

The C99 relay implementation is complete and builds/runs end-to-end. Current
capability is documented in [README.md](README.md); this file tracks
completeness in more detail and the roadmap toward a high-performance,
feature-complete relay. For contribution workflow, use
[IMPLEMENTATION.md](IMPLEMENTATION.md).

## Build Status

`gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe && .\nob.exe` produces
`build/main.exe`, which links the relay, SQLite amalgamation, bundled
mongoose, and bundled secp256k1 from source (no external dependencies, no
cmake/perl/autotools). OpenSSL is used for SHA-256 hashing only.

## Component Completeness

| Module | Lines | Status |
| --- | --- | --- |
| [src/cagliostr.c](src/cagliostr.c) / [.h](src/cagliostr.h) | ~250/180 | Complete: event/filter/tag allocation and ownership. |
| [src/crypto.c](src/crypto.c) / [.h](src/crypto.h) | ~684/197 | Complete: SHA-256, Schnorr verify (secp256k1), NIP-26 delegation, NIP-13 PoW, JSON string escaping. |
| [src/json_util.c](src/json_util.c) / [.h](src/json_util.h) | ~712/232 | Complete: bounded JSON array/object parsing for protocol frames, filters, and events; serialization via `json_builder_t`. |
| [src/storage.c](src/storage.c) / [.h](src/storage.h) | ~886/214 | Complete: SQLite schema, indexes, WAL mode, CRUD, filtered queries, COUNT, deletion strategies for NIP-09/16/33/62, NIP-40 expiration filtering. |
| [src/server.c](src/server.c) / [.h](src/server.h) | ~467/12 | Complete: mongoose HTTP/WebSocket handling, NIP-01 message dispatch (`EVENT`/`REQ`/`CLOSE`/`COUNT`/`AUTH`), NIP-42 challenge/auth, NIP-11 info document, NIP-17 gift-wrap recipient gating, NIP-62 vanish, replaceable/parameterized-replaceable/addressable event handling, NIP-67 EOSE hints. |
| [src/main.c](src/main.c) | ~93 | Complete: CLI/env configuration, signal handling, storage/crypto init and shutdown. |

All NIPs listed in the [README.md](README.md) support table (01, 09, 11, 13,
16, 17, 26, 33, 40, 42, 45, 62, 67) are implemented in `server.c`/`storage.c`
and exercised by the running relay, not stubs.

## Known Correctness/Hardening Gaps

1. **Fixed-size query buffers** (`storage.c`, `send_records()`): conditions
   (2048 B), SQL (4096 B), and parameter (256) buffers are bounds-checked and
   reject oversized filters, but do not support arbitrarily large filter
   arrays. Replacing with dynamic allocation would remove the 256-element
   filter cap.
2. **No rate limiting or connection quotas**: `server.c` has no per-IP or
   per-pubkey request/event throttling, no backpressure limits beyond the
   5 MiB WebSocket frame cap, and no connection quotas. A public deployment
   needs a reverse proxy or added in-process limiting.
3. **Single SQLite connection, single-threaded event loop**: matches the
   documented limitation in README but caps throughput; no read replicas or
   WAL-backed concurrent readers are wired up beyond SQLite's own WAL mode.
4. **`search` filter is a raw SQL `LIKE`**: functional but unranked, unbounded
   in cost, and not a real full-text index (see NIP-50 roadmap item below).
5. **No metrics, structured logging, or admin API**: operational visibility is
   limited to stderr messages.

## Roadmap

Prioritized future work, mirroring [README.md](README.md)'s Social Network
Roadmap table:

### High priority
- Social graph, thread, reaction, list, and relay-list indexing (NIP-02,
  NIP-10, NIP-25, NIP-51, NIP-65) to support feed construction and profiles.
- Replace `LIKE`-based search with a bounded full-text index, ranking, query
  limits, and abuse controls (NIP-50).
- Bounded approximate counts and Negentropy sync for efficient client refresh
  and relay migration (NIP-45, NIP-77).
- Relay operations: per-IP/per-pubkey rate limits, connection quotas,
  backpressure limits, event retention policies, metrics, structured logs,
  backups, and database migrations.

### Medium priority
- Group/community events and an authenticated relay-management API with
  audit logging (NIP-29, NIP-72, NIP-86).
- Identifier/entity/URI/reference-aware indexing for discovery and link
  resolution (NIP-05, NIP-19, NIP-21, NIP-27).
- Relay-side support for modern encrypted payload, remote signer,
  wallet-connect, and HTTP-auth workflows where applicable (NIP-44, NIP-46,
  NIP-47, NIP-98).
- Liveness/discovery metadata and protected-event access enforcement
  (NIP-66, NIP-70).

### Later
- PostgreSQL support, read replicas, durable job queues,
  sharding/partitioning, multi-relay replication, and a documented
  operational deployment model.

## Testing Recommendations

1. Compare event hash/signature verification against a reference Nostr
   client for special characters (quotes, backslashes, UTF-8/emoji content).
2. Load-test with large filter arrays (near the 256-element and 10-filter
   caps) to validate the fixed-buffer limits in `send_records()`.
3. Exercise NIP-09/16/33/62 deletion and replacement paths for regressions
   before schema or query changes.
4. Run the relay under a WebSocket fuzzer/stress client to validate the
   5 MiB frame limit and 20-subscription cap under load.
5. Run valgrind/ASan over a full event lifecycle (insert, query, delete) to
   catch memory issues before enabling higher-throughput code paths.

## References

- [Nostr Protocol (NIP-01)](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [Nostr NIPs index](https://github.com/nostr-protocol/nips)
- [mongoose Documentation](https://mongoose.ws/)
- [secp256k1 GitHub](https://github.com/bitcoin-core/secp256k1)
- [SQLite Documentation](https://www.sqlite.org/docs.html)

---

**Last Updated**: 2026-09-01
**Status**: Feature-complete relay per README's supported-NIP table; hardening
and social-network-scale features are the remaining roadmap.
