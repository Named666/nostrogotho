# Vendored third-party code

Pinned to the exact commits the previous (dangling, no .gitmodules) gitlinks pointed at.

| Dir | Upstream | Commit | Version | Files kept |
|---|---|---|---|---|
| uSockets/ | https://github.com/uNetworking/uSockets | 166a048 | v0.8.x | src/ (epoll backend; SSL/QUIC/io_uring/libuv sources removed, built with -DLIBUS_NO_SSL), LICENSE (Apache-2.0) |
| secp256k1/ | https://github.com/bitcoin-core/secp256k1 | a9a61831bdcd97475e200a4bdd1ebed641f7268d (2026-08-30) | master | include/, src/, COPYING (MIT) |
| sqlite3.c/.h | https://sqlite.org amalgamation | 3.54.1 (zip sha3-256 92281c86…e30, matches sqlite.org) | 3.54.1 | sqlite3.c, sqlite3.h (public domain) |

thirdparty/nips is still a gitlink to the NIPs spec fork (not needed to build).

## uSockets
- Upstream: https://github.com/uNetworking/uSockets
- Commit: 166a04810c9fa970fc22096a7b35b792378364fb
- License: Apache-2.0 (thirdparty/usockets/LICENSE)
- Vendored: src/ only; removed sni_tree.cpp and asio.cpp (C++/TLS-only). Built with -DLIBUS_NO_SSL (epoll backend); TLS terminated by nginx.

Removed: the previous GPLv2/commercial transport library — replaced by the in-tree ngws server.
Evaluated and rejected: wslay (MIT) as the frame codec. Benchmarked against the
in-tree `src/ws_proto.c` codec; the native codec was equal or faster in every
case and used less CPU per byte (see BENCHMARKS.md), so wslay is not vendored.
