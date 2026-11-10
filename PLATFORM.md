# Platform contract

nostrogotho's own code (everything outside `thirdparty/`) is written against
one explicit contract. Anything outside it is a bug.

| Layer | What we rely on | Where it is spelled |
|---|---|---|
| Language | ISO C99, compiled as `-std=gnu99` | build flags (`src_build/nob_linux.c`) |
| OS | POSIX.1-2008: pthreads (mutex, cond, `pthread_setname_np` on Linux only), BSD sockets, `clock_gettime(CLOCK_MONOTONIC)`, `strtoull`, `strncasecmp` | `_GNU_SOURCE` is defined for glibc prototypes |
| Atomics | GCC/Clang `__atomic_*` builtins (not C11 `<stdatomic.h>`) | `src/platform/ng_atomic.h` |
| Thread-local storage | GNU `__thread` | `NG_THREAD_LOCAL`, `src/platform/ng_platform.h` |
| Alignment, hints, bit scan | `__attribute__((aligned))`, `__builtin_expect`, `__builtin_ctzll` | `NG_ALIGNED`, `NG_LIKELY`, `ng_ctz64` in `ng_platform.h` |
| Overflow checks | `__builtin_add_overflow`, `__builtin_mul_overflow` | `src/platform/ng_alloc.h` |
| Plugin registration | `__attribute__((constructor))` | `src/nips/*.c` (see `nip_plugin.h`) |
| SIMD | SSE2 / AVX2 (x86-64) and NEON (AArch64) intrinsics, each with a scalar fallback selected by the compiler's predefined macros | `src/ws_proto.c` (`ws_unmask`, `ws_utf8_valid`) |
| Compilers | GCC or Clang (`#error` otherwise); built and tested with GCC 14.2 | `ng_platform.h` |

Rules:

- No C11-only constructs in first-party code: no `<stdatomic.h>`,
  `_Atomic`, `_Alignas`, `_Thread_local`, `_Static_assert`, `_Generic`,
  anonymous structs/unions. `-Wpedantic` under `-std=gnu99` enforces this.
- Atomic objects are one-member structs (`ng_atomic_int`, `ng_atomic_size`,
  ...). A plain read or write of one does not compile; every access names
  its memory order through `ng_atomic_*` and generates the same code as the
  C11 operations it replaced.
- Every allocation whose size is computed (counts, peer-controlled lengths)
  uses `ng_alloc.h` (`ng_malloc_array`, `ng_malloc_flex`, `ng_malloc_add`,
  `ng_size_add`/`ng_size_mul`, `ng_grow_cap`). Overflow fails like OOM.
- Vendored code (`thirdparty/`: uSockets, SQLite, libsecp256k1) keeps its own
  language level (`-std=gnu11`) and is compiled to separate objects with the
  default warnings. Its headers reach our code through `-isystem`, so its
  warnings are never reported as ours. Patches to vendored code are listed in
  `thirdparty/VENDOR.md`.
- Performance is not traded for purity. If the contract ever blocks a
  measured optimization, the contract is extended here first (one new
  adapter in `src/platform/`), not bypassed in place.

## Warnings

First-party code builds with:

    -std=gnu99 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    -Wstrict-prototypes -Wmissing-prototypes

`NG_WERROR=1 ./nob linux` adds `-Werror`. `tools/strict_check.sh` compiles
every first-party translation unit (relay, tools, C tests) with that set and
prints counts by flag and file; it exits non-zero on any warning. Warnings
are fixed at the site; nothing is suppressed globally.
