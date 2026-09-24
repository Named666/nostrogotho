# Nob Hot Reload (NHR) — Implementation Specification

**Status:** implementation underway. `src_build/nob_linux.c` and `src_build/nob_win.c` remain separate target builders by design. The choices below are the design baseline; update the final sections with verified behavior and test results as implementation lands.

## Goal and developer experience

NHR recompiles the relay's replaceable protocol/application code while keeping the relay process alive. Live WebSocket connections, the Mongoose event manager, SQLite, subscriptions and host-owned configuration survive reloads. The ordinary build remains a monolithic executable and does not require a dynamic loader.

The opt-in developer command is:

```text
nob [win|linux] -hr -- [relay arguments...]
```

For example, `nob win -hr -- -port 7447 --db ./dev.sqlite` builds the hot-reload host and module, launches the relay, watches source changes, debounces editor save bursts and rebuilds only the module. Relay arguments after `--` go to the host. `nob [win|linux]` continues to perform the current one-shot monolithic build. Ctrl-C stops the supervised relay cleanly.

Nob is the development supervisor, not part of runtime module loading. The host detects a newly published module artifact at its event-loop boundary and reloads it. A failed build never replaces the last good artifact; a failed candidate load never displaces the currently running module.

## Reference model: Musializer

[tsoding/musializer](https://github.com/tsoding/musializer) demonstrates a deliberately small C hot-reload design:

- one X-macro list defines module entry points and function-pointer types;
- a permanent executable loads a shared object/DLL and resolves the listed symbols;
- platform loaders wrap POSIX `dlopen`/`dlsym`/`dlclose` and Windows `LoadLibrary`/`GetProcAddress`/`FreeLibrary`;
- explicit pre/post-reload hooks pass state between module generations;
- build scripts compile replaceable code as a separate shared library.

NHR adopts those ideas, not its source. This relay is headless and its Mongoose callbacks, socket manager, SQLite connection and authenticated client records have longer lifetimes than plugin code. Therefore NHR adds ABI validation, unique per-generation library filenames, host-owned callback/timer state, a candidate validation/switch protocol, and preservation of the running module after build/load failures. The live relay policy must never leave a callback, data pointer, or timer into a library after that library is unloaded.

## Verified codebase baseline

- `nob.c` is the first-stage dispatcher. It selects `src_build/nob_win.c` or `src_build/nob_linux.c`, builds that script, then runs it. It currently recognizes `win`, `linux`, and help, and otherwise ignores unrelated arguments.
- `src_build/nob_win.c` and `src_build/nob_linux.c` are retained as distinct platform build entry points. Their ordinary mode builds the existing monolithic relay; hot mode builds a permanent host and reloadable NIP module separately.
- `src_build/nob_configed.c` is a separate/alternate recipe and is not selected by the current `nob.c` dispatcher. Do not silently make it a third implementation path; either leave it explicitly unsupported for NHR or deliberately route it through shared build logic.
- `src/main.c` owns CLI/environment parsing, crypto and storage initialization, signal setup, and process cleanup.
- `src/server.c` owns permanent Mongoose transport/event-loop responsibilities and host subscription/filter allocations. In hot mode it dispatches REQ/COUNT/EVENT and NIP policy through the active module interface; static fallbacks remain compiled only for ordinary builds.
- `src/nips/nip_plugin.c` owns a per-image registry populated by constructors. Plugin send requires a host-provided bridge; plugin implementation must not call Mongoose transport directly.
- `src/storage.c` owns SQLite and generic selectors/index operations. NIP modules provide synchronous criteria; legacy delegation rows are migrated into a generic tag/value index.
- `src/crypto.c` owns a static secp256k1 verify context, validates event IDs/signatures, and currently calls `nip26_check_delegation()` during `check_event()`.
- NIP-42 authentication clients are held in a module-global linked list containing live `mg_connection *`, challenge and authenticated pubkey. There is no current serialization API.
- `src/nips/nip_event.{h,c}` is shared event/tag inspection code and remains at that location; it must not be assumed to be host-only because NIP policy uses it.
- `nob.h` provides command execution, directory listing, mtime-based `needs_rebuild`, and blocking child waits. It does not provide a complete watch loop or a child-process liveness/termination abstraction.

These facts are from the current source and take precedence over earlier design notes that described host/loader files or NIP-42 migration hooks as already implemented; those files/APIs do not currently exist.

## Ownership boundary

### Permanent host

- `main()` process lifetime, CLI/environment parsing, signals, shutdown ordering;
- Mongoose manager, listener, event loop, transport event callback and connection handles;
- subscription IDs, filters and all memory referenced beyond a callback;
- SQLite connection, schema, backend, and persistent generic indexes;
- crypto/secp256k1 context and core event-ID/signature verification;
- dynamic loader, module generation paths, reload coordination, logging;
- host services and stable configuration snapshot.

### Reloadable relay module

- `src/nips/nip_plugin.{h,c}` registry and NIP constructor registration;
- relay protocol decisions extracted from `src/server.c`;
- `src/nips/*.c`, including NIP-01 dispatch and NIP-specific validation, with `nip_template.c` excluded;
- NIP policy state that can be explicitly serialized/restored or re-derived during module initialization.

The host event callback is permanent. It calls the currently active module synchronously, and no operation may unload a module while execution is inside one of its calls. The module uses host services for sending WebSocket/HTTP responses and storage/crypto operations; it does not retain host connection internals or call Mongoose transport functions directly.

## ABI and allocation rules

- `src/nhr.h` is the single authoritative C99-compatible ABI header. It defines the ABI version, export/calling-convention macros, `Nhr_State`, opaque host handles, the versioned host-services table, and an X-macro list of module exports.
- The X-macro exports one ABI version query, `init`, `shutdown`, explicit `pre_reload` and `post_reload`, plus only the host dispatch calls (connect/disconnect/message, publish/delivery, filter/query/event processing, maintenance, and protocol response construction). It does not export plugin-specific helpers such as NIP-26 tag extraction or internal sender functions.
- Never pass the existing `storage_context_t *` across the dynamic boundary. Module adapters call host service functions. ABI-visible event/filter structures must have fixed-width/versioned layouts or be represented as sized byte/string views.
- Every pointer has an explicit owner and lifetime. Module response strings are either caller-provided buffers or paired module/host allocator functions. The host may not `free()` module memory, and the module may not retain borrowed message/config/event memory after a call.
- Host callbacks into the module are synchronous and are never saved by host storage or Mongoose. Storage predicate callbacks are invoked only within the operation; if a result must persist, storage copies a stable event ID/value into host-owned memory before returning.
- NIP-42 state migration uses a versioned blob whose bytes are allocated/freed by the host. It includes only challenge and authenticated pubkey data associated with host-owned connection identities; no module pointer is embedded. Incompatible/invalid state is rejected safely, with a documented policy for re-challenge versus preserving the relay.
- Shared module and host runtime must use compatible CRT/allocator conventions on Windows. Prefer host-provided allocation for cross-boundary blobs and avoid passing allocation-owned objects across the ABI.

## Storage contract: mechanics in storage, criteria in NIPs

Storage is a persistence mechanism, not the place where NIP policy is decided.

- Remove `purge_expired` and NIP-40 calls from the public storage interface and `src/storage.c`. Provide generic bounded event scanning/selection and exact-ID deletion primitives; NIP-40 supplies the expiry predicate and asks storage to delete matched IDs.
- Move expiry timestamp parsing, expired-event publish rejection, delivery suppression, and garbage-collection criteria into `src/nips/nip40.c`. Malformed expiration values must follow one explicitly tested policy; future-dated events must not be accidentally excluded from GC merely because their `created_at` value is in the future.
- Replace NIP-specific d-tag/p-tag deletion helpers with generic scoped candidate selectors and exact-ID deletion. NIP-01 replacement, NIP-09 deletion, and NIP-62 vanish code own their tag/author/kind/time criteria. Storage may use indexed columns to narrow candidates but must leave semantic validation to the NIP.
- Preserve NIP-26 delegated-author REQ behavior and existing databases. The current `delegation` table, backfill, and author subquery are NIP-26-specific. Introduce generic indexed-tag facilities (generic tag name/value-to-event-ID mechanics) so NIP-26 chooses and parses the `delegation` tag while storage only maintains/queries the generic index. Existing index data must be migrated/reused without changing `{authors:[...]}` results.
- Generic indexes must be maintained for all writes at the storage boundary, not by a stored callback into the unloadable module. NIP policy chooses index key/value semantics; storage owns safe, generic persistence mechanics.
- Keep `src/nips/nip_event.{h,c}` in place and use its helpers for NIP-side tag parsing.

## Build and reload protocol

### Build artifacts

- Default mode remains a single `build/main` monolithic executable.
- Hot mode emits a permanent host (`build/main` / Windows executable), a stable published candidate path, and unique loaded generations (platform suffix `.so`/`.dll`). Linux module compilation uses PIC/shared flags. Windows builds use explicit export and loader-compatible DLL flags.
- Host links SQLite, Mongoose transport, crypto and secp256k1. Module does not directly link against host implementation symbols. Any mirrored pure helper code must be stateless and must not duplicate live transport/resource ownership.
- Build the candidate under a temporary path and atomically publish only after the compiler/linker succeeds. Never overwrite the exact image currently loaded by the process.

### Startup and reload lifecycle

1. Host initializes crypto, SQLite and Mongoose-owned state.
2. Loader performs LOAD and ABI VALIDATION only: open a unique image, resolve every X-macro symbol, and check ABI version/table size. Constructors may build the new image's private registry but cannot acquire host resources or run plugin `init` hooks.
3. Call module `init(host, config, storage_handle)` exactly once, then enter RUN. Permanent Mongoose callbacks dispatch only to the active module table.
4. Nob watches source/header/config file mtimes and NIP-directory membership; it debounces writes and invokes the module-only build. A failed build logs diagnostics, preserves the last published library, and resumes watching.
5. Host notices a new artifact only at a safe event-loop boundary. It copies/opens a uniquely named candidate image and performs symbol/ABI validation while the active module remains in RUN. Do not initialize this preflight image.
6. Run old `pre_reload` to quiesce work and obtain host-owned versioned state; then run old `shutdown` and UNLOAD it. LOAD a fresh unique candidate image, ABI-validate it, and call its `post_reload(host, config, storage_handle, state)`. `post_reload` performs new-generation initialization, restores state and enters RUN. Switch host dispatch to the new function table only after `post_reload` succeeds.
7. If preflight fails, discard the candidate and continue with the active generation. If fresh LOAD or POST_RELOAD fails after old shutdown/unload, load the last-known-good published artifact into a new unique image and invoke POST_RELOAD with the same migration blob. If rollback also fails, stop dispatching and fail closed; never call a dangling old function pointer.
8. At process shutdown, stop accepting callbacks, invoke active module shutdown, unload it, then free Mongoose, storage and crypto in ownership order.

Never unload while a callback is running. Never let timers, subscriptions, queued work, storage backends, or connection fields retain module code/data pointers. Reload work occurs synchronously on the host event-loop thread unless a future design explicitly adds synchronization.

## Nob watch/supervisor behavior

- Parse `-hr` and optional `--` explicitly. Preserve a target selection (`win`/`linux`) and pass only arguments after `--` to the relay host. Unknown build options should fail with usage rather than silently disappearing.
- Nob builds host+module, launches host with relay arguments, polls source/config/NIP membership changes, debounces rapid saves, and performs module-only rebuilds. Runtime host checks module generation at event-loop boundaries.
- Source discovery must include C/H files that affect module compilation and NIP additions/removals, without treating generated `build/` outputs or transient SQLite WAL files as sources.
- Nob must notice host exit, stop the watcher, and return host status. Ctrl-C must stop/terminate the child and reap it on both Windows and POSIX. Since `nob.h` currently exposes blocking waits rather than a full process supervisor, implementation should add only the minimum portable child liveness/termination support required; alternatively a simpler proven mechanism may replace this requirement and must be documented.
- Keep build recipes shared where practical, but do not obscure platform flags or accidentally route the currently unused `src_build/nob_configed.c` into the active path.

## Implementation phases

1. **This document first:** capture design and criteria; review before touching implementation sources.
2. **Baseline and ABI:** ensure default build remains known-good; add the ABI and host service design; identify exact module exports and direct-call fallback.
3. **Storage boundary:** add generic scan/index/delete APIs; move expiry and tag criteria into NIP modules; preserve delegation migration/queries.
4. **Host/module extraction:** split transport from relay policy; ensure host-owned subscriptions and no retained callbacks into module code.
5. **Loader and migration:** implement POSIX/Windows loaders, ABI validation, unique copies, NIP-42 explicit state, safe candidate switching and fallback.
6. **Build supervisor:** add `-hr`, argument forwarding, module-only build, debounced polling, child lifecycle, Ctrl-C handling.
7. **Regression and final docs:** run C tests, protocol smoke tests, Windows/Linux build checks, live reload/failure recovery; record actual behavior and limitations here.

## Current implementation status

- The design-first specification and opt-in `-hr` command shape are in place.
- `nhr.h` is the ABI source of truth. Candidate preflight is split from activation. Activation uses the order PRE_RELOAD → SHUTDOWN/UNLOAD → fresh LOAD/ABI VALIDATION → POST_RELOAD → RUN; post-reload failure attempts rollback. End-to-end rollback behavior is not yet runtime-verified.
- `nob_linux.c` and `nob_win.c` remain separate. The Linux builder has a module-only target rebuild; Windows has a retained in-file hot build/watch path. Neither has passed an end-to-end toolchain/runtime check in this environment.
- Storage's `purge_expired` and tag-specific d/p delete callbacks have been replaced by generic bounded predicate selection. NIP-01, NIP-09, NIP-40, and NIP-62 now supply policy predicates; NIP-26 has generic tag-key extraction/query constraints and a legacy delegation index migration path.
- Partitioned C syntax checks have passed for the module, dynamic host, static host, and both target-builder translation units. The Windows reloadable module link now includes `mongoose.c`, which provides the shared JSON/string helpers used by module policy; the direct MinGW DLL link succeeds. Full host link/build, storage behavior, supervisor exit/interrupt behavior, and live reload/failure recovery remain unverified.
- The implementation is incomplete: do not use `-hr` for normal relay operation until the module+host link, storage behavior, and supervisor have passed full tests.

## Acceptance criteria

- Ordinary `nob`/`nob win`/`nob linux` remains a monolithic build with current runtime options and no loader dependency.
- Hot mode builds separate host and module; host is not linked to NIP implementation symbols.
- Existing WebSocket protocol/NIP behavior, SQLite persistence, delegation queries and existing database contents remain compatible.
- Editing a module source reloads it without terminating the process, losing live sockets, dropping host subscriptions, or closing/reopening SQLite.
- NIP-42 challenge/auth state follows the documented migration policy; module-only statics are never implicitly assumed to survive.
- Compile failure, missing symbol, ABI mismatch, or load failure leaves the currently active generation usable.
- No Mongoose timer/callback/storage object refers to a module after unload. Ctrl-C and host exit cleanly stop Nob and the relay.
- C tests and existing WebSocket/NIP smoke tests pass in monolithic mode; relevant tests pass in hot mode. New tests cover generic storage predicates, NIP-40 expiry/GC edge cases, delegation index/backfill, module registry generations, and reload success/failure.
- Linux and Windows behavior is verified against the actual configured toolchains; unsupported compiler/platform combinations are reported rather than guessed.

## Risks and decisions to verify during implementation

- Constructor execution, symbol export, function-pointer conversion and CRT behavior differ across Windows toolchains; verify MinGW (and MSVC only if supported) with real builds.
- Loading both old and candidate images simultaneously requires isolated module statics and plugin registry state. Confirm constructor registry is per image and no host symbols accidentally bind to the wrong generation.
- NIP-42 records reference opaque connections; migration must map by stable host-owned connection identity and discard closed connections safely.
- Generic tag indexing must preserve current delegation behavior and migration guarantees without making SQLite schema/API NIP-aware.
- Full event snapshots can be large. Generic scans must be bounded and avoid retaining module callbacks or accumulating unbounded event arrays.
- Current build scripts use GCC/MinGW style flags despite some compiler abstractions in `nob.h`; do not claim MSVC support without a successful end-to-end DLL build.
- This implementation is for development only. Hot-reload builds should not be used for distribution; ordinary builds remain the release path.
