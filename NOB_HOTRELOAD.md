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

- `nob.c` is the first-stage dispatcher. It selects `src_build/nob_win.c` or `src_build/nob_linux.c`, builds that script, then runs it. Shared build/watch logic lives in `src_build/nob_common.h`; the platform files keep only OS flags, libs, and artifact names.
- `src_build/nob_win.c` and `src_build/nob_linux.c` are retained as distinct platform build entry points. Their ordinary mode builds the existing monolithic relay; hot mode builds a permanent host and reloadable NIP module separately.
- `src/main.c` owns CLI/environment parsing, crypto and storage initialization, signal setup, and process cleanup.
- `src/transport/server.c` owns permanent Mongoose transport/event-loop responsibilities. NIP policy is dispatched through the capability registry (`nip_composition_*`); no transport file references individual NIPs.
- `src/nips/nip_capability.{h,c}` owns the per-image capability registry populated by constructors (one `nipXX.c` per NIP). NIP code sends via host-provided shims and never calls Mongoose transport directly.
- `src/storage.c` owns SQLite and generic selectors/index operations. NIP modules provide synchronous criteria; legacy delegation rows are migrated into a generic tag/value index.
- `src/crypto.c` owns a static secp256k1 verify context, validates event IDs/signatures, and calls `nip26_check_delegation()` (declared in `nip_capability.h`, implemented in `src/nips/nip26.c`) during `check_event()`.
- NIP-42 challenge/auth state lives in host-owned `connection_session_t` keyed by opaque connection IDs; the versioned `nip42_state_t` blob is a redundant safety net for reload migration.
- `src/model/event_util.{h,c}` is the shared event/tag inspection code used by core and NIP policy alike.
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

- `src/nips/nip_capability.{h,c}` registry and per-NIP constructor registration (one `nipXX.c` per NIP, `nip_template.c` excluded);
- relay protocol decisions dispatched through capability composition;
- NIP policy state that is re-derived in lifecycle `init` or kept in host-owned sessions (never in module statics).

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

## Current implementation status (reviewed 2026-09-25)

- `nhr.h` is the ABI source of truth. Candidate preflight is split from activation. Activation follows PRE_RELOAD → UNLOAD → fresh LOAD/ABI validation → POST_RELOAD → RUN, with fallback to a copy of the last loaded image. The normal reload path is live-tested on Linux; rollback and invalid-candidate recovery are not failure-injection tested.
- Both Linux and Windows ordinary/hot startup paths build with the current GCC/MinGW toolchain. Linux live reload was tested by rebuilding/publishing a module while a WebSocket subscription remained connected; the same socket completed a second REQ/EOSE. `tests/hotreload_live_smoke.py` contains the client-side continuity test (run against port 7456 while `nob_configed -module-only` publishes during its wait window).
- `tests/test_hotreload_integration.py` is the reproducible Linux integration harness: it starts the already-built hot host on a free port, leaves one WebSocket open, performs two `-module-only` builds, and verifies a new loaded-generation identity plus REQ/EOSE after each publication. It requires the Linux-target artifacts and Python `websockets` package.
- The host compares module metadata and a bounded-memory content hash, and retries a rejected pending artifact. The builders stage output as `.next` and use same-directory atomic rename. A failed compile does not replace the published image; a failed rename leaves the `.next` artifact for the supervisor retry. No injected compile, rename, ABI, or activation failure test has yet exercised these guarantees.
- The supervisors track top-level module dependencies and all `src/nips/*.c`/`.h` build inputs except `nip_template.c`, retry failed builds at a throttled interval, and install SIGINT/SIGTERM stop handlers before initial compilation. Linux runtime Ctrl-C has been tested: Mongoose shut down, the supervisor terminated/reaped the relay child, and the listener was released. Windows runtime console-signal cleanup remains unverified; a forced process stop is not equivalent and left a child that was manually cleaned up.
- Unique generation files are deleted on failed open and after unload. Repeated reload cleanup and Windows DLL replacement while another generation is loaded need runtime verification.
- Storage work currently has generic bounded predicate selection and NIP-specific policies; it is not a substitute for the larger architecture plan's requirements for a `relay_t`, protocol boundary, subscription manager, typed storage results, or removal of Mongoose-facing types from NIP code. Those architecture phases are not complete.
- Linux JSON utility, storage utility, crypto helper, and SHA-256 tests passed in the recorded run. Some existing test entries are informational stubs. Full protocol/NIP regression coverage and the architecture acceptance matrix remain incomplete.

Hot reload is a development feature and is not yet fully acceptance-tested for failure recovery or Windows runtime behavior. Ordinary monolithic builds remain the release path.

## Cohesion addendum (2026-09-27): capability-backed hot reload

This section binds NHR to PLAN.md's capability architecture (see also
SPEC_UNIFIED.md and the PLAN.md cohesion addendum). The module is not a bag
of flat hooks; it is a **capability provider** for the host relay core.

- **Exports stay at six** (`abi_version, init, shutdown, pre_reload,
  post_reload, register_capabilities`). New NIP powers never widen the ABI;
  they add `nip_capability_t` types consumed through `register_capabilities`.
- **Host owns the registry.** `nip_registry_register()` deep-copies each
  descriptor; `nip_registry_clear()` drops a whole generation. Startup
  (`relay_init_hot_reload`) and every activation/rollback
  (`nhr_check_candidate_timer` in `src/relay/relay.c`) perform
  clear + `active.register_capabilities()`. Add/change/remove of a NIP source
  file therefore swaps behavior without process restart.
- **State rule.** Sockets, Mongoose manager, SQLite, subscriptions, sessions,
  and config never cross the unload boundary by value — they are host-owned.
  Only the versioned `Nhr_State` blob migrates (currently NIP-42 auth);
  `nhr_module_shutdown` detaches it instead of freeing (fixed 2026-09-27).
  Empty state is valid.
- **Dispatch rule.** Host parses one `protocol_message_t` per WS frame and
  offers it to `NIP_CAP_MESSAGE_INTERCEPT` before default dispatch; a `true`
  return consumes the message. Maintenance runs via
  `nip_composition_run_maintenance` (all handlers). No timer, subscription,
  or connection field retains module code after unload; the swap is
  synchronous on the event-loop thread.
- **Developer cycle.** `nob [win|linux] -hr -- [relay args]` builds host +
  module, watches `src/nips/*.c` (minus template) plus module inputs,
  debounces saves, rebuilds module-only, publishes atomically, and reloads at
  the event-loop boundary. Failed build/load keeps the active generation;
  failed activation falls back and re-registers the fallback generation's
  capabilities. Each NIP is one `nipXX.c` file: drop it in, edit it, or
  delete it — the watcher notices membership changes and the reload swaps
  behavior with connections and state intact.

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



### HOT RELOAD NOB SPECIFICATION

# NOB Hot Reload

Status: Design Specification  
Feature: Hot Reload  
Subsystem: NOB Build System / Runtime  
Language: C / C99-compatible  
Terminology: Module, Host, Module Interface

## 1. Purpose

NOB Hot Reload provides a development-time mechanism for rebuilding and replacing application implementation code while an application's host process remains running.

The feature separates an application into two independently compiled units:

1. A persistent Host executable.
2. A replaceable Module dynamic library.

The Host owns the lifetime of the process and resources that must survive code replacement.

The Module contains application implementation code and may be unloaded and loaded repeatedly during development.

The build system is responsible for producing the two artifacts.

The runtime is responsible for loading, unloading, and resolving the Module.

Hot Reload does not require a file watcher. Rebuilding and reloading are independent operations.

The canonical development cycle is:

    edit source
        ↓
    ./nob
        ↓
    rebuild Module
        ↓
    application remains running
        ↓
    request reload
        ↓
    Module is unloaded
        ↓
    new Module is loaded
        ↓
    Module Interface is resolved
        ↓
    application continues


## 2. Design Goals

NOB Hot Reload shall:

- preserve the Host process across reloads;
- preserve Host-owned resources;
- allow the majority of application logic to be dynamically replaceable;
- use a small, explicit C ABI;
- support POSIX and Windows dynamic-library mechanisms;
- integrate naturally with NOB's C-based build model;
- support builds with and without hot reload;
- avoid requiring a separate runtime framework;
- allow application state to survive Module replacement;
- make the boundary between persistent runtime code and replaceable implementation explicit.

NOB Hot Reload shall not require:

- a file-watching daemon;
- an external build system;
- an IDE;
- a scripting runtime;
- C++;
- serialization for every reload;
- process restart.


## 3. Terminology

### Host

The executable process that owns the application lifetime.

The Host contains:

- `main()`;
- the main event loop;
- operating-system integration;
- resources that must survive reload;
- the dynamic-library loader;
- the Module Interface function pointers.

### Module

The dynamically loaded portion of the application.

The Module contains the implementation that developers want to replace without restarting the Host.

The Module is not a plugin marketplace mechanism and does not imply third-party extensibility.

A Module is simply the replaceable implementation unit of the application.

### Module Interface

The stable C ABI connecting the Host and Module.

The interface consists of exported Module functions and their signatures.

### Module State

Application state that survives replacement of the Module's code.

Module state may reside in memory owned by the Host or in process memory deliberately retained across Module unloading.

### Module Generation

A particular compiled instance of a Module.

A project may use a single Module filename or generation-specific filenames.

Generation-specific filenames are recommended for platforms where loaded libraries cannot safely be overwritten.


## 4. Architectural Model

The Host and Module shall be separate compilation units when Hot Reload is enabled.

    +-------------------------------+
    |             HOST              |
    |                               |
    | main()                        |
    | event loop                    |
    | platform resources            |
    | persistent runtime resources  |
    | Module loader                 |
    | Module function pointers      |
    +---------------+---------------+
                    |
                    | Module Interface
                    |
    +---------------v---------------+
    |            MODULE             |
    |                               |
    | application implementation    |
    | rendering                     |
    | UI                            |
    | algorithms                    |
    | application behavior          |
    +-------------------------------+

The Host must not directly link against the replaceable implementation.

The Host communicates with the Module exclusively through the Module Interface.

When Hot Reload is disabled, the same source architecture may be compiled into one executable.

This allows Hot Reload to be a build configuration rather than an application-specific programming model.


## 5. Ownership Model

The Host owns resources whose lifetime must exceed the lifetime of one Module generation.

Examples include:

- process state;
- window;
- graphics context;
- OS handles;
- long-lived sockets;
- database connections;
- platform event queues;
- external device handles;
- other resources that cannot safely survive dynamic-library unloading.

The Module owns implementation details and temporary state.

The fundamental ownership rule is:

    If a resource must survive Module replacement,
    its ownership must not depend on the lifetime of Module code.

The Module must release or detach resources that contain callbacks, function pointers, or other references into Module code before the Module is unloaded.


## 6. Module Interface

The Module Interface shall be defined in one authoritative header.

The interface should use an X-macro declaration list so that declarations, typedefs, exports, and Host function pointers can be generated from the same definition.

Example:

    #define NOB_MODULE_INTERFACE \
        NOB_MODULE_FUNC(module_init,        void, void) \
        NOB_MODULE_FUNC(module_pre_reload,  void*, void) \
        NOB_MODULE_FUNC(module_post_reload, void, void*) \
        NOB_MODULE_FUNC(module_update,      void, void)

The actual function names are project-defined.

The NOB framework shall not impose application-specific names such as `plug_init`.

The interface list is the ABI definition.

A generic project may therefore define:

    #define NOB_MODULE_INTERFACE \
        NOB_MODULE_FUNC(app_init,        void, void) \
        NOB_MODULE_FUNC(app_pre_reload,  void*, void) \
        NOB_MODULE_FUNC(app_post_reload, void, void*) \
        NOB_MODULE_FUNC(app_update,      void, void)

or any equivalent interface appropriate to the application.


## 7. Interface Generation

The same interface list shall be reusable to generate:

1. Function typedefs.
2. Host-side function pointers.
3. Module-side declarations.
4. Platform-specific exports where necessary.

Example typedef generation:

    #define NOB_MODULE_FUNC(name, ret, ...) \
        typedef ret name##_fn(__VA_ARGS__);

    NOB_MODULE_INTERFACE

    #undef NOB_MODULE_FUNC

Host generation:

    #define NOB_MODULE_FUNC(name, ret, ...) \
        name##_fn *name;

    NOB_MODULE_INTERFACE

    #undef NOB_MODULE_FUNC

Module declarations:

    #define NOB_MODULE_FUNC(name, ret, ...) \
        ret name(__VA_ARGS__);

    NOB_MODULE_INTERFACE

    #undef NOB_MODULE_FUNC

This ensures that the Host and Module derive their ABI from the same source definition.


## 8. Module Loading

The Host shall provide a platform-independent Module loading abstraction.

Conceptually:

    Module_Handle *module_load(const char *path);

    void *module_symbol(
        Module_Handle *module,
        const char *name
    );

    void module_unload(Module_Handle *module);

POSIX implementations shall use the platform dynamic-loader facilities such as:

    dlopen()
    dlsym()
    dlclose()

Windows implementations shall use:

    LoadLibrary()
    GetProcAddress()
    FreeLibrary()

The platform-specific implementation shall not leak into application code.


## 9. Module Initialization

At startup:

    1. Host initializes resources that belong to the Host.
    2. Host loads the Module.
    3. Host resolves the Module Interface.
    4. Host initializes the Module.
    5. Host enters the normal application loop.

The Module must not assume that it owns the Host process.

The Host remains alive for the entire development session.


## 10. Reload Lifecycle

A reload consists of four logical phases:

    PREPARE
    UNLOAD
    LOAD
    RESTORE

The logical sequence is:

    module_pre_reload()
            ↓
    Module state/resources prepared
            ↓
    unload current Module
            ↓
    load new Module
            ↓
    resolve Module Interface
            ↓
    module_post_reload(state)
            ↓
    resume execution


## 11. Pre-Reload Contract

Before unloading the Module, the Host shall invoke the Module's pre-reload operation if one exists.

The pre-reload operation is responsible for making the Module safe to unload.

Typical operations include:

- unregistering callbacks;
- detaching audio processors;
- stopping Module-owned worker threads;
- releasing Module-owned dynamic resources;
- unloading assets that must be recreated;
- preparing persistent state;
- returning a pointer or state object required by the new Module generation.

The Module must not leave active callbacks executing Module code when the Host unloads the Module.


## 12. State Preservation

NOB Hot Reload does not require state serialization.

The simplest supported mechanism is persistent process memory.

Example:

    typedef struct App_State {
        int counter;
        float camera_x;
        float camera_y;
    } App_State;

    static App_State *state;

The initial Module allocates the state:

    state = malloc(sizeof(*state));

The pre-reload operation releases/detaches resources but does not free the state:

    void *module_pre_reload(void)
    {
        release_module_resources();
        return state;
    }

After the Module has been replaced:

    void module_post_reload(void *previous_state)
    {
        state = previous_state;
        restore_module_resources();
    }

The critical invariant is:

    The state memory must remain valid after the old Module
    has been unloaded.

The state must therefore not point into the old Module's code or static storage.


## 13. State ABI Requirements

Persistent state creates an ABI constraint.

A retained memory object is interpreted by both the old and new Module generations.

Therefore, the application must not blindly change the memory layout of persistent state while relying on raw pointer preservation.

Projects requiring structural evolution should use one of the following approaches:

1. Stable state structures.
2. Explicit state versioning.
3. Host-owned state.
4. Serialization/deserialization.
5. Migration functions.

NOB Hot Reload shall not require one particular strategy.

The framework's responsibility is to provide the lifetime boundary.

The application's responsibility is to define the state ABI.


## 14. Module-Owned State

A Module may retain state in process memory across reload if the project deliberately uses this model.

However:

    Module code
        may disappear

    Module static storage
        may disappear

    Module heap allocation
        may remain

Therefore a pointer returned from pre-reload must refer to memory whose lifetime extends beyond the dynamic-library unload.

The generic framework shall document this distinction explicitly.


## 15. Module Resources

Resources containing references to Module code must be released or detached before unloading.

Examples:

    callback registration
    function-pointer callbacks
    background threads
    asynchronous jobs
    JIT-generated code referencing Module functions
    OS callbacks
    event subscriptions

A resource may remain alive across reload only if it does not contain references into the old Module or can safely have those references rebound.

This allows an application to keep expensive Host resources alive while reconstructing Module-level bindings.


## 16. Symbol Resolution

After loading a Module, the Host shall resolve every required symbol defined by the Module Interface.

For each interface entry:

    symbol = module_symbol(module, "symbol_name");

If a required symbol cannot be resolved, the Module is invalid.

The Host must report:

- Module path;
- missing symbol;
- platform loader error where available.

A partially resolved Module must not become the active Module.


## 17. Build Integration

When Hot Reload is enabled, NOB shall create two build targets.

Example:

    build/app
    build/module.so

or:

    build/app.exe
    build/module.dll

The Host target contains:

    main.c
    hotreload.c
    other persistent Host sources

The Module target contains:

    application implementation sources
    Module-specific dependencies

The Module is built as a dynamic library.


## 18. Platform Build Requirements

POSIX Module builds generally require position-independent code and shared-library linking.

Typical requirements include:

    -fPIC
    -shared

Windows builds must use the platform's dynamic-library compilation/linking mechanism.

For MSVC this generally corresponds to:

    /LD

The NOB feature shall provide platform-specific construction of these commands rather than requiring every project to duplicate them.


## 19. Dependency Linking

Dependencies required by both Host and Module must be handled deliberately.

When a dependency is statically linked into both sides, two separate copies may exist.

When a dependency maintains process-global state, this may be undesirable.

Therefore NOB Hot Reload should permit dependencies to become shared libraries when necessary.

Conceptually:

    Host
      │
      ├──── Runtime Library
      │
      └──── Module
               │
               └──── Runtime Library

The precise dependency strategy remains project-specific.

The Hot Reload build feature must provide the ability to link the Module against shared dependencies.


## 20. Runtime Search Paths

Development builds must ensure that the Host can locate the Module and any dynamic dependencies.

NOB may configure platform-specific runtime search paths such as:

    ./build
    .

or their platform equivalents.

The search path configuration is a development concern.

Production packaging should not automatically include development-only Hot Reload infrastructure.


## 21. Generation Strategy

A project may use a stable Module filename:

    build/app.so

However, generation-specific filenames are recommended where the operating system makes replacement of loaded libraries difficult.

Example:

    build/modules/
        app.001.so
        app.002.so
        app.003.so

The Host can then load the newest successfully built generation.

Generation management is a NOB build concern.

The runtime loader only needs a valid Module path.


## 22. Build and Runtime Separation

NOB Hot Reload consists of two independent systems.

### Build side

    source
      ↓
    NOB
      ↓
    Module dynamic library

### Runtime side

    Host
      ↓
    load Module
      ↓
    execute Module
      ↓
    unload Module
      ↓
    load replacement

NOB does not need to know when the user wants to reload.

The Host does not need to know how the Module was built.

This separation is fundamental to the design.


## 23. Reload Trigger

The reload trigger is intentionally outside the core NOB Hot Reload mechanism.

Possible triggers include:

    keyboard shortcut
    menu action
    debugger command
    IPC
    editor integration
    filesystem watcher
    explicit API call

The core runtime operation is simply:

    nhr_reload()

A filesystem watcher is therefore an optional development convenience, not a requirement of Hot Reload.


## 24. Automatic Reload

A future NOB integration may provide:

    ./nob watch

or equivalent functionality.

The watcher would:

    detect source changes
        ↓
    invoke NOB build
        ↓
    produce new Module
        ↓
    notify running Host
        ↓
    Host performs reload

The watcher must remain separate from the Module loading mechanism.


## 25. Non-Hot-Reload Build

Hot Reload shall be optional.

When disabled, NOB should be able to compile the same project as a conventional executable.

Conceptually:

    Hot Reload ON:

        Host sources → executable
        Module sources → dynamic library


    Hot Reload OFF:

        Host sources
        Module sources
        dependencies
              ↓
        executable

The Module Interface may still exist in the source tree.

The difference is how its implementation is linked.


## 26. Interface Abstraction in Non-Hot-Reload Mode

The Host-side interface declarations should be generated differently depending on the build mode.

Hot Reload:

    module_function → function pointer

Normal build:

    module_function → normal function

For example:

    #ifdef NOB_HOT_RELOAD

        #define NOB_MODULE_FUNC(name, ret, ...) \
            extern name##_fn *name;

    #else

        #define NOB_MODULE_FUNC(name, ret, ...) \
            ret name(__VA_ARGS__);

    #endif

This permits the application source code to call:

    module_update();

without knowing whether the implementation is statically linked or dynamically loaded.


## 27. Error Handling

Module loading failures must be explicit.

Possible failures include:

- library not found;
- dependency not found;
- ABI mismatch;
- missing symbol;
- invalid Module;
- initialization failure;
- state restoration failure.

At minimum the runtime shall report the failure and avoid invoking unresolved function pointers.

Where possible, the Host should retain the previous Module until the replacement has been validated.

However, platform-specific library replacement constraints may require unloading the previous generation before loading the new generation.

The framework should therefore support generation-specific Module files so that future implementations can perform safer replacement.


## 28. Threading

The Host must never unload a Module while execution is occurring inside that Module.

Before unload:

    all Module calls must have returned

and Module-owned threads must be stopped or detached from Module code.

A Module that creates worker threads must provide a pre-reload mechanism capable of bringing those threads to a safe state.

The Host must not attempt to infer Module thread ownership.


## 29. Allocation Boundary

Memory crossing the Host/Module boundary should use a defined ownership convention.

Projects should avoid:

    Module malloc()
        ↓
    Host free()

or the inverse when the platform/runtime may use incompatible allocators.

The generic interface may expose Host allocation functions:

    void *host_alloc(size_t);
    void host_free(void *);

Opaque handles are preferred for resources whose ownership remains with the Host.


## 30. ABI Stability

The Module Interface is an ABI and must therefore be treated as such.

The interface should expose:

- C-compatible types;
- fixed-width integers where appropriate;
- opaque pointers;
- fixed-layout structures;
- function pointers;
- buffers and sizes.

The interface should not expose:

- C++ classes;
- C++ standard-library objects;
- compiler-specific object layouts;
- exceptions;
- ownership assumptions that are not documented.

An optional ABI version function may be provided:

    uint32_t module_abi_version(void);

The Host can reject incompatible Module generations before activation.


## 31. Recommended Generic Interface

A minimal generic Module Interface is:

    #define NOB_MODULE_INTERFACE \
        NOB_MODULE_FUNC(module_init,        int,   Nhr_Host *) \
        NOB_MODULE_FUNC(module_pre_reload,  void *, void) \
        NOB_MODULE_FUNC(module_post_reload, int,   void *) \
        NOB_MODULE_FUNC(module_update,      void,  void) \
        NOB_MODULE_FUNC(module_shutdown,    void,  void)

Additional functions are project-defined.

For example:

    module_render()
    module_event()
    module_resize()
    module_tick()
    module_load()
    module_save()

NOB itself should not prescribe application semantics beyond the reload lifecycle.


## 32. Recommended Runtime API

The generic runtime implementation should expose approximately:

    Nhr_Module *nhr_load(const char *path);

    bool nhr_resolve(
        Nhr_Module *module
    );

    bool nhr_reload(
        Nhr_Module *module,
        const char *path
    );

    void nhr_unload(
        Nhr_Module *module
    );

    void *nhr_symbol(
        Nhr_Module *module,
        const char *name
    );

    const char *nhr_error(void);


The exact API is implementation-specific.

The important abstraction is that application code does not directly call:

    dlopen()
    dlsym()
    dlclose()

or:

    LoadLibrary()
    GetProcAddress()
    FreeLibrary()


## 33. Recommended NOB Build API

The build system should expose a declarative-enough C interface for describing the Host/Module split.

Conceptually:

    Nob_Hot_Reload target = {
        .name = "app",

        .host_sources = {
            "src/main.c",
            "src/hotreload.c",
        },

        .module_sources = {
            "src/app.c",
            "src/render.c",
            "src/ui.c",
        },

        .interface = "src/module.h",
    };

    nob_hot_reload_build(&target);

The implementation should handle:

- object compilation;
- dynamic-library compilation;
- platform-specific flags;
- Module output paths;
- Host output paths;
- dependency tracking;
- runtime search paths;
- configuration;
- optional generation management.


## 34. NOB Build Graph

The expected dependency graph is:

                         Module Interface
                         /              \
                        /                \
                       ↓                  ↓
                  Host sources      Module sources
                       │                  │
                       ↓                  ↓
                  Host objects       Module objects
                       │                  │
                       ↓                  ↓
                   executable        shared library
                       │                  │
                       └───────┬──────────┘
                               │
                            runtime


Changing Module source should not require rebuilding the Host.

Changing Host source should not require rebuilding the Module.

Changing the shared Module Interface invalidates both sides.


## 35. Configuration

Hot Reload should be exposed as a generic NOB feature.

For example:

    #define NOB_HOT_RELOAD

or through a NOB configuration command:

    ./nob config hotreload

The exact configuration syntax is project-specific.

The build system should expose the feature as:

    hotreload

rather than requiring application-specific names.

The generated configuration should make the feature state visible to both the build system and source code.


## 36. Development vs Distribution

Hot Reload is a development feature.

A production build should normally omit:

- the dynamic Module loader;
- development Module libraries;
- development runtime paths;
- reload controls;
- temporary Module generations.

Production builds may instead statically link the Module implementation into the executable.

The same source architecture should therefore support:

    development:
        Host + Module


    production:
        Host + Module implementation
        → one executable


## 37. Minimal Application Loop

A generic application using NOB Hot Reload should ultimately look approximately like:

    int main(void)
    {
        Host host = host_create();

        Nhr_Module module = {
            .path = "build/modules/app.so",
        };

        if (!nhr_load(&module))
            return 1;

        module.init();

        while (application_running()) {

            if (reload_requested()) {
                void *state =
                    module.pre_reload();

                nhr_reload_module(&module);

                module.post_reload(state);
            }

            module.update();
        }

        module.shutdown();
        nhr_unload(&module);

        host_destroy();

        return 0;
    }

The actual application remains responsible for deciding what constitutes a safe reload.


## 38. Core Invariants

A conforming implementation shall preserve these invariants:

1. The Host process survives Module replacement.

2. The Module is independently compiled when Hot Reload is enabled.

3. Host-to-Module communication occurs through a defined ABI.

4. Every required Module symbol is resolved before use.

5. Module code is not executed after its library has been unloaded.

6. Module-owned callbacks are detached before unload.

7. Persistent state is stored outside ephemeral Module code/static storage.

8. The same project can be built without Hot Reload.

9. NOB performs the build-time separation.

10. The runtime loader performs the run-time replacement.

11. File watching is optional.

12. Application-specific terminology does not belong in the generic NOB Hot Reload implementation.


## 39. Reference Architecture

The complete feature can therefore be reduced to:

                    ┌─────────────────────┐
                    │        NOB          │
                    │                     │
                    │ configure           │
                    │ dependency tracking │
                    │ compile             │
                    │ link                │
                    └─────────┬───────────┘
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
          ┌─────────────┐           ┌─────────────┐
          │    HOST     │           │   MODULE    │
          │             │           │             │
          │ main        │           │ application │
          │ event loop  │           │ logic       │
          │ resources   │           │             │
          │ loader      │           │             │
          └──────┬──────┘           └──────┬──────┘
                 │                         │
                 └───────── ABI ───────────┘
                              │
                              ▼
                       reload lifecycle

                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
             PRE-RELOAD                POST-RELOAD
                 │                         │
           detach/release              restore
           preserve state              state/resources
                 │                         │
                 └────── unload/load ──────┘


## 40. Definition of Done

NOB Hot Reload is complete when a new NOB project can:

1. Declare a Host source set.
2. Declare a Module source set.
3. Declare a Module Interface.
4. Enable `hotreload`.
5. Build both artifacts with `./nob`.
6. Start the Host.
7. Load the Module.
8. Resolve its interface automatically.
9. Continue running while the developer rebuilds the Module.
10. Request a reload without restarting the Host.
11. Execute the Module's pre-reload lifecycle.
12. Unload the old Module.
13. Load the new Module.
14. Resolve the new interface.
15. Restore persistent state.
16. Resume execution.
17. Build the exact same project without Hot Reload.
18. Support the appropriate dynamic-library mechanism for each target platform.

The resulting developer experience should be:

    $ ./nob
    $ ./build/app

    # edit module source

    $ ./nob

    # application is still running

    [reload]

    # new Module is now executing

    No process restart.
    No Host rebuild.
    No loss of Host-owned resources.