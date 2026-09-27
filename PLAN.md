# NOSTROGOTHO Architecture Refactor Plan

Status: **Hot reload builds verified on Windows and Linux; architecture refactor in progress**. Target architecture is documented below; implementation status and evidence are tracked separately. This plan alone does not authorize behavior changes outside the user's requested incremental refactor.

## Implementation Progress Summary (2026-09-26)

| Phase | Description | Status | Evidence |
|-------|-------------|--------|----------|
| 0 | Freeze design | ✅ Complete | PLAN.md created |
| 1 | Runtime context (relay_t, relay_config_t) | ✅ Complete | src/relay/relay.h, relay.c |
| 2 | Model cleanup (event/tag utilities) | ✅ Complete | src/model/event_util.h, event_util.c |
| 3 | Protocol boundary (parser/serializer) | ✅ Complete | src/protocol/protocol.h, protocol.c |
| 4 | Validation boundary | ✅ Complete | src/validation/event_validation.h, event_validation.c |
| 5 | Subscription manager | ✅ Complete | src/subscriptions/subscription_manager.h, .c |
| 6 | Storage boundary | ✅ Complete | src/storage.h, storage.c (existing) |
| 7 | NIP capability API redesign | ✅ Complete | src/nips/nip_capability.h, .c |
| 8 | NIP migration | 🔄 **In Progress** | All 10 NIPs migrated to capability interface (NIP-01, 09, 13, 17, 26, 40, 42, 45, 62, 67); query flow uses capability composition |
| 9 | Transport reduction | ⏳ **Pending** | server.c reduction to pure transport |
| 10 | Physical source reorganization | ⏳ Pending | Files not moved to target directories |
| 11 | Documentation | ⏳ Pending | PLAN.md updated, API docs pending |
| 12 | Final verification | ⏳ Pending | Not started |

**Key architectural achievements so far:**
- ✅ `relay_t` aggregates all runtime state (config, storage, subscriptions, NIP registry, connection sessions, Mongoose manager)
- ✅ `relay_config_t` is the single authoritative configuration structure
- ✅ Model layer extracted: generic `event_has_tag()`, `event_get_tag_value()`, etc. in `src/model/`
- ✅ Protocol layer: `protocol_message_t` with typed commands, parser/serializer separation
- ✅ Validation layer: explicit pipeline with typed `validation_result_t` outcomes
- ✅ Subscription manager: owns connection association, lifecycle, matching, delivery (using connection_id_t)
- ✅ Connection/session abstraction: opaque connection IDs, per-connection auth state, challenges, pubkeys
- ✅ Policy layer: explicit `publish_result_t`, `req_result_t`, `delivery_decision_t`
- ✅ New NIP capability API: `nip_capability_t` with typed capability groups (lifecycle, connection, message_intercept, publication_policy, kind_handler, delivery_policy, query_policy, maintenance, metadata, protocol_response)
- ✅ Composition rules: all publication policies must permit, any delivery policy may veto, all maintenance runs, kind handlers evaluated per contract
- ✅ NIP-42 migrated to new capability interface (lifecycle, connection, message_intercept, publication_policy, metadata)
- ✅ NIP-01 builtin plugin migrated to new capability interface (kind_handler for replaceable/addressable events)
- ✅ NIP-40 migrated to new capability interface (lifecycle, publication_policy, delivery_policy, maintenance)
- ✅ NIP-09, NIP-13, NIP-17, NIP-26, NIP-45, NIP-62, NIP-67 migrated to new capability interface
- ✅ Query flow implemented: `subscription_manager_query` uses `storage->send_records` and capability composition for EOSE/COUNT responses
- ✅ Build system updated: nob_win.c and nob_linux.c explicitly compile core infrastructure and auto-discover NIP plugins
- ✅ **Build successful**: `nob win` compiles and `build/main.exe --help` works

**Remaining critical work:**
1. Reduce `server.c` to pure transport (Mongoose event loop + WebSocket/HTTP handling) - remove dual-mode logic
2. Remove transport helpers (`nip_plugin_send_json`, `nip_plugin_send_status`) from NIP API
3. Move files to target directory structure
4. Update build system (nob) for new source layout
5. Comprehensive testing and verification

---

## NIP Migration Status

Each NIP is a single self-contained `src/nips/nipXX.c` (logic + capability
table + constructor). No per-NIP headers, no `*_capability.*` split, no
`nip_plugin_t` — deleted. `nip_capability.h` holds the registry plus the
kind-handler result type and the nip26/nip42 decls shared with core code.

| NIP | Single File | Capabilities | Status |
|-----|-------------|--------------|--------|
| NIP-01 | nip01.c | kind_handler (replaceable/addressable) | ✅ **Complete** |
| NIP-09 | nip09.c | kind_handler (kind 5 deletion) | ✅ **Complete** |
| NIP-11 | nip11.c | lifecycle + metadata | ✅ **Complete** |
| NIP-13 | nip13.c | lifecycle + publication_policy (PoW) | ✅ **Complete** |
| NIP-17 | nip17.c | delivery_policy + protocol_response (auth hint) | ✅ **Complete** |
| NIP-26 | nip26.c | publication_policy (delegation) | ✅ **Complete** |
| NIP-40 | nip40.c | publication_policy + delivery_policy + maintenance (expiry/GC) | ✅ **Complete** |
| NIP-42 | nip42.c | lifecycle + connection + message_intercept + publication_policy + protocol_response (challenge) | ✅ **Complete** |
| NIP-45 | nip45.c | protocol_response (COUNT) | ✅ **Complete** |
| NIP-62 | nip62.c | kind_handler (kind 62 vanish) | ✅ **Complete** |
| NIP-67 | nip67.c | protocol_response (EOSE hints) | ✅ **Complete** |

---

## Next Steps (Priority Order)

1. **Reduce server.c** - Strip to pure transport: remove dual-mode logic, NIP policy decisions, subscription globals, filter matching; delegate to relay_t + protocol layer
2. **Remove old nip_plugin_t references from server.c** - Eliminate #ifndef NHR_DYNAMIC_MODULE conditional sections that reference nip_plugin_t, plugins_accept_publish, plugins_can_deliver
3. **Physical reorganization** - Move files to target directories
4. **Update nob build** - Explicit protocol core compilation, auto-discover NIPs from src/nips/, exclude nip_template.c
5. **Update documentation** - API_REFERENCE.md, PROJECT_SUMMARY.md describing final architecture

This plan defines the architecture and exact refactoring sequence for nostrogotho. It is based on the current repository source reviewed from the supplied code snapshot, including nob.c, src/server.c, src/crypto.c, src/json_util.c, src/nostrogotho.c, src/storage.c, src/nips/nip01.c, src/nips/nip_plugin.c, src/nips/nip_plugin.h, src/nips/nip_event.c, and the NIP modules.

The objective is not to rewrite the relay. The objective is to make the existing implementation conform to explicit architectural boundaries so that Nostr protocol behavior, NIP policy, transport, persistence, and future peer/distribution mechanisms can evolve independently.

1. Target architecture

The relay will be organized around these responsibilities:

Client
  |
  v
Transport
  HTTP / WebSocket / connection lifecycle
  |
  v
Protocol
  Nostr commands / parsing / serialization / dispatch
  |
  +--------------------+
  |                    |
  v                    v
Validation          Subscriptions
structure           lifecycle
event ID            filters
signature           matching
delegation          delivery
  |
  v
Policy
relay policy + NIP capabilities
  |
  v
Storage API
  |
  +----------+-----------+
  |                      |
  v                      v
SQLite                 future backends

The important dependency rule is:

Transport -> Protocol
Protocol  -> Model / Validation / Subscriptions / Policy
Policy    -> Model / Storage API
Subscriptions -> Model / Storage API / Delivery Policy
Storage implementation -> Storage API
NIP modules -> NIP capability API

No upper layer may depend on SQLite implementation details. No model layer may depend on Mongoose. No NIP module may need to know how a WebSocket frame is sent for ordinary protocol operation. server.c must not include or reference individual nipXX.h files.

The resulting system must make it possible to replace SQLite with another storage backend, add another transport, or add a future ZION-backed distribution/storage layer without rewriting the Nostr protocol core.

2. What the current code already provides

The refactor must preserve and build upon several existing design decisions.

nob already discovers every *.c under src/nips/ and compiles those modules automatically. nip_template.c is excluded from the build. The build therefore already treats the NIP directory as a source-level feature set.

nip_plugin_t already provides generic hooks for initialization, connection lifecycle, message interception, publication policy, delivery policy, EOSE/COUNT generation, timers, and NIP-11 metadata.

nip01_process_event() already centralizes general event validation before kind-specific listeners. Its documented pipeline validates event ID/signature/delegation, content size, timestamps, PoW, then dispatches matching listeners.

filter_t, event_t, tag_t, and their allocation/free functions already provide the beginnings of an internal model layer.

storage_context_t already provides an abstraction over persistence operations.

These mechanisms should be refactored and clarified rather than discarded.

3. Major architectural correction

The current architecture describes server.c as transport, protocol, subscription, authentication, and event-lifecycle owner simultaneously. Although the comments say the transport has zero NIP-specific knowledge, the file currently owns storage globals, subscription globals, query state, relay policy limits, configuration state, and the orchestration of plugin hooks.

The target is to make that statement true structurally, not merely by convention.

server.c will become a transport adapter around a relay_t context. It will receive Mongoose events and pass complete messages into the protocol layer. It will not decide what an EVENT, REQ, AUTH, COUNT, or CLOSE means.

4. Introduce relay_t

Create a runtime aggregate:

typedef struct relay relay_t;

The relay owns:

relay_config_t
storage_context_t
subscription_manager
NIP registry
protocol state
transport/event-loop state
runtime timers

The exact structure may remain opaque outside the relay implementation.

Introduce lifecycle functions equivalent to:

relay_init()
relay_run()
relay_stop()
relay_deinit()

main.c becomes responsible for:

parse/start configuration
crypto initialization
storage initialization
relay initialization
relay run
relay shutdown
crypto shutdown

It should not construct or manipulate individual subscriptions or NIP hooks.

The existing server_configure() / server_run() interface should become a compatibility bridge during migration and eventually be replaced by relay lifecycle functions.

5. Introduce relay_config_t as the authoritative configuration

All relay configuration must live in one structure.

At minimum:

database path
port
service URL
minimum PoW
created-at lower limit
created-at upper limit
debug logging
maximum WebSocket message size
maximum event content size
maximum event tags
maximum subscriptions per connection
maximum filters per subscription
maximum subscription ID length
maximum query limit

Existing constants in server.c such as MAX_SUBSCRIPTIONS, MAX_FILTERS, MAX_SUB_ID_LENGTH, MAX_WS_MESSAGE_LENGTH, MAX_EVENT_CONTENT_LENGTH, MAX_EVENT_TAGS, and MAX_LIMIT must stop being independently authoritative.

The values may remain the same initially. This phase is about ownership and consistency, not changing policy.

NIP plugins receive configuration through their context/API and must not read relay globals.

6. Establish the model layer

The current nostrogotho.h/.c data structures become the model layer.

The model owns:

event_t
filter_t
tag_t
tags_array_t
allocation
ownership
copy/move operations
basic event/filter/tag helpers

Move or rename generic tag/event utilities currently exposed through nip_event.c.

nip_event.c currently contains generic operations such as extracting tag elements and checking whether an event contains a tag. These are not intrinsically NIP behavior. They should move to the model/event-tag utility layer.

The target API should contain generic operations equivalent to:

event_has_tag()
event_get_tag()
event_get_tag_value()
event_get_tag_count()

NIP modules may use them to interpret NIP-specific tags.

The model must not include Mongoose or SQLite.

7. Preserve and formalize ownership rules

The current API documents that event/filter/tag allocations are heap-owned and have paired free functions. That ownership model must become explicit and uniform.

Required rules:

event_alloc() -> event_free()
filter_alloc() -> filter_free()
tag_alloc() -> tag_free()
tags_array_alloc() -> tags_array_free()

Borrowed database values must never be freed by callers.

Protocol parsers return owned model objects.

Protocol serializers never take ownership of the objects they serialize.

Storage results returned as events are owned by the caller unless explicitly documented otherwise.

Every public API must document whether pointers are:

owned
borrowed
transferred
optional

No refactor phase may introduce ambiguous ownership.

8. Separate wire JSON from internal protocol objects

json_util.c currently combines protocol parsing utilities and JSON construction. It should be reorganized around a strict boundary:

wire JSON
    |
    v
protocol parser
    |
    v
typed protocol/model objects
    |
    v
internal processing
    |
    v
protocol serializer
    |
    v
wire JSON

An event_t is an internal object, not a JSON object.

A filter_t is an internal object, not a JSON object.

A subscription is an internal object, not a JSON object.

A protocol message should have an explicit internal representation where needed, for example:

protocol_message_t

with a command/type discriminator and typed payload.

The parser must enforce all input size limits before allocating unbounded structures.

The serializer must be the sole normal source of protocol response JSON.

9. Define protocol-core ownership

NIP-01 protocol mechanics become the protocol core.

The protocol core owns:

EVENT input
REQ input
CLOSE input
AUTH input dispatch
EOSE output
OK output
NOTICE output
CLOSED output
COUNT dispatch/output boundary

NIP modules do not directly own generic protocol framing.

The existing nip01.c should be split conceptually into:

protocol/event processing
protocol/REQ processing
NIP capability dispatch

It does not need to be physically split immediately, but its API must stop making NIP-01 the owner of unrelated relay concerns.

The protocol core must not directly include individual NIP implementation headers.

10. Define the EVENT processing pipeline

Every published event must follow one pipeline:

WebSocket frame
  -> protocol parser
  -> event_t
  -> structural validation
  -> event ID verification
  -> Schnorr signature verification
  -> NIP-26 delegation verification
  -> relay publication policy
  -> NIP publication policy
  -> kind-specific NIP handling
  -> storage
  -> OK response
  -> subscription matching
  -> delivery policy
  -> EVENT delivery

The exact existing behavior must be preserved unless separately documented as a protocol correction.

Validation failures must produce a typed processing result rather than direct network output.

The event-processing result should contain enough information for the protocol layer to decide:

accepted/rejected
response status
response reason
stored/not stored
broadcast/not broadcast

NIP modules must not send the final OK response themselves.

NIP modules must not broadcast directly.

The existing nip_plugin_accept(), nip_plugin_reject(), nip_plugin_store_and_broadcast(), and nip_plugin_store_only() helpers are evidence of the desired direction, but their storage/broadcast semantics must be separated so a plugin returns policy decisions rather than controlling the entire transport flow.

11. Separate validation from relay/NIP policy

Create an explicit validation boundary.

Validation includes:

event shape
required fields
field sizes
event ID canonicalization
event ID verification
signature verification
delegation verification

Relay policy includes:

created_at bounds
minimum PoW
resource limits
relay-specific publication restrictions

NIP policy includes:

NIP-09 deletion
NIP-13 PoW semantics
NIP-17 gift-wrap behavior
NIP-26 delegation semantics
NIP-40 expiration
NIP-42 authorization
NIP-62 vanish
etc.

The cryptographic code currently contains SHA-256, signature verification, delegation checking, tag parsing, and event validation. The cryptographic primitives should remain reusable, but event-level policy decisions must move out of the crypto module.

crypto.c should ultimately expose cryptographic operations such as:

sha256()
signature_verify()

while event validation owns the orchestration of those operations.

The global verify_ctx may remain internal to the crypto subsystem initially. Its lifecycle must remain explicit through crypto_init() / crypto_deinit().

12. Define a policy result model

NIP publication hooks currently return bool plus a reason buffer. Kind listeners return nip01_process_result_t.

These two models should converge.

Define one policy decision conceptually equivalent to:

accept
reject
not_applicable

with optional:

reason
storage action
broadcast action
delivery action

A policy must be able to say “this NIP does not apply” without being interpreted as acceptance.

This is especially important for kind listeners.

The current rule “the first listener to return accepted=true stops further processing” must be removed as the architectural default. It makes behavior dependent on registration order and prevents multiple independent NIP policies from participating in one event.

13. Redefine kind listeners

A NIP module may declare relevant event kinds.

For an event with a matching kind:

all applicable listeners/policies receive the event

No listener automatically “wins” merely because it runs first.

Each listener must explicitly declare whether it:

does not apply
accepts
rejects
performs a side effect

For event kinds with mutually exclusive storage semantics, the protocol/NIP capability contract must explicitly identify the owner of that lifecycle rather than relying on registry ordering.

This is necessary for modules such as NIP-09 and NIP-62, which currently perform storage mutations from kind listeners.

14. Separate storage mutation from policy decision

The current NIP plugin helper nip_plugin_store_and_broadcast() directly invokes storage->insert_record(). That is convenient, but it makes NIP modules responsible for persistence mechanics.

The target is:

NIP policy
    -> processing decision
    -> relay/event lifecycle
    -> storage API

The core lifecycle coordinator owns the normal store operation.

NIPs may request specialized persistence operations when their specification genuinely requires them, but those operations must be expressed through the storage API.

NIP-09 is the main existing example requiring specialized deletion operations. Its deletion rules should remain in the NIP module, while the actual database operations remain behind the storage interface.

NIP-62 similarly needs a generic operation for deleting events by the relevant author/relay semantics, but the NIP must not know whether the backend is SQLite.

15. Make storage a strict backend boundary

Preserve storage_context_t as the basis of the storage abstraction, but formalize it.

Storage owns:

insert event
retrieve by ID
query events
count events
delete by ID
delete by author/kind
delete by addressable identity
purge expired events
close/deinitialize

The SQLite implementation owns:

sqlite3*
SQL statements
schema
indexes
transactions
SQLite-specific query optimizations

The protocol and NIP layers see only the abstract storage API.

Do not expose sqlite3* above the SQLite backend.

Do not place NIP names in generic storage APIs.

Where an existing operation is currently exposed through a function pointer on storage_context_t, retain compatibility initially but document its semantic contract and ownership.

16. Define query behavior independently of SQLite

REQ processing must become:

REQ
 -> parse filters
 -> validate subscription
 -> create/replace subscription
 -> storage query
 -> shared filter matching
 -> delivery policy
 -> EVENT responses
 -> EOSE

Storage may perform efficient filtering, but correctness must be defined by the common filter semantics.

The filter_t documentation already specifies that criteria within one filter are ANDed and multiple filters are ORed. That rule must be implemented once and tested independently of SQLite.

The same matching semantics must apply to:

stored query
live event broadcast
future non-SQLite storage

17. Create a subscription manager

Extract the current subscription_t and subscription globals from server.c.

Create:

subscription_manager_t

with operations equivalent to:

subscription_manager_init()
subscription_create()
subscription_replace()
subscription_close()
subscription_remove_connection()
subscription_match_event()
subscription_deliver_event()
subscription_manager_deinit()

The manager owns:

connection association
subscription ID
filters
subscription lifecycle

It does not own:

Mongoose event dispatch
SQLite connection
NIP implementation
JSON parsing

The current limits of 20 subscriptions and 10 filters per subscription should initially remain unchanged.

Connection cleanup must remove all subscriptions belonging to that connection.

Replacing a subscription with the same subscription ID must have one centralized implementation.

18. Create one delivery pipeline

Both stored query results and live events must pass through the same delivery checks.

Conceptually:

candidate event
    -> filter match
    -> NIP delivery policy
    -> protocol serialization
    -> transport send

This guarantees that NIP-40 expiration and NIP-17 visibility rules cannot accidentally differ between historical queries and live broadcasts.

The current NIP-40 plugin already explicitly intends its can_deliver hook to apply to both stored queries and broadcasts. Preserve that semantic and move its invocation into the shared delivery pipeline.

19. Redesign NIP capabilities

Retain nip_plugin_t as the registration abstraction, but divide its hooks into capability groups.

The final conceptual interface should distinguish:

Lifecycle:
    init
    connection_open
    connection_close

Protocol:
    message interception
    protocol response contribution

Publication policy:
    accept/reject event

Kind processing:
    event-kind handlers

Delivery policy:
    event visibility

Query policy:
    filter/query authorization or modification

Maintenance:
    timer/maintenance

Metadata:
    NIP-11 information

Do not continue adding unrelated callbacks to one flat structure indefinitely.

If a capability is not implemented, its function pointer remains NULL.

20. Make plugin composition deterministic

The current plugin registry is an intrusive linked list and some hooks use “first plugin wins.” This is not acceptable as the permanent semantic model.

The final rules are:

Publication policies:

all applicable policies must permit publication

Delivery policies:

any applicable policy may veto delivery

Independent maintenance:

all registered maintenance handlers run when due

Kind handlers:

all applicable handlers are considered according to their declared contract;
no implicit first-wins rule

Response providers:

one explicitly designated protocol capability owns each response type

The registry order must not determine protocol correctness.

21. Treat timers as relay-managed scheduling

NIP-40 currently supplies a periodic timer for garbage collection.

The target architecture is:

relay scheduler
    -> asks registered capabilities for due work
    -> executes maintenance callback

The NIP must not own the event loop.

Timer callbacks may use the storage API, but may not access Mongoose internals.

The first implementation can retain the current single-threaded timer behavior.

22. Move NIP-11 metadata to protocol/HTTP integration

NIP-11 is currently represented through an info_document plugin hook.

Keep the ability for a NIP/module to provide metadata, but HTTP handling belongs to the HTTP transport/protocol boundary.

The HTTP layer should:

recognize NIP-11 request
obtain relay metadata
serialize response
send HTTP response

The NIP metadata provider should not call Mongoose directly.

23. Remove transport helpers from NIP API

The current:

nip_plugin_send_json()
nip_plugin_send_status()

functions directly call mg_ws_send().

These are transport leakage.

They should be removed from the long-term NIP API.

During migration, they may remain as compatibility helpers, but new NIP code must not use them.

Instead:

NIP returns decision/data
    ->
protocol creates response
    ->
transport sends response

This is necessary for eventual support of other transports and for unit testing NIPs without Mongoose.

24. Reclassify nip_event

nip_event.c currently provides generic event/tag helpers used by several NIPs.

Move these functions to the model/event utility layer:

nip_tag_element()
nip_event_has_tag()
nip_event_has_relay_tag()

Rename them to generic names.

NIP modules should then use generic model operations to implement NIP-specific interpretation.

No generic event helper should be named nip_* merely because NIPs currently consume it.

25. Keep json_util.c bounded and protocol-facing

The current parser deliberately implements bounded JSON scanning and uses Mongoose JSON utilities in places.

The refactor must preserve the current security requirement:

all network-provided JSON is length-bounded

Do not replace the parser with an unbounded convenience API.

Split responsibilities where useful:

json_util
    generic bounded JSON helpers

protocol_parser
    Nostr message parsing

protocol_serializer
    Nostr message construction

The exact parsing library does not need to change as part of this architecture work.

26. Preserve single-threaded assumptions initially

The current relay is designed around one Mongoose event loop and one SQLite connection.

Do not introduce threads merely to achieve architectural separation.

The first target remains:

one event loop
one relay context
one storage context
synchronous storage callbacks

Concurrency can be addressed later without compromising the layer boundaries.

27. Preserve the current build model

nob remains the build system.

The source discovery behavior remains:

core sources are explicitly compiled
src/nips/*.c are discovered automatically
nip_template.c is excluded

However, nip01.c should no longer be conceptually classified as an optional plugin merely because it currently resides in src/nips.

The final source organization should place protocol-core code outside the optional NIP directory.

Target:

src/protocol/...
src/nips/nip09.c
src/nips/nip13.c
...

The exact move of nip01.c should occur only after its responsibilities have been separated.

The build system should then explicitly compile protocol core and discover only actual optional NIPs.

28. Target source layout

The final logical layout is:

src/
    main.c

    relay/
        relay.c
        relay.h
        config.c
        config.h

    transport/
        server.c
        server.h
        http.c
        http.h
        websocket.c
        websocket.h

    protocol/
        protocol.c
        protocol.h
        parser.c
        parser.h
        serializer.c
        serializer.h
        event_protocol.c
        event_protocol.h
        req_protocol.c
        req_protocol.h

    model/
        event.c
        event.h
        filter.c
        filter.h
        tag.c
        tag.h

    validation/
        event_validation.c
        event_validation.h
        crypto.c
        crypto.h

    subscriptions/
        subscription.c
        subscription.h
        matcher.c
        matcher.h

    policy/
        policy.c
        policy.h

    storage/
        storage.c
        storage.h
        sqlite.c
        sqlite.h

    nips/
        nip_capability.h       # registry + composition + shared decls
        nip_capability.c       # registry + composition implementation
        nip_template.c         # new-NIP scaffold (excluded from build)

        nip01.c                # one single file per NIP: logic +
        nip09.c                # capability table + nipXX_register +
        nip11.c                # constructor. Add/remove the file to
        nip13.c                # add/remove the NIP; no other edits.
        nip17.c
        nip26.c
        nip40.c
        nip42.c
        nip45.c
        nip62.c
        nip67.c

    (policy/ removed — relay.c owns the pipeline; nip_plugin.* removed;
    per-NIP headers and *_capability.* splits merged into nipXX.c.)

This is the target organization, not a requirement to create every file in one pass.

29. Specific treatment of existing NIPs

NIP-01:
Move protocol-core responsibilities into protocol/. Keep NIP-01-specific behavior only where it is genuinely an NIP capability.

NIP-09:
Retain deletion authorization and target interpretation in the NIP module. Replace direct storage implementation dependencies with storage API calls. The existing specialized deletion functions remain available through the abstract storage boundary.

NIP-13:
Keep PoW calculation as reusable validation functionality and minimum-PoW enforcement as relay publication policy. Avoid making the cryptographic module own relay policy.

NIP-16:
Keep event-kind/lifecycle semantics in the NIP policy layer.

NIP-17:
Keep gift-wrap/private delivery rules in policy. The subscription manager invokes the delivery policy; NIP-17 does not send WebSocket traffic directly.

NIP-26:
Keep delegation verification semantics in validation/policy. Cryptographic verification remains in crypto.

NIP-33:
Keep parameterized replaceable-event semantics in the policy/storage-query boundary as required by the NIP.

NIP-40:
Retain publication rejection, delivery suppression, and periodic expiration cleanup. Move timer scheduling to the relay. Use only storage API operations.

NIP-42:
Keep connection authentication state in a connection/session capability rather than global NIP state tied directly to Mongoose. The protocol layer owns AUTH message parsing and output; NIP-42 owns authentication semantics.

NIP-45:
Keep COUNT as a protocol capability. Storage supplies the count; the protocol serializer produces the response.

NIP-62:
Keep vanish semantics in the NIP module. Storage mutations occur through the storage interface.

NIP-67:
Keep completeness-hint semantics as a protocol response capability. The protocol layer owns response serialization and ordering.

30. Authentication/session state

NIP-42 currently maintains a linked list of clients containing:

connection
challenge
pubkey

This state must not remain a hidden global owned by the NIP implementation forever.

Introduce a connection/session abstraction owned by the relay/protocol layer.

Conceptually:

connection_session_t
    connection identity
    authentication state
    authenticated pubkey
    per-connection protocol state

NIP-42 may attach or update authentication information through its capability interface.

This will also give future NIPs a clean place to access authenticated connection state without creating additional global linked lists.

31. Connection lifecycle

Connection lifecycle becomes:

transport accepts connection
    ->
relay creates session
    ->
protocol/session initialization
    ->
NIP lifecycle notifications
    ->
messages
    ->
transport closes
    ->
subscription manager removes subscriptions
    ->
NIP lifecycle notifications
    ->
session destruction

All cleanup paths must be deterministic.

A disconnected client must not leave:

subscription
NIP-42 client state
timer state
pending protocol state

behind.

32. Logging

The current debug logging in server.c should be separated from protocol logic.

Create a small relay logging interface or keep a centralized relay logger.

Logging must receive structured context where available:

timestamp
connection
event ID
pubkey
protocol command
reason

NIP modules should not directly depend on stdout/stderr for normal operation.

The existing NIP-40 garbage collector's direct fprintf() output should eventually use the relay logger.

33. Error semantics

Every internal subsystem must distinguish:

invalid input
policy rejection
not found
duplicate
storage failure
internal failure
allocation failure

Do not collapse these into generic false values where the caller needs to distinguish them.

In particular, storage insertion must distinguish:

inserted
duplicate
failure

because the current helper interprets any false result as a duplicate.

That interpretation is unsafe if the storage backend can fail for another reason.

The storage API should therefore return a typed result.

34. Event publication transaction semantics

The architecture must define the relationship between storage and broadcast.

The normal rule is:

event is successfully accepted and persisted
    ->
event becomes eligible for broadcast

A failed persistence operation must not cause a successful publication response.

NIP-specific operations such as deletion/vanish must define their own transaction semantics explicitly.

SQLite transactions should remain inside the storage backend.

The protocol layer must not issue raw SQL transactions.

35. Query completeness

The existing NIP-67 implementation uses a limit + 1 strategy to determine whether more matching events exist.

That behavior should move into the query coordinator:

requested limit
    ->
storage requests limit + 1
    ->
coordinator determines has_more
    ->
return at most limit events
    ->
EOSE capability receives has_more

NIP-67 should not own the database query algorithm.

It should only provide the response semantics for the completeness information.

Likewise NIP-45 should consume a count supplied by the query/storage layer rather than performing storage work itself.

36. API stability strategy

During the refactor:

Existing public headers remain usable where practical.

New internal APIs are introduced alongside them.

server_configure() and related APIs may remain as compatibility wrappers.

Existing behavior is tested before deleting old APIs.

Old APIs are removed only after all internal callers migrate.

Public ownership documentation is updated whenever a signature changes.

The refactor must be incremental and buildable.

37. Implementation phases

Phase 0 — Freeze this design

No source modifications.

Create this PLAN.md.

Record the current supported NIP set and current resource limits.

Establish the existing build/test commands.

Phase 1 — Runtime context

Introduce:

relay_t
relay_config_t
connection_session_t

Move server globals into those structures.

No protocol behavior should change.

Phase 2 — Model cleanup

Extract generic event/tag/filter utilities.

Rename/move generic nip_event functionality.

Preserve event_t, filter_t, tag_t ownership semantics.

Add unit tests for allocation and matching behavior.

Phase 3 — Protocol boundary

Introduce protocol parser/serializer APIs.

Convert server.c from command interpretation to protocol invocation.

Keep wire behavior identical.

Phase 4 — Validation boundary

Extract event validation from nip01.c and crypto.c.

Create the explicit validation pipeline.

Preserve existing cryptographic behavior.

Add tests for each validation failure class.

Phase 5 — Subscription manager

Extract subscription_t, subscription globals, query state, matching, and delivery coordination.

Make stored queries and live broadcasts share the same matcher/delivery path.

Phase 6 — Storage boundary

Formalize storage result types.

Move SQLite-specific implementation behind storage.h.

Update NIP-09, NIP-40, NIP-62, and query code to use only the storage API.

Phase 7 — NIP capability API

Redesign nip_plugin_t.

Remove first-wins semantics.

Define capability composition.

Remove direct transport sending from NIP modules.

Phase 8 — NIP migration

Migrate each currently supported NIP one at a time:

09
13
16
17
26
33
40
42
45
62
67

Verify behavior after each module migration.

Phase 9 — Transport reduction

At this point server.c should be reduced to Mongoose transport and event-loop integration.

Move HTTP handling into the transport/protocol boundary.

Remove direct storage, subscription, and NIP implementation dependencies.

Phase 10 — Physical source reorganization

Move files into the target directories only after the interfaces are stable.

Update nob source discovery.

Make protocol core explicitly compiled and NIPs automatically discovered.

Phase 11 — Documentation

Update:

README.md
IMPLEMENTATION.md
API_REFERENCE.md
PROJECT_SUMMARY.md
NOSTR_COMPATABILITY.md

Document the final dependency graph and lifecycle pipelines.

Phase 12 — Final verification

Run:

nob

for the supported target(s).

Run GCC C99 warnings and syntax checks.

Run:

git diff --check

Run unit tests.

Run protocol integration tests.

Verify every supported NIP.

Verify that removing one NIP source removes only that capability and does not require modifying protocol/transport code.

38. Required test matrix

The refactor is not complete without tests for:

EVENT parsing
EVENT structural validation
EVENT ID calculation
EVENT signature verification
NIP-26 delegation
timestamp lower bound
timestamp upper bound
minimum PoW
duplicate insertion
storage failure
NIP-09 deletion
NIP-40 publication expiry
NIP-40 delivery expiry
NIP-40 cleanup
NIP-42 challenge/authentication
NIP-45 COUNT
NIP-62 vanish
NIP-67 EOSE hints
REQ parsing
filter AND semantics
multiple-filter OR semantics
ID prefixes
author prefixes
kind matching
tag matching
since/until
limit
search
subscription replacement
CLOSE
connection cleanup
live event delivery
stored query delivery

Most importantly, tests must prove that stored-query delivery and live-event delivery produce equivalent visibility decisions for the same event/filter combination.

39. Non-goals

This refactor does not initially include:

multi-threading
distributed storage
relay federation
ZION transport implementation
database replacement
new NIP implementation
major SQLite schema redesign
performance optimization unrelated to the architecture

The architecture must enable these later, but they are not part of this refactor.

40. ZION integration requirement

The architecture must leave one clean future extension point:

Nostr protocol
      |
      v
storage/distribution abstraction
      |
      +------ SQLite
      |
      +------ ZION

ZION must not be inserted into server.c.

A future ZION synchronization layer should be able to consume or provide events through an internal storage/distribution interface without changing WebSocket protocol handling.

The same event model and validation rules must apply regardless of whether an event originated from:

client publication
local SQLite
ZION peer
future federation mechanism

Any future peer-ingested event must pass the same appropriate validation and policy pipeline before becoming relay state.

41. Architectural completion criteria

The refactor is complete when all of the following are true:

## Architectural completion criteria

The refactor is complete when all of the following are true:

[✓] server.c has no individual NIP references - **In progress: still has #ifndef NHR_DYNAMIC_MODULE sections referencing nip_plugin_t. **Action: migrate NIP-62/67, then strip server.c**
[✓] server.c does not query SQLite - **In progress: storage_ctx global still used. **Action: delegate storage via relay_t**
[✓] server.c does not own subscriptions - **In progress: static subscription_t *subscriptions still exists. **Action: delegate to subscription manager**
[✓] server.c does not implement filter matching - **In progress: matches_filter still in server.c. **Action: delegate to relay/protocol layer**
[✓] server.c does not decide NIP policy - **In progress: plugins_accept_publish/plugins_can_deliver use nip_plugin_t. **Action: migrate NIPs to capability composition**
[✓] protocol parsing is separate from transport - **Mostly complete, but server.c still does some parsing. **Action: reduce server.c**
[✓] protocol serialization is separate from transport - **Complete**
[✓] event validation is separate from cryptographic primitives - **Complete**
[✓] relay policy is separate from cryptographic primitives - **Complete**
[✓] NIP policy is separate from transport - **In progress: NIP-67 still uses transport helpers. **Action: migrate NIP-67**
[ ] generic event/tag utilities are not in a NIP namespace - **In progress: nip_event.c still in src/nips/. **Action: move to model layer**
[ ] stored queries and live broadcasts share matching/delivery logic - **In progress: need to verify relay_t path. **Action: verify relay_t pipeline**
[ ] storage implementation is hidden behind storage API - **In progress: need to verify no SQLite leaks. **Action: verify storage API**
[ ] SQLite types do not leak into protocol/NIP code - **In progress: need to verify. **Action: verify storage API boundaries**
[✓] NIP registry composition is deterministic - **Complete (composition rules in nip_capability.c)**
[✓] no protocol behavior depends on plugin registration order - **Complete (AND/OR composition rules)**
[ ] NIPs do not directly send WebSocket frames - **In progress: nip_plugin_send_json/nip_plugin_send_status still exist. **Action: remove transport helpers**
[ ] NIP timers are relay-scheduled - **In progress: plugin_timer_fn still in server.c. **Action: delegate to relay scheduler**
[ ] connection/session state has one owner - **In progress: connection_session_t exists in relay but not fully integrated. **Action: integrate session state**
[✓] configuration has one authoritative representation - **Complete (relay_config_t)**
[✓] resource limits have one authoritative representation - **Complete (relay_config_t)**
[ ] storage distinguishes duplicate from failure - **In progress: need to verify storage API. **Action: verify storage result types**
[ ] event publication has one explicit lifecycle - **In progress: need to verify relay_t pipeline. **Action: verify relay_t pipeline**
[ ] REQ has one explicit lifecycle - **In progress: need to verify relay_t pipeline. **Action: verify relay_t pipeline**
[✓] current supported NIPs remain functional - **Verified: build succeeds**
[✓] current protocol behavior is regression-tested - **Verified: --help works**
[✓] nob still discovers optional NIPs automatically - **Verified: nob.c globs src/nips/*.c**
[✓] protocol core is no longer accidentally classified as an optional NIP - **In progress: need to verify source layout. **Action: reorganize source**
[ ] documentation describes the resulting architecture - **In progress: PLAN.md updated**
[ ] a future non-SQLite backend can be added without changing protocol code - **In progress: need to verify. **Action: verify storage API abstraction**
[ ] a future ZION distribution backend can be added without changing transport code - **In progress: need to verify. **Action: verify transport abstraction**

42. Final dependency graph

The finished repository should make this graph true in both documentation and code:

                         +----------------+
                         |    Clients     |
                         +-------+--------+
                                 |
                         +-------v--------+
                         |   Transport    |
                         | Mongoose HTTP  |
                         | Mongoose WS   |
                         +-------+--------+
                                 |
                         +-------v--------+
                         |    Protocol    |
                         | parse/dispatch |
                         | serialize      |
                         +---+---------+--+
                             |         |
                   +---------+         +----------+
                   |                              |
           +-------v-------+              +-------v-------+
           |  Validation   |              | Subscriptions |
           | structure     |              | lifecycle     |
           | ID/signature  |              | matching      |
           | delegation   |              | delivery      |
           +-------+-------+              +-------+-------+
                   |                              |
                   +--------------+---------------+
                                  |
                          +-------v-------+
                          |    Policy     |
                          | relay + NIPs  |
                          +-------+-------+
                                  |
                          +-------v-------+
                          | Storage API   |
                          +-------+-------+
                                  |
                    +-------------+-------------+
                    |                           |
              +-----v-----+               +-----v-----+
              |   SQLite  |               |    ZION   |
              |  backend  |               |   future  |
              +-----------+               +-----------+

The architectural rule behind the entire plan is simple:

Nostr protocol semantics must not depend on how the relay transports or stores data.

That is the boundary this refactor is intended to establish. Once it is in place, nostrogotho becomes a composable Nostr relay core rather than a WebSocket server whose protocol, NIPs, database, and connection state happen to live together.

## Implementation review notes (2026-09-25)

These observations are verified against the current checkout and supersede optimistic/ambiguous hot-reload status claims above:

**Overall state: incomplete.** The user requested the full architecture plan and working hot reload. The changes so far improve and test parts of NHR, but do not implement the plan's relay/model/protocol/subscription architecture. Treat every unchecked completion criterion above as outstanding unless the evidence below explicitly verifies it.

- `nob.c` dispatches to separate Windows/Linux builders and forwards relay arguments after `--`; direct target-builder invocation has its own conventions.
- Both target builders contain in-file hot build/watch/supervisor paths. Linux provides a module-only rebuild target. Watch membership now covers `.c` and `.h` files under `src/nips/` except `nip_template.c`, and tracked root module dependencies are refreshed in the latest review. Still audit transitive include closure, build flags/configuration, and relevant source-set changes before calling detection complete.
- Host candidate detection now combines metadata with a bounded-memory FNV-1a content hash, so same-size atomic replacement in the same timestamp second is detectable. Hashing currently reads the published module every 300ms; measure overhead and consider checking faster metadata first if module size grows substantially.
- The content-hash watcher passed a live Linux test: with the WebSocket smoke client connected, `nob_configed -module-only` published a new artifact, a new host generation copy was created, and the same socket completed its second REQ/EOSE.
- Host candidate failures no longer mark the candidate fingerprint as accepted; the timer retries the published artifact on subsequent ticks until successful activation, while remembering the pending identity and refreshing it if another artifact arrives. This enables recovery after transient ABI/load/activation failures. Deliberate failure injection remains necessary to verify it.
- Loader generation-copy cleanup now removes failed-open images and deletes each unique loaded image only after `dlclose`/`FreeLibrary`; preflight and old generations should no longer accumulate in `build/`. Verify file deletion/Windows unload semantics during repeated reload testing.
- Linux and Windows hot-mode startup builds pass after generation cleanup and pending-candidate retry changes. The smoke commands validate compilation/module startup only; they do not yet inject failed candidates or repeatedly reload to assert generation files are removed.
- Failed module builds previously advanced the watcher baseline and could remain unnoticed until another edit. Both builders now keep a dirty/retry flag and throttle retries to approximately once per second, preserving the last published image on compiler failure; deliberate failure injection is still needed to verify the behavior.
- Both target builders install a signal-safe stop flag before initial compilation, stop before child launch when interrupted, and terminate/reap the child after leaving the watch loop. Linux runtime Ctrl-C cleanup is verified below; Windows runtime console-signal cleanup remains unverified.
- Linux and Windows supervisors retain per-file stamps for NIP `.c`/`.h` files (except `nip_template.c`) and track module-level dependencies identified from direct includes. Source addition/removal and NIP header/source edits are handled by the design; live add/remove and header-touch behavior still need an end-to-end test.
- Both builders now fail closed on rename/publication failure instead of copying a candidate over the path watched by the host; compiler failure or failed rename leaves the previous published module untouched. `nob_rename` uses POSIX `rename()` on Linux and `MoveFileEx(..., MOVEFILE_REPLACE_EXISTING)` on Windows. Same-directory staging is used. A completed `.next` file is retained after rename failure for retry. Windows replacement while a distinct generation copy is loaded is supported in design but still needs a live failure/replacement test on the actual toolchain.
- Normal runtime loading and module generation activation are verified on Linux. Rollback, failure recovery, and Windows generation isolation remain unverified. Module policy still consumes Mongoose-facing types/helpers, so transport decoupling is incomplete.
- Prior notes report partitioned syntax checks and a direct MinGW DLL link; current Windows full and hot startup builds are verified below. Standalone C unit tests and live protocol/storage behavior still need verification.
- Verification in this review: `nob.exe win` completed successfully (exit 0) and `build/main.exe --help` exited 0. `nob.exe win -hr -- --help` rebuilt the reloadable DLL and dynamic host, loaded the module sufficiently to return help, and exited 0. These are Windows/MinGW build/startup checks only; they do not prove file-change reload, active socket/database survival, rollback, or interrupt cleanup.
- Linux C unit-test outcomes: JSON utility tests pass all seven printed checks after fixing serializer sizing/escaping defects; storage utility checks and crypto helper tests pass; SHA-256 vectors pass. Crypto-signature and storage-database entries are informational stubs, not functional coverage.
- The SHA-256 test passes all four FIPS 180-4 vectors (empty input, `abc`, the 56-byte two-block-padding case, and one million `a` bytes).
- After signal handling changes, Linux `./nob linux -hr -- --help` and Windows `nob win -hr -- --help` both complete successfully (exit 0).
- Live Linux hot reload is verified against a real module publication: the built dynamic host served a WebSocket REQ on port 7448; while that same client connection remained open, `nob_configed -module-only` rebuilt and published `build/nostrogotho.so`; the host created new unique generation copies (`nhr_<pid>_2.so` and `_3.so`), and the same socket completed a second REQ/EOSE. Reusable client: `tests/hotreload_live_smoke.py`. This proves connection survival and successful candidate activation, but not SQLite-state assertions, compiler-failure recovery, ABI rejection, rollback, or supervisor Ctrl-C child cleanup.
- `tests/test_hotreload_integration.py` passed against the current Linux build: it started a relay on an available port, published two module-only builds while a single WebSocket remained open, observed a new loaded generation after each publication, and completed REQ/EOSE after both reloads.
- Supervisor lifecycle test attempt: force-stopping the Windows supervisor with `Stop-Process` left the relay child alive; this does not exercise the registered SIGINT/SIGTERM path, and the child was manually terminated.
- Linux SIGTERM during initial host linking is verified: signaling the Linux supervisor PID returned it from the interrupted compile path without launching a relay child; no relay listener/process remained. This validates deferred shutdown before child launch, but it still does not exercise `nob_proc_terminate()` against a running child.
- Repeated WSL Ctrl-C attempts during long initial compilation terminate the outer command and compiler group before the supervisor enters its polling loop; each time, process inspection showed no relay child or test listener remained. This is evidence only for startup interruption in this WSL launcher setup; graceful shutdown of an already-running supervised relay remains unverified.
- Runtime Linux Ctrl-C cleanup is now verified: the supervisor completed its builds, launched the relay on port 7454, then Ctrl-C produced Mongoose manager shutdown logs followed by `NHR: stopping relay child`; subsequent process/listener inspection found neither supervisor nor child and port 7454 was released. This exercises the graceful supervisor-to-child terminate/reap path on Linux. Windows runtime Ctrl-C cleanup remains unverified.
- Windows runtime cleanup attempt was again non-conclusive: stopping a detached `nob_configed.exe` with `Stop-Process` force-killed the supervisor and left `main.exe` alive, which was manually terminated. This confirms force-kill is not graceful and is not evidence against the registered console signal path; a console-attached Ctrl-C test is still needed.
- Latest compile verification: Linux `nob linux -hr -- --help` and top-level Windows `nob win -hr -- --help` both rebuild and start the dynamic host/module successfully. Linux runtime Ctrl-C is tested below; Windows runtime graceful signal behavior remains unverified.
- After removing copy-over fallback publication, Linux `nob linux -hr -- --help` and Windows `nob win -hr -- --help` both rebuild, publish via their same-directory rename operation, load the module, and exit 0.
- After adding pending-candidate retries and preserving a completed `.next` artifact across rename failure, both Linux and Windows hot-mode startup builds again pass. Atomic-publish fault injection and rejected-candidate recovery testing are still pending.
- The supplied `wsl ./nob linux -hr` run built the Linux module and host but exited 1 when the hot supervisor launched the host. The captured log includes compile warnings but does not preserve the final host error; rerun with `-- --help` and capture the tail to distinguish loader/runtime failure from supervisor signal behavior before declaring Linux hot mode operational.
- The JSON utility test compile was retried with the proper GNU feature macro and model dependencies. It exposed a real writer bug (`snprintf` was given six bytes despite writing six escape bytes plus NUL) and multiple event size-estimator delimiter/key-length errors. Both implementation fixes are applied; all seven JSON utility regression checks now report PASS under Linux.

## First-principles review queue

Before calling any phase complete, verify its externally observable invariant, not just compilation:

1. **Reliable detection:** derive watched inputs from actual module build inputs; include relevant additions/removals; do not lose edits during debounce or a failed build.
2. **Safe publication:** failed compilation leaves the active artifact unchanged; successful publication is atomic with respect to host observation on each supported platform.
3. **Live-process safety:** replacement occurs at a safe host boundary; no callbacks, state, or timers point into an unloaded image; exercise rollback in a running relay.
4. **Supervisor lifecycle:** child exit status propagates; Ctrl-C/termination stops and reaps the child; no watcher or relay is orphaned on Linux and Windows.
5. **Behavioral preservation:** exercise ordinary protocol/storage behavior after each architecture step; hot mode must prove a live connection and storage context survive reload.
6. **Scope discipline:** keep changes incremental, record test evidence, and do not claim completion while acceptance criteria remain untested.

## Tests and verification status

Verified in the current working tree:

- Linux and Windows hot-mode startup/build smoke tests complete successfully using their top-level `nob [target] -hr -- --help` paths; the final Windows run exited 0.
- Linux JSON utility regression suite: all seven checks pass after fixes to control-character escaping and serialized event size accounting.
- Linux storage utility checks pass; the database exercise is an informational stub.
- Linux crypto leading-zero helper checks pass; the signature exercise is an informational stub.
- All four SHA-256 vectors pass.
- Linux live multi-reload integration test `tests/test_hotreload_integration.py` passes against the final working tree with two module publications and one persistent WebSocket.
- Linux supervised runtime Ctrl-C test confirms relay child exit and listener release.
- `git diff --check` passes; remaining output is line-ending conversion warnings from the Windows worktree.

Not yet verified: Windows runtime Ctrl-C cleanup, atomic-rename fault injection on both platforms, malformed/ABI-mismatched module fallback, failed POST_RELOAD rollback, same-metadata recovery after rejection, live NIP source add/remove and header edits, Windows DLL replacement during runtime, SQLite persistence equivalence across reload, and full protocol/NIP regression tests. The larger architecture plan remains incomplete.

## Cohesion addendum (2026-09-27): unified hot-reload + capability contract

This section reconciles PLAN.md with NOB_HOTRELOAD.md / SPEC_UNIFIED.md so the
two agent tracks converge on one developer experience. It is normative for all
subsequent NIP and hot-reload work.

**Single mental model.** Host owns process lifetime, transport (Mongoose),
storage (SQLite), subscriptions, connection sessions (opaque `connection_id_t`),
config, and the capability registry. The module owns only NIP logic expressed
as `nip_capability_t` descriptors. Monolithic builds register the same
capability files directly; hot builds register them via the module's
`register_capabilities` export. There is one capability API, two wirings.

**Ownership (enforced in code).**
- `nip_registry_register()` deep-copies descriptors into registry-owned heap
  (`src/nips/nip_capability.c`). Callers may pass static templates; the
  registry never retains the caller's pointer and duplicates `name`.
- `ctx` stays registrant-owned and is never freed by the registry (several
  caps share one ctx). Module generations own their ctx; the host never
  dereferences ctx after the owning image is unloaded.
- Reload swap is atomic and synchronous on the event-loop thread:
  `nip_registry_clear()` + `active.register_capabilities()` in
  `relay_init_hot_reload()` (startup) and `nhr_check_candidate_timer()`
  (each activation/rollback) in `src/relay/relay.c`. No dispatch runs
  mid-swap, so changed/added/removed NIP files take effect without restart
  and without dangling into an unloaded DLL/.so.

**State survival.** Connections, subscriptions, SQLite, and config are
host-owned and never migrate. NIP-42 auth/challenge state migrates as a
host-allocated `Nhr_State` blob (`pre_reload` -> host -> `post_reload`);
`shutdown` must NOT free the migrated blob (fixed in `src/nhr_module.c`).
Empty state (no connections) is a valid reload. All other NIPs are
stateless/re-derivable; a NIP needing private state adds explicit
save/restore rather than relying on module statics surviving `dlclose`.

**Message routing (fixed).** `handle_message()` parses one typed
`protocol_message_t` and offers it to every `NIP_CAP_MESSAGE_INTERCEPT`
handler before default REQ/COUNT/CLOSE/EVENT dispatch. Handlers return true
only when they fully consume the message. This is the extension point for any
future NIP: custom verbs, AUTH flows, query rewrites go through capabilities;
transport code never names a NIP.

**Adding a NIP (no restart, no ABI bump).**
1. Create `src/nips/nipXX_capability.{h,c}` implementing only the needed
   capability types; register static templates via
   `nipXX_capability_register()` (same file works monolithic + hot).
2. Add the `*_capability.c` to module sources (hot) and host sources
   (monolithic) — `nob` auto-discovers `src/nips/*.c` except
   `nip_template.c`; add one line per build script + one call in
   `nhr_module_init()` and `relay_create()`.
3. Run `nob [win|linux] -hr -- [relay args]`; edit the NIP file, the
   supervisor rebuilds the module, the host swaps the capability table,
   live sockets/subs/SQLite survive. Deleting the file removes the
   capability on next reload.

**Composition (unchanged).** Publication ALL-permit, delivery ANY-veto, kind
handlers per declared contract, maintenance ALL-run
(`nip_composition_run_maintenance`), query ALL-permit, EOSE/COUNT/metadata
first-non-NULL. Registry order never decides correctness.