# NOSTR Compatibility & Feature Completeness

> **Status:** Living document — one section per implemented NIP.
> Each NIP is audited by comparing `src/nips/nip<X>.c` against the reference
> specification in `thirdparty/nips/<X>.md`.
>
> **2026-09-03 audit:** NIP-16 and NIP-33 were consolidated into `nip01.c`
> (both specs are `final mandatory` "Moved to NIP-01"); NIP-40 and NIP-45 were
> wired into the request path; NIP-62 relay-tag enforcement, NIP-13 nonce
> target validation, NIP-26 delegated-author queries and delegator deletion,
> NIP-42 `restricted` prefix, and NIP-67 `auth` hint were implemented. NIP-11
> now derives `supported_nips` and `limitation` from real runtime values.
>
> **Status legend**
>
> | Status | Meaning |
> | ------ | ------- |
> | ✅ **Complete** | Spec requirements covered, wired into the server, exercised |
> | 🟡 **Partial** | Core behaviour present, but spec details missing and/or not fully integrated |
> | ⏳ **Infrastructure only** | Helper function exists but is not wired into the request path |
> | 🔌 **Supported-by-other-NIP** | Spec moved/absorbed into another NIP (matches the reference `.md`) |

---

## Summary Table

| NIP | Title | Status | Kind(s) registered | Wired into server |
| --- | ----- | ------ | ------------------ | ----------------- |
| [01](thirdparty/nips/01.md) | Basic Protocol Flow | ✅ Complete | dispatcher core + NIP-16/33 | ✅ |
| [09](thirdparty/nips/09.md) | Event Deletion Request | ✅ Complete | `5` | ✅ |
| [11](thirdparty/nips/11.md) | Relay Information Document | ✅ Complete | HTTP document | ✅ |
| [13](thirdparty/nips/13.md) | Proof of Work | ✅ Complete | (via NIP-01) | ✅ |
| [16](thirdparty/nips/16.md) | Event Treatment | ✅ Complete (→ NIP-01) | `0, 3, 10000-19999` | ✅ |
| [17](thirdparty/nips/17.md) | Private Direct Messages | ✅ Complete | gating only + `auth` hint | ✅ |
| [26](thirdparty/nips/26.md) | Delegated Event Signing | ✅ Complete | (via crypto) | ✅ |
| [33](thirdparty/nips/33.md) | Parameterized Replaceable Events | ✅ Complete (→ NIP-01) | `30000-39999` | ✅ |
| [40](thirdparty/nips/40.md) | Expiration Timestamp | ✅ Complete | — | ✅ |
| [42](thirdparty/nips/42.md) | Client Authentication | ✅ Complete | `22242` (auth) | ✅ |
| [45](thirdparty/nips/45.md) | Event Counts | ✅ Complete | — | ✅ |
| [62](thirdparty/nips/62.md) | Request to Vanish | ✅ Complete | `62` | ✅ |
| [67](thirdparty/nips/67.md) | EOSE Completeness Hint | ✅ Complete | — | ✅ |


---

## NIP-11 — Relay Information Document

**Reference:** `thirdparty/nips/11.md` · **Implementation:** `src/nips/nip11.c`

### What is implemented ✅

- **`name`** — `"nostrogotho"`.
- **`supported_nips` advertisement** — `[1, 9, 11, 13, 16, 17, 26, 33, 40, 42, 45, 62, 67]`,
  matching the NIPs actually wired into the server.
- **`limitation` block** — built from the real runtime constants passed in via
  `nip11_configure()` during `server_configure()`: `max_message_length` (5242880),
  `max_subscriptions` (20), `max_filters` (10), `max_subid_length` (100),
  `max_event_tags` (100), `max_content_length` (16384), `max_limit` (500),
  `default_limit` (500), `created_at_lower_limit` / `created_at_upper_limit`
  (emitted only when non-zero), `auth_required`.
- **HTTP delivery** — `nostr_event_handler` in `server.c` serves the document
  for HTTP requests with `Accept: application/nostr+json`, including the
  `Access-Control-Allow-Origin: *` CORS header.

### Planned features

- [ ] Populate optional metadata (`description`, `software`, `version`,
      `contact`, admin `pubkey`) from configuration.

---

## NIP-17 — Private Direct Messages

**Reference:** `thirdparty/nips/17.md` · **Implementation:** `src/nips/nip17.c`

### What is implemented ✅

- **Gift-wrap gating** — `nip17_can_deliver()` refuses to serve `kind 1059` and
  `kind 21059` events unless the connection is authenticated (NIP-42) as a
  pubkey `p`-tagged on the event.
- **Enforced in both delivery paths** — used in `broadcast_event()` and
  `query_sender()` in `server.c`, so gift-wrap metadata is only served to
  participants.
- **`kind 10050` inbox list** — stored as a replaceable event via the
  consolidated NIP-01 listener (10000–19999 range), which is all a relay needs.
- **`auth` hint support** — unauthenticated `REQ`s targeting gift-wrap kinds
  receive an `AUTH` challenge followed by `["EOSE", sub, ["auth", ...]]`
  (NIP-67 integration).

### Notes

- **No encryption / decryption** — NIP-44 and NIP-59 are referenced; relays do
  not decrypt. This is expected: relays should only gate, not decrypt.
- **No `subject` tag semantics** — relays do not track chat-room topics
  (primarily a client concern).
- **Disappearing messages** — the `expiration` tag path is now enforced via
  NIP-40 (expired gift-wraps are dropped on publication and never served).

---

## NIP-40 — Expiration Timestamp

**Reference:** `thirdparty/nips/40.md` · **Implementation:** `src/nips/nip40.c`

### What is implemented ✅

- **`nip40_event_is_expired(event)`** — scans the event's raw tags JSON for an
  `expiration` tag and returns `true` when `expiration <= now`.
- **`nip40_is_expired(tags)`** — parsed-tags variant for storage callers.
- **Accept path (plugin `accept_publish`)** — rejects already-expired
  publications with `"invalid: event is expired"`.
- **Query path (plugin `can_deliver`)** — drops expired events from stored
  queries and broadcasts, so stored-but-expired events are never served.
- **Background GC** — the plugin registers a periodic `timer` hook that sweeps
  expired rows out of the database.
- **Ephemeral events unaffected** — kinds 20000–29999 are never stored, so
  expiration has no effect on their broadcast-only treatment (per spec).

### Plugin note

NIP-40 is a fully modular plugin. It self-registers via
`nip_plugin_register()` in `nip40.c` and participates in the relay only
through the generic `nip_plugin_t` hooks (`accept_publish`, `can_deliver`,
`timer`). Deleting `src/nips/nip40.c` from the build removes all of the above
with no changes to `server.c`.

---

## NIP-45 — Event Counts

**Reference:** `thirdparty/nips/45.md` · **Implementation:** `src/nips/nip45.c`

### What is implemented ✅

- **`nip45_build_count_response(sub_id, count)`** — builds a `["COUNT", qid,
  {"count": N}]` JSON array with the JSON builder.
- **Wired end-to-end** — `send_records()` in `storage.c` now reports the
  aggregated count via its `out_count` out-parameter instead of formatting the
  response itself; `query_events()` in `server.c` builds and sends the response
  through `nip45_build_count_response()`. The storage layer stays free of
  protocol formatting.
- **Multiple filters are OR'd and aggregated** into a single count, per spec.

### Planned features

- [ ] Optional `approximate` probabilistic counting.
- [ ] Optional HyperLogLog `hll` support with the deterministic `offset`.
- [ ] `CLOSED` + `auth-required` / `restricted` gating for `COUNT` of protected
  kinds.

---

## NIP-62 — Request to Vanish

**Reference:** `thirdparty/nips/62.md` · **Implementation:** `src/nips/nip62.c`

### What is implemented ✅

- **Kind `62` handler** registered for `62..62`.
- **`nip62_should_vanish()`** — returns `true` when a `relay` tag equals
  `ALL_RELAYS` (global vanish) or matches the relay's service URL (trailing-slash
  normalized via `nip_event_has_relay_tag`).
- **On vanish** — `delete_all_events_by_pubkey(pubkey, created_at)` removes all
  events authored by the pubkey **up to the event's `created_at`**, matching the
  spec's "delete everything ... until its `.created_at`".
- **Stores the request itself for bookkeeping** (`insert_record`), per the spec's
  "MAY store the signed request for bookkeeping".
- **Broadcasts** the request once accepted.
- **`relay` tag enforcement** — kind-62 events without at least one `relay`
  tag are rejected with
  `"invalid: kind 62 requires at least one relay tag"` (spec: the tag list
  MUST include at least one `relay` value).

### What is missing / partial 🟡

- **NIP-59 gift-wrap cleanup** — the spec says relays SHOULD delete gift-wraps
  that `p`-tagged the pubkey (deleting DMs received by the pubkey). Not
  implemented: `delete_all_events_by_pubkey` only removes events **authored by**
  the pubkey, not gift-wraps **received by** them.

### Planned features

- [ ] Gift-wrap (`1059` / `21059`) cleanup for `p`-tagged recipients on vanish.

---

## NIP-67 — EOSE Completeness Hint

**Reference:** `thirdparty/nips/67.md` · **Implementation:** `src/nips/nip67.c`

### What is implemented ✅

- **`nip67_build_eose_response(_ex)(sub_id, has_more[, auth_hint])`** —
  appends a third-element hint array to `EOSE`:
  - `["EOSE", sub_id, ["more"]]` when more stored events exist,
  - `["EOSE", sub_id, ["finish"]]` when complete,
  - `["EOSE", sub_id, ["auth", ...]]` when unauthenticated results may be
    auth-gated.
- **Integration** — `server.c` `query_events()` calls it after the initial
  query, with `has_more` computed by the storage layer (`send_records` fills
  it).
- **`auth` hint** — when an unauthenticated client REQs gift-wrap kinds
  (1059/21059), the relay sends a fresh `["AUTH", challenge]` (via
  `nip42_open_challenge`) followed by `EOSE` with the `auth` hint, meeting the
  spec's ordering requirement.
- **Advertised** — `67` is present in the NIP-11 `supported_nips`.

### What is missing / partial 🟡

- **`created_at` tie advancement** — the guidance to keep all boundary-timestamp
  events in one response is left to the storage layer (best-effort).

### Planned features

- [ ] Keep all events sharing the boundary `created_at` in one response.

---

## Cross-cutting notes

### Consolidation record (2026-09-03)

- **NIP-16 / NIP-33** — both specs are `final mandatory` "Moved to NIP-01";
  their listeners were folded into `nip01.c` (`nip01_replaceable_listener`,
  `nip01_addressable_listener`, registered via `nip01_init_listeners()`).
  `nip16.c/h` and `nip33.c/h` were deleted and the build list updated.
- **NIP-40** — fully wired (accept + query paths); advertisement is honest.
- **NIP-45** — `nip45_build_count_response` is the single COUNT formatter;
  storage returns the raw count via `out_count`.
- **NIP-11** — document generated from `nip11_configure()` with real limits.

### Target `supported_nips`

Implemented (as advertised by `nip11.c`):

```
[1, 9, 11, 13, 16, 17, 26, 33, 40, 42, 45, 62, 67]
```

### Shared theme: JSON escaping

`crypto.c` escapes the content when computing the event hash; response
serialization uses `json_builder_escape_string()` in `json_util.c` (single
source of truth for escaping) so all string fields are emitted correctly.

---

## References

- Implementation headers: `src/nips/nip<X>.h`
- Reference specs: `thirdparty/nips/<X>.md`
- Storage SQL / query helpers: `src/storage.c`, `src/storage.h`
- Crypto (ID / signature / delegation / PoW): `src/crypto.c`, `src/crypto.h`
- Server wiring: `src/server.c`, `src/main.c`