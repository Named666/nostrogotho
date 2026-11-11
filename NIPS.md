# NIP support audit: what a social-media Nostr relay still needs

Audited 2026-11-10 12:47 CST against branch `usockets` @ `d2f276e` (`build/main`).
Specs come from the official repo, https://github.com/nostr-protocol/nips (index:
[README.md](https://github.com/nostr-protocol/nips/blob/master/README.md)). The links
below point to `https://github.com/nostr-protocol/nips/blob/master/NN.md`.

Scope decision (owner, 2026-11-10 13:08 CST): implement everything below **except NIP-86 (management API) and NIP-77 (negentropy)**, which are intentionally out of scope.

## Final status (2026-11-10, branch `usockets`, local only, not pushed)

Everything in this audit is done except NIP-86 and NIP-77, which the owner put out of scope. The tables further down are the **baseline audit at `d2f276e`**. They are kept for reference and no longer describe the code.

| Item | Status | Commit(s) | Notes / remaining |
|---|---|---|---|
| A1 NIP-01 `#tag` filters | **done** | 182fe68, 755e00d, 9b1c4fc | `tag` table + delete trigger; WAL write-coalescing VFS (`ngwal`). Only `tag_index_letters` (default e,p,a,q,t,d,h,k) are indexed, at most `tag_index_max_per_event` (default 2000) per event; other letters and tags past the cap are answered from the stored tags JSON (correct, slower). The `kind` column stays: kinds filters are checked on the tag row before the join |
| A2 `limit:0` | **done** | 94aeaf6 | |
| A3/B7 tag count, sizes | **done** | 2d5e673 | configurable (`max_event_tags`, `max_content_length`, ...) |
| A4 OK for invalid events | **done** | 9257dad | NIP-01 prefixes |
| A5/A6 CLOSED, home-feed REQs | **done** | 734b4c4 | |
| A7 NIP-11 | **done** | d340020, a682d05 | supported_nips = 1, 9, 11, 13, 16, 17, 29\*, 33, 40, 42, 43\*, 45, 50\*, 62, 67, 70 (\* when enabled) |
| A8 NIP-09 | **done** | 76c3042 | recipient deletes gift wraps |
| A9 NIP-42 | **done** | d340020 | works without SERVICE_URL |
| A10-A12 | **done** | (baseline) | id tie-break covered in A1 ordering |
| B1 NIP-50 | **done** | 2f1138c, e6c656a | FTS5 external content, fed once per writer batch (one INSERT…SELECT before COMMIT and before any DELETE in the batch) instead of a per-row trigger; `search = 0` turns it off |
| B2 NIP-45 | **done** | c2cd747 | gift-wrap gating, HyperLogLog |
| B3 NIP-17/59 | **done** | 76c3042, fe947c5 | `auth-required:` CLOSED; NIP-67 `auth` hint |
| B4 NIP-70 | **done** | a682d05 | declared; reposts embedding protected events blocked |
| B5 NIP-62 | **done** | c046669 | durable `vanished` table |
| B6 NIP-40, B9 NIP-13 | **done**, declared | a682d05 | |
| B10 rate limits / bans | **done** | f7846d6, d8d8a31 | GCRA lock-free per IP (/64 for v6) and pubkey; `rate-limited:` / `blocked:`; ban lists load at startup only. Behind a reverse proxy listed in `trusted_proxies` (default 127.0.0.1, ::1; CIDRs allowed) the client IP is the rightmost untrusted X-Forwarded-For entry (else X-Real-IP); nginx snippet in `nostrogotho.conf` |
| B11 NIP-86 | **out of scope** | – | owner decision |
| NIP-77 | **out of scope** | – | owner decision |
| NIP-26 | **removed** | e822225 | unrecommended |
| NIP-29 groups | **done (core spec)** | 6ec0dbe, cd73744, 0dc4ea3, 63bf842 | needs `relay_secret_key_file`. Moderation kinds 9000-9002, 9005, 9007-9010 (others in 9000-9020 refused `invalid:`), join/leave 9021/9022, relay-signed 39000-39003 and 39005, private/restricted/hidden/closed, `previous` references checked, late publication (`group_max_age`, default 3600 s). **Not done (optional parts of the spec):** subgroups (`parent`/`child`), LiveKit (39004 and `/.well-known/nip29/livekit`), join requests held for admin review |
| NIP-43 | **done** | 6b8f91d | `nip43 = 1`; 28934/28936, relay-signed 13534/8000/8001, `members_only`. **Not done:** 33534 roles, 28935 claims (these need NIP-86 `createclaim`) |
| NIP-67 | **done** | fe947c5 | `finish` / `more` (LIMIT n+1 probe, byte budget) / `auth`. **Not done:** moving the cursor past created_at ties (a SHOULD) |

Known limitations:
- NIP-29/43 in-memory state is updated before COMMIT. If a writer COMMIT fails, the relay-generated events roll back, but the in-memory state does not until restart, when the state is replayed from the DB.
- Tag filters on letters outside `tag_index_letters` (e.g. NIP-22 `#E`/`#K`/`#P`, `#r`, `#g`) scan the tags JSON of the events the rest of the filter selects: correct, but O(candidates) instead of an index lookup. Add heavily queried letters to the list (the index is rebuilt at the next start).
- Ban lists are read at startup only, because changing them at runtime would need NIP-86.

Durability: `tools/fsync_check/` (LD_PRELOAD tracer) shows that every `OK true` is sent only after an fdatasync of the WAL that started after the event's frames were written. This holds with coalescing on and off. The `db_sync = normal` negative control is caught. Results are in `tools/fsync_check` output at 1f961ac: 2400/2400 OKs covered, 0 violations; 704 WAL pwrites / 668 syncs with coalescing, 19211 pwrites without; the NORMAL control flags all 2400.

Durability at d8d8a31 (`tools/fsync_check/run.sh`, 18:44 CST, `/workspace/bench/gate-results/perf2-fsync.txt`): every `OK true` was sent only after an fsync of the WAL that covered its frames.

| run | OKs covered | violations | WAL pwrites / syncs |
|---|---|---|---|
| coalescing on | 2400/2400 | 0 | 1038 / 1038 |
| coalescing off | 2400/2400 | 0 | 22257 / 706 |
| `db_sync = normal` control | – | 2400, as expected | – |

Publish events/s, FULL sync, 64 conns × pipeline 16, relay on CPUs 0-3. Median of 3 interleaved runs, 18:46-18:52 CST (`/workspace/bench/gate-results/perf2-pub.txt`):

| dataset | d2f276e (base) | 04f344e (before fixes) | d8d8a31 (HEAD) | HEAD vs 04f344e | HEAD vs base |
|---|---|---|---|---|---|
| ev1500k (1 tag, content "0") | 45,492 | 29,580 | 48,332 | +63% | +6% |
| ev400k_tags (4 tags with hints) | 43,310 | 20,193 | 25,070 | +24% | −42% |
| ev400k_text (25-word content) | 40,519 | 17,054 | 24,121 | +41% | −40% |

Reading:
- FTS5 bulk feed (e6c656a) and the smaller tag index (9b1c4fc) recover the search cost on short and text events.
- ev400k_tags uses only indexed letters (e/p), so the remaining gap is the tag rows themselves.
- Base numbers are about 5-35% higher than the 17:16 CST runs (host load varies), so compare within one table.

Earlier numbers from 17:16 CST, for reference:

| dataset | 182fe68 (tag index) | 755e00d (+ WAL shim) | 0dc4ea3 | 0dc4ea3 `search = 0` |
|---|---|---|---|---|
| ev1500k | 39,754 | 53,618 | 29,847 | 52,211 |
| ev400k_tags | 19,270 | 24,346 | 17,328 | 25,044 |
| ev400k_text | 17,397 | 23,332 | 15,411 | 23,631 |

Fan-out and echo at HEAD only; the d2f276e baselines are in `nips-final-fan.txt` and `nips-final-echo.txt`:

| test | d2f276e baseline | HEAD |
|---|---|---|
| fan-out, 1000 subs | 1.99M/s | 1.99M/s (p50 2.9 ms) |
| fan-out, 5000 subs | 2.50M/s | 2.50M/s (p50 15.3 ms) |
| uncapped fan2, 1000 subs × 4000 ev/s | – | 3.98M/s delivered (p50 4.2 ms, p99 26.7 ms) |
| 50k idle | 650 B/conn | 666 B/conn |
| echo 64 B | 3.17M/s | 3.15M/s |
| echo 4 KB | ~1.61M/s | 1.59M/s |

Gate at d8d8a31 (`perf2-gate.txt`, 18:27-18:44 CST): all checks pass.

| check | result |
|---|---|
| gcc / clang strict | 0 warnings |
| cppcheck | 0 findings |
| full suite | nips 205/205 |
| C tests | 11/11 |
| ASan+UBSan | suite and C tests, 0 reports |
| TSan | suite, 0 reports |

Method:
1. Read the code (file:function references below).
2. Run live probes against a throwaway relay (`SERVICE_URL=ws://127.0.0.1:7460 build/main --port 7460 --db /tmp/nipchk.sqlite`), using the probe scripts in `/tmp/nipchk/chk*.py`, which are not in the repo.
3. Get SQLite `EXPLAIN QUERY PLAN` output for the generated SQL.

"Verified" means a live probe observed the behavior. "Code" means I only read the code. Uncertain items are marked **(?)**.

## Probe results (live)

| Probe | Result |
|---|---|
| NIP-11 `GET /` with `Accept: application/nostr+json` | 200, `application/nostr+json`, CORS headers present. Body: `name`, `supported_nips:[1,9,11,13,16,17,26,33,40,42,45,62]`, `limitation{max_message_length:5242880, max_subscriptions:20, max_filters:10, max_subid_length:100, max_event_tags:100, max_content_length:16384, max_limit:500, default_limit:500, created_at_upper_limit:900, auth_required:false}` |
| kind 0 twice, then an older one | newest kept; the older one gets `OK true "duplicate: have this or a newer version"`; REQ returns only the newest ✅ |
| kind 30023 with the same `d`, twice | newest kept ✅ |
| kind 5 with an `e` target | target gone; republishing it gets `OK false "blocked: this event was deleted by its author"`; the kind 5 is still served ✅ |
| kind 5 with an `a` target (`30023:pk:x`) | addressable target gone ✅ |
| COUNT | `["COUNT","c1",{"count":3}]` ✅ |
| Ephemeral kind 20001 | broadcast live, not stored ✅ |
| `["-"]` event without AUTH | `OK false "auth-required: ..."` ✅ |
| AUTH (kind 22242) with the correct relay and challenge, then REQ kind 1059 `#p` = self | delivered ✅ |
| **`#p` filter vs tag `["p",<pk>,"wss://relay.example"]`** | **NOT matched** ❌ (only 2-element tags match) |
| **`#e` filter vs tag `["e",<id>,"","reply"]`** | **NOT matched** ❌ |
| **`limit:0`** | **returned 3 stored events** ❌ (NIP-01: MUST NOT return stored events) |
| **kind 3 with 101 `p` tags** | **`NOTICE "error: invalid event"`, no OK** ❌ (100 works) |
| **content of 20,000 chars (kind 30023)** | `OK false "invalid: content too large"` (16 KiB cap) ⚠️ |
| REQ with 5 filters × 256 authors (1280 > 1024 cap) | **`EOSE` only, no `CLOSED`** ❌ (log: `REQ too complex`) |
| Unauthenticated COUNT of kind 1059 `#p` | **returns the real count (1)** ⚠️ metadata leak (REQ correctly returns nothing) |
| Unauthenticated REQ for kind 1059 | AUTH challenge then `["EOSE","g"]`; no NIP-67 `["auth"]` hint, although nip17.c says otherwise |
| Recipient (p-tag) sends kind 5 for a gift wrap | gift wrap **still served** ⚠️ (NIP-59 SHOULD delete) |
| kind 62 vanish, then republish an old event | rows deleted; republishing gets `OK true "duplicate: already have this event"` from the dedupe cache. Not re-stored *now*, but nothing durable blocks it (see NIP-62) ⚠️ |
| `search:"hello"` vs content "Hello World…" | no match; `"Hello"` matches. Case-sensitive substring ⚠️ |
| `NEG-OPEN` | `NOTICE "error: invalid request"` (NIP-77 absent) |
| Same `created_at` tie | not ordered by lowest id first (NIP-01 SHOULD) — minor |
| kinds 6, 7, 16, 1111, 9735, 10002, 10050, 1059 | all accepted ✅ |
| Query plan of the `#tag` filter | `SCAN event USING INDEX timeidx`: no tag index, a scan in time order plus `LIKE` on the tags JSON |

## Tier (a): must-have for a functional social relay

These items break mainstream clients today. Most are NIP-01 core bugs, not new NIPs.

| # | NIP / item | Status | Evidence | What's missing | Effort | Perf / scale (single-writer SQLite) |
|---|---|---|---|---|---|---|
| A1 | [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) `#tag` filters | **broken (partial)** | `src/storage_query.c:sq_tag_value` builds `LIKE '%["p","<v>"]%'` (and a spaced variant), so the value must be followed by `"]`. Tags carrying a relay hint or marker never match in stored queries. The live path (`relay_core.c:matches_filter` → `tags_have`) is correct, so stored and live results disagree. | Clients put relay hints and markers on `e`/`p`/`a`/`q` tags (NIP-10, 18, 22, 25, 57). Replies, mentions, notifications, reactions and zap lookups by `#e`/`#p` silently miss most real events. Fix: a normalized `tag(event_rowid, name, value, created_at)` table, filled in `storage_write.c` on insert (single-letter tag names only, per NIP-01 indexing), with index `(name, value, created_at DESC)`; `sq_build` uses `id IN (SELECT …)` / a JOIN. Also cascade deletes for NIP-09, 40 and 62. | M (2–4 d incl. migration and backfill of existing DBs) | **Biggest scale item.** Today a rare-tag query (notifications for a small account) is a full table walk in time order: O(N) per REQ on the read side. The index table makes it O(log N + k). It costs about 1 extra row per indexed tag per write (about 3–10× rows; kind 3 can carry 1000s). The single writer absorbs this inside the existing batched transaction. Expect publish throughput to drop measurably (my estimate: 20–40% at 45k ev/s, **re-benchmark**), and the DB to grow ~1.5–2×. Could restrict indexing to single-letter tags and cap per-event indexed tags. |
| A2 | NIP-01 `limit:0` | **wrong** | `json_util.c:json_parse_filter` keeps 0, but `storage_read.c:ngdb_send_records` (`limit > 0 && < 500 ? limit : 500`) turns 0 into 500. | Skip the stored query for `limit==0`, then send EOSE and keep the sub live. | XS (<1 h + test) | Saves work: clients use `limit:0` for live-only subs, which currently trigger up to 500-row reads. |
| A3 | NIP-01 tag count / event size (kind 3 follow lists, 10000/30000 lists) | **too strict** | `json_util.c:validate_event_tags` hard-codes `++tag_count > 100`; `nostrogotho.h MAX_TAGS_SIZE 65536`; `json_util.h NG_EVENT_JSON_MAX 65536`; `relay_core.c MAX_EVENT_TAGS 100`. Verified: a kind 3 with 101 follows is rejected. | Typical follow lists hold hundreds to thousands of `p` tags (2000 follows ≈ 150 KB). Raise the tag count (2,000–10,000) and the event JSON / tags caps (256–512 KiB is common), or make them configurable per kind. Keep NIP-11 `max_event_tags`/`max_message_length` truthful (today NIP-11 says 100 but the 100 in json_util is a separate literal). | S (0.5–1 d; touches the parse buffers' sizing assumptions, so re-run ASan and the fuzz/overload tests) | Larger events mean bigger writer batches and fan-out copies. Kind 3/10002 are replaceable, so the stored count stays bounded per user. Watch the per-REQ byte budget (`query_bytes_max`) and per-connection output limits. |
| A4 | NIP-01 OK for malformed or over-limit events | **partial** | `relay_core.c:handle_event` answers parse failures with `NOTICE "error: invalid event"`. | When the `id` is extractable, reply `["OK",id,false,"invalid: <reason>"]` (too many tags, too large, bad sig). Clients wait on the OK and otherwise time out (Damus/Amethyst show "failed / pending"). | S | none |
| A5 | NIP-01 CLOSED on rejected queries (known issue) | **wrong** | `storage_read.c:ngdb_send_records` returns false on the complexity caps (SR_MAX_TOTAL_AUTHORS 1024, SR_MAX_FILTER_ITEMS, SQ_MAX_SQL/PARAMS). `relay_core.c:query_events` ignores that and sends EOSE (verified: 1280 authors → EOSE). | Send `["CLOSED",sub,"error: query too complex"]` (or `invalid:`), and remove the live sub. Pre-validate in `handle_req` so the sub is never registered. | S | none. Big-follow-list home feeds (≥1024 authors) are **common**, so consider raising the cap and/or splitting the authors across queries instead of rejecting. |
| A6 | [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) limits vs real clients | **partial** | `relay_core.c MAX_SUBSCRIPTIONS 20`, `MAX_FILTERS 10`; `json_util.c` caps authors/ids/kinds at 256 per filter. | Coracle, nostrudel and Amethyst open many concurrent subs (often 20–50+) and send home-feed filters with 500–2000 authors. Raise to ~50–100 subs per connection and ~2000 authors per filter, or chunk. Today the `CLOSED "too many subscriptions"` path works correctly. | S | More subs per connection mean more index entries in the shard sub index and more fan-out matching. Benchmarked fan-out (4M deliveries/s at 1k subs) has headroom; re-measure at 50 subs × N conns. |
| A7 | [NIP-11](https://github.com/nostr-protocol/nips/blob/master/11.md) document | **partial** | `src/nips/nip11.c:nip11_information_document`; `backend_ngws.c:on_http` (Accept detection and CORS ✅). | `description`, `pubkey`, `contact`, `software`, `version`, `icon`, `self`, `restricted_writes`, `payment_required`, `terms_of_service`, configurable via config/env. Fix `supported_nips` (16 and 33 are merged into 01; 26 is **unrecommended**; add 70, which is implemented; only add 50 after B1). Fixed 1 KiB buffer: grow it. | S | none |
| A8 | [NIP-09](https://github.com/nostr-protocol/nips/blob/master/09.md) deletion | **done** (minor gaps) | `src/nips/nip09.c:delete_e_target`/`delete_a_target`/`kind_is_requested`/`deletion_authorized`; tombstones (`deleted_event`) block republish (verified). | Deletion by the p-tagged recipient of a kind 1059 (NIP-59, see B3). The `a` deletion ignores the `d` part when it is empty, which is fine. | – | Tombstone table grows forever (index on id): fine. |
| A9 | [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) AUTH | **done** | `src/nips/nip42.c:nip42_authenticate` (kind 22242, ±600 s, challenge, relay tag compare with trailing-slash normalization), `nip42_plugin_on_connect` sends the challenge, `nip42_plugin_on_message`. Verified. | (1) If `SERVICE_URL` is unset, every AUTH fails (`nip_event_has_relay_tag` with an empty URL). Document it as a required setting or derive it from the Host header. (2) Failure reason `"error: failed to authenticate"` should use the `invalid:`/`restricted:` prefixes. (3) Only one pubkey per connection (spec allows several): acceptable. | XS | none |
| A10 | NIP-01 replaceable / addressable / ephemeral | **done** | `src/nips/nip01.c:nip01_replaceable_listener` (0, 3, 10000–19999), `nip01_addressable_listener` (30000–39999, missing `d` treated as ""), `nip01_dispatch_event` (20000–29999 not stored). Verified. | Equal-`created_at` tie-break by lowest id (spec) **(?) not checked in `replaceable_admit`**. | XS | – |
| A11 | NIP-01 since/until/ids/authors/kinds, REQ/CLOSE/EOSE/OK/NOTICE | **done** | `json_util.c:json_parse_filter`, `storage_query.c:sq_build`, `relay_core.c:handle_req`/`relay_core_on_message`/`remove_subscriptions`. Ordering is `created_at DESC` only (no id tie-break, minor). Note: `since:0` / `until:0` are treated as "absent" (`if (f->since > 0)`): harmless. | tie-break | XS | – |
| A12 | [NIP-65](https://github.com/nostr-protocol/nips/blob/master/65.md) kind 10002 | **done** (nothing relay-side) | Stored as generic replaceable (verified OK). Outbox-model clients query `{"kinds":[10002],"authors":[…many]}`, which hits A6's author cap and A5. | Covered by A5/A6. | – | `pubkindidx(pubkey,kind)` serves it well. |

## Tier (b): strongly expected by major clients (Damus, Amethyst, Primal, Coracle, nostrudel)

| # | NIP | Status | Evidence | What's missing | Effort | Perf / scale |
|---|---|---|---|---|---|---|
| B1 | [NIP-50](https://github.com/nostr-protocol/nips/blob/master/50.md) search | **partial (undeclared)** | `json_util.c:json_parse_filter` parses `search`; `storage_query.c:sq_build` uses `content LIKE %q%`; `relay_core.c:matches_filter` → `jl_str_contains` (case-sensitive). Verified case-sensitive. Not in `supported_nips`. | Tokenized, case-insensitive matching; ignore `key:value` extensions (today `include:spam` is searched literally); relevance ordering (spec: results by relevance, not `created_at`). Use SQLite **FTS5** (external-content table on `event`) and keep live matching consistent. | M (2–3 d) | `LIKE %q%` is a full scan (verified plan) and a cheap DoS vector: gate it or add FTS5. FTS5 adds writer work per event (index the content of kinds 0, 1, 30023 only) and ~30–50% DB size for those kinds **(estimate)**. |
| B2 | [NIP-45](https://github.com/nostr-protocol/nips/blob/master/45.md) COUNT | **partial** | `relay_core.c:handle_req(do_count)` → `query_events`; `src/nips/nip45.c:nip45_build_count_response`. Verified. | (1) COUNT ignores `can_deliver`, so it leaks kind 1059 counts to unauthenticated clients (verified): apply the NIP-17 rule (refuse with `CLOSED "auth-required:"` or count only events delivered to the AUTH'd pubkey). (2) Optional `hll` (spec section on HyperLogLog, used by clients for reaction/follower counts across relays). (3) COUNT uses the same broken tag SQL (A1): follower counts via `#p` on kind 3 are wrong today. | S (leak) + M (hll) | `COUNT(id)` over a `#p` lookup is cheap only once A1 exists. HLL needs a pass over matched pubkeys (bounded register array of 256 bytes). |
| B3 | [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) / [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) DMs | **mostly done** | `src/nips/nip17.c:nip17_can_deliver` gates 1059/21059 to the p-tagged AUTH'd pubkey (verified both ways); `nip17_plugin_eose_auth_hint` sends AUTH. kind 10050 accepted. | (1) COUNT leak (B2). (2) NIP-59: delete kind 1059 when the **p-tagged recipient** issues kind 5 (verified not done; `nip09.c:deletion_authorized` checks author/delegation only). (3) The NIP-67 `["EOSE",sub,["auth"]]` hint, which the code comment claims but `relay_core.c:query_events` deliberately emits plain EOSE (optional, draft NIP). (4) Gift wraps carry `created_at` up to 2 days in the past: OK (no lower limit by default). | S | `#p` on 1059 depends on A1 for efficient inbox queries. |
| B4 | [NIP-70](https://github.com/nostr-protocol/nips/blob/master/70.md) protected events | **done (undeclared)** | `src/nips/nip42.c:nip42_plugin_accept_publish` rejects `["-"]` unless AUTH'd pubkey == author (verified). | Add 70 to `supported_nips`. Optional: reject reposts (kind 6/16) that embed a protected event (spec SHOULD). | XS | – |
| B5 | [NIP-62](https://github.com/nostr-protocol/nips/blob/master/62.md) vanish | **partial** | `src/nips/nip62.c:nip62_listener` → `delete_all_events_by_pubkey`; `ALL_RELAYS` or own URL. | Spec MUST: "ensure the deleted events cannot be re-broadcasted". Today only the in-memory dedupe cache (`NG_DEDUPE_RECENT`, 131072 ids, lost on restart) prevents it. Store a durable per-pubkey "vanished before T" marker and reject pubkey events with `created_at <= T` in `nip01_dispatch_event`. SHOULD: delete kind 1059 p-tagging the pubkey (needs A1). | S | One indexed lookup per write (cache in memory, since the table is tiny). The mass delete runs inside one writer transaction and can stall the writer for large accounts: chunk it. |
| B6 | [NIP-40](https://github.com/nostr-protocol/nips/blob/master/40.md) expiration | **done** | `src/nips/nip40.c:nip40_accept_publish` (reject expired), `nip40_can_deliver`, `nip40_plugin_timer` → `purge_expired` every 60 s. | – | – | `purge_expired` runs on the writer. Make sure it is indexed (an `expiration` column/index) **(?) not verified**. |
| B7 | NIP-01 limits vs content | **too strict** | `relay_core.c MAX_EVENT_CONTENT_LENGTH (16*1024)` | [NIP-23](https://github.com/nostr-protocol/nips/blob/master/23.md) long-form articles (kind 30023, Habla/Yakihonne/Primal reads) often exceed 16 KiB. Raise it to 64–128 KiB, ideally per kind. | XS | Same as A3. |
| B8 | [NIP-18](https://github.com/nostr-protocol/nips/blob/master/18.md), [NIP-22](https://github.com/nostr-protocol/nips/blob/master/22.md), [NIP-25](https://github.com/nostr-protocol/nips/blob/master/25.md), [NIP-57](https://github.com/nostr-protocol/nips/blob/master/57.md) | **no blocker** besides A1/A3 | kinds 6, 16, 7, 1111, 9735 accepted (verified). Uppercase tag filters (`#E`, `#K` for NIP-22) work. | They depend on A1 (all reference events via `e`/`p`/`a`/`E`/`P` tags, usually with hints) and A3 (kind 6 embeds the reposted JSON in content; zap receipts embed the zap request in `description`, usually < 16 KiB). | – | Reactions (kind 7) are the highest-volume kind on social relays. `#e` lookups per note make A1's index essential. |
| B9 | [NIP-13](https://github.com/nostr-protocol/nips/blob/master/13.md) PoW | **done** | `src/nips/nip13.c:nip13_accept_publish` (min difficulty via `MIN_POW_DIFFICULTY`, honors a committed `nonce` target), `pow:` prefix. Default 0, i.e. off. | Policy only: keep it off for social (no mainstream client mines PoW by default). | – | cheap (bit count on the id). |
| B10 | Anti-spam / write policy (not a NIP, but required in practice) | **missing** | There is overload shedding (`backend_ngws.c` admission, `tests/test_overload.py`) but no per-IP/per-pubkey rate limits, no allow/deny lists, no kind allowlist. | `rate-limited:` OK/CLOSED with a retry-after param (NIP-01 now defines the params element), pubkey/IP bans, and kind allowlists. Feeds B11. | M | Do the checks on the workers (`accept_publish` hook) to keep the writer free. |
| B11 | ~~[NIP-86](https://github.com/nostr-protocol/nips/blob/master/86.md) management API~~ | **intentionally out of scope** (owner decision) | `backend_ngws.c:on_http` answers only GET/OPTIONS (POST → 405). | JSON-RPC over HTTP POST with `Content-Type: application/nostr+json+rpc` and [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) `Authorization` (signed kind 27235 with `payload` hash). Methods: `supportedmethods`, `banpubkey`, `allowpubkey`, `listbannedpubkeys`, `banevent`, `allowevent`, `listbannedevents`, `changerelayname/description/icon`, `allowkind`/`disallowkind`, `blockip`/`unblockip`, etc. Needs B10's policy tables. Used by relay-admin UIs (e.g. relay.tools, Coracle/Flotilla admin) **(?) client adoption is moderate**. | M (2–4 d) | Ban lookups belong in in-memory sets checked on the workers. Writes to the policy tables go through the single writer (low volume). |

## Tier (c): optional / nice-to-have

| NIP | Status | Notes / effort / perf |
|---|---|---|
| ~~[NIP-77](https://github.com/nostr-protocol/nips/blob/master/77.md) Negentropy~~ | **intentionally out of scope** (owner decision, 2026-11-10) | Not implemented by design. Original notes: Used by strfry-to-strfry sync and some clients (Amethyst and nostrudel have experimented) **(?) adoption**. Effort M–L (3–5 d; vendor a C negentropy implementation or port the reference, plus an id+created_at range scan). Perf: per-session memory for the sorted (created_at, id) set, capped by a max-records limit. Read-only, so the writer is unaffected. |
| [NIP-29](https://github.com/nostr-protocol/nips/blob/master/29.md) relay-based groups | missing at baseline, **done** (see Final status) | A large feature: `h`-tag enforcement, membership/roles state, moderation kinds 9000–9020, join/leave 9021/9022, relay-signed 39000–39003 metadata (needs a relay keypair and NIP-11 `self`), late-publication/timeline-ref checks, read gating. Effort L (1–2 wk). Only needed if you target Flotilla/Chachi/0xchat groups. Perf: group state checks on every write in a group (in-memory cache; the writer signs metadata events). |
| [NIP-43](https://github.com/nostr-protocol/nips/blob/master/43.md) relay access metadata/requests | missing at baseline, **done** (see Final status) | Only for membership/paid relays. S–M. |
| [NIP-67](https://github.com/nostr-protocol/nips/blob/master/67.md) EOSE completeness hint (draft) | not emitted at baseline, **done** (see Final status) | `finish`/`auth` hints are cheap (S). `more` needs an extra-row probe (`LIMIT n+1`). |
| [NIP-66](https://github.com/nostr-protocol/nips/blob/master/66.md) relay discovery | n/a (relay-side nothing required) | Monitors read NIP-11; A7 helps. |
| [NIP-26](https://github.com/nostr-protocol/nips/blob/master/26.md) delegation | implemented (`src/nips/nip26.c`, delegation table, `authors` OR-join) | **Unrecommended** in the official index. Consider dropping it from `supported_nips` and the authors query path: every `authors` filter pays an extra `OR pubkey IN (SELECT … FROM delegation)` subquery. |
| NIP-11 pay-to-relay fields (`fees`, `payments_url`) | missing | Only for paid relays. |
| Search extensions (`language:`, `domain:`, `nsfw:`) | missing | After B1. |

## Recommended order

1. **A1** tag index table (fixes replies, mentions, notifications, reactions, zaps and COUNT accuracy; the largest scale win and the largest write cost), then re-run the perf gate.
2. **A2, A3, A4, A5, A6, B7**: small, high-impact limit and semantics fixes (about 1–2 days together).
3. **A7** NIP-11 metadata, plus **B4** declaration and **B2/B3** gift-wrap leaks, then **B5** durable vanish.
4. **B1** FTS5 search, **B10** policy (NIP-86 is out of scope).
5. Tier (c) as product needs dictate (NIP-77 if syncing with other relays; NIP-29 only for groups).

## Single-writer SQLite notes

- Reads already run off the writer (WAL). A1 and B1 move cost from O(N) reads to O(rows) extra writes on the one writer thread. That is the right trade for a social relay (read-heavy, ~10–100 reads per write), but it lowers the 45k ev/s publish ceiling. Keep the tag index to single-letter names and consider a per-event cap on indexed tags (e.g. first 2,000) to bound the worst case from huge kind 3 lists.
- Mass deletes (NIP-62, large NIP-09 `a` deletes, NIP-40 purge) run inside writer transactions. Chunk them (e.g. 5k rows per batch) so publish latency stays bounded.
- Raising A3/A6 caps increases per-REQ SQL size (`SQ_MAX_SQL 256 KiB`, `SQ_MAX_PARAMS 4096`): 2000 authors fit. Beyond that, split into several queries and merge by `created_at`.
