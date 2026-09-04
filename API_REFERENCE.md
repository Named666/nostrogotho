# C API Reference

Public headers live in [src/nostrogotho.h](src/nostrogotho.h),
[src/crypto.h](src/crypto.h), [src/storage.h](src/storage.h), and
[src/server.h](src/server.h). Headers are authoritative when this guide and
implementation differ.

## Ownership

`event_alloc`, `filter_alloc`, `tag_alloc`, and `tags_array_alloc` return
heap-owned values. Release them with the paired `*_free` function. `string_dup`
returns heap memory released with `string_free` or `free`.

`event_t` owns `tags_json` and `content`. `filter_t` owns its string arrays,
kind array, tags, and `search`. Do not free borrowed SQLite column values.

## Core Types

| Type | Purpose |
| --- | --- |
| `event_t` | Nostr event fields: ID, pubkey, time, kind, tags JSON, content, and signature. |
| `filter_t` | Query fields: ID/author prefixes, kinds, tag filters, time range, limit, and search text. |
| `tag_t` | Owned array of tag strings with `count` and `capacity`. |
| `storage_context_t` | SQLite backend operation table. |

## Crypto

```c
bool crypto_init(void);
void crypto_deinit(void);
bool check_event(const event_t *event);
bool check_delegation(const event_t *event, const char *delegator_pubkey,
                      const char *conditions, const char *delegation_sig);
int count_leading_zero_bits(const char *hex);
```

Call `crypto_init` before `check_event` or signature validation and call
`crypto_deinit` during process shutdown.

## Storage

```c
void storage_context_init_sqlite3(storage_context_t *context);
```

Initialize the context, call `context->init(path)`, use its operation pointers,
then call `context->deinit()`. `get_event_by_id` returns an owned `event_t *`.
`send_records` calls its callback synchronously with `EVENT` or `COUNT` JSON
frames that are valid only for that callback invocation.

## Server

```c
void server_configure(storage_context_t *storage, const char *relay_url,
                      int min_pow_difficulty, time_t lower_limit,
                      time_t upper_limit);
bool server_run(int port);
void server_stop(void);
```

Configure the server after storage initialization. `server_run` blocks until
`server_stop` is called, normally by the signal handler in `main.c`.