# Nostr Protocol Message Types

This document describes the Nostr wire protocol message types as implemented in nostrogotho.

## Message Format

All messages are JSON arrays sent over WebSocket. First element is the message type (string).

---

## Client → Relay

### EVENT

Publish a new event.

```
["EVENT", <event_json>]
```

- `<event_json>`: Full event object (id, pubkey, created_at, kind, tags, content, sig)
- Relay responds with `OK`

### REQ

Request event stream (subscription).

```
["REQ", <subscription_id>, <filter_1>, <filter_2>, ...]
```

- `<subscription_id>`: Client-chosen identifier (string)
- `<filter_N>`: Filter objects (see below)
- Relay responds with zero or more `EVENT` messages, then `EOSE`

### CLOSE

Close an existing subscription.

```
["CLOSE", <subscription_id>]
```

- `<subscription_id>`: ID from REQ
- Relay responds with `CLOSED`

### COUNT

Request event count for filters (NIP-45).

```
["COUNT", <subscription_id>, <filter_1>, <filter_2>, ...]
```

- `<subscription_id>`: Client-chosen identifier (string)
- `<filter_N>`: Filter objects
- Relay responds with `COUNT`

### AUTH

Authenticate with NIP-42.

```
["AUTH", <event_json>]
```

- `<event_json>`: Kind 22242 event with challenge tag
- Relay responds with `OK` (success) or `OK` (failure with reason)

---

## Relay → Client

### EVENT

Event notification for subscription.

```
["EVENT", <subscription_id>, <event_json>]
```

- `<subscription_id>`: From REQ
- `<event_json>`: Full event object

### OK

Response to EVENT or AUTH.

```
["OK", <event_id>, <accepted>, <reason>]
```

- `<event_id>`: Event ID from request
- `<accepted>`: Boolean (true = accepted, false = rejected)
- `<reason>`: Human-readable string (empty on success, error message on failure)

### EOSE

End of Stored Events (NIP-01, NIP-67).

```
["EOSE", <subscription_id>]
```

NIP-67 extended form with completeness hint:

```
["EOSE", <subscription_id>, <hint_array>]
```

- `<hint_array>`: One of `["more"]`, `["finish"]`, `["auth", ...]`

### COUNT

Response to COUNT request (NIP-45).

```
["COUNT", <subscription_id>, {"count": <number>}]
```

- `<subscription_id>`: From COUNT request
- `count`: Total matching events (unsigned integer)

### CLOSED

Subscription closed by relay.

```
["CLOSED", <subscription_id>, <reason>]
```

- `<subscription_id>`: From REQ
- `<reason>`: Human-readable string (e.g., "auth-required", "restricted")

### NOTICE

Human-readable notice (non-fatal).

```
["NOTICE", <message>]
```

### AUTH

Authentication challenge (NIP-42).

```
["AUTH", <challenge>]
```

- `<challenge>`: Random string (should be used in kind 22242 event)

---

## Filter Object

```json
{
  "ids": ["<event_id>", ...],
  "authors": ["<pubkey>", ...],
  "kinds": [<kind>, ...],
  "#<tag_name>": ["<value>", ...],
  "since": <unix_timestamp>,
  "until": <unix_timestamp>,
  "limit": <max_results>,
  "search": "<string>"
}
```

- All fields optional
- Multiple filters in REQ/COUNT are OR'd
- Criteria within one filter are AND'd
- `#<tag_name>` syntax for tag filters (e.g., `#e`, `#p`, `#a`)

---

## Event Object

```json
{
  "id": "<32-byte-hex>",
  "pubkey": "<32-byte-hex>",
  "created_at": <unix_timestamp>,
  "kind": <integer>,
  "tags": [
    ["<tag_name>", "<value1>", "<value2>", ...],
    ...
  ],
  "content": "<string>",
  "sig": "<64-byte-hex>"
}
```

---

## Message Flow Examples

### Basic Publish

```
C: ["EVENT", {"id":"...","pubkey":"...","created_at":123,"kind":1,"tags":[],"content":"hello","sig":"..."}]
S: ["OK", "...", true, ""]
```

### Subscription

```
C: ["REQ", "sub1", {"kinds":[1],"authors":["pk1"]}]
S: ["EVENT", "sub1", {"id":"...","pubkey":"pk1",...}]
S: ["EVENT", "sub1", {"id":"...","pubkey":"pk1",...}]
S: ["EOSE", "sub1"]
```

### Subscription with COUNT

```
C: ["REQ", "sub1", {"kinds":[1]}]
C: ["COUNT", "cnt1", {"kinds":[1]}]
S: ["EVENT", "sub1", {...}]
S: ["EOSE", "sub1"]
S: ["COUNT", "cnt1", {"count":42}]
```

### NIP-42 Authentication

```
S: ["AUTH", "challenge123"]
C: ["AUTH", {"kind":22242,"tags":[["challenge","challenge123"]],...}]
S: ["OK", "event_id", true, ""]
C: ["EVENT", {...}]
S: ["OK", "event_id", true, ""]
```

### Gift Wrap (NIP-17) with Auth Hint (NIP-67)

```
C: ["REQ", "sub1", {"kinds":[1059]}]
S: ["AUTH", "challenge456"]
S: ["EOSE", "sub1", ["auth", "challenge456"]]
```

---

## Error Conditions

| Condition | Response |
|-----------|----------|
| Invalid JSON | `NOTICE` "invalid: malformed JSON" |
| Unknown command | `NOTICE` "invalid: unknown command" |
| EVENT validation fail | `OK` with `accepted=false`, reason |
| REQ too many filters | `CLOSED` "invalid: too many filters" |
| Auth required for kind | `OK` with `accepted=false`, "auth-required: ..." |
| Rate limited | `OK` with `accepted=false`, "rate-limited" |
| PoW insufficient | `OK` with `accepted=false`, "pow: required N bits" |

---

## Implemented NIPs

- **NIP-01**: Basic protocol (EVENT, REQ, CLOSE, EOSE, OK, NOTICE)
- **NIP-09**: Event deletion (kind 5)
- **NIP-11**: Relay info (HTTP endpoint)
- **NIP-13**: Proof of work (PoW on EVENT)
- **NIP-16**: Event treatment (replaceable kinds 0, 3, 10000-19999)
- **NIP-17**: Private DMs (gift-wrap gating + auth hint)
- **NIP-26**: Delegated signing (delegation tag validation)
- **NIP-33**: Parameterized replaceable (addressable kinds 30000-39999)
- **NIP-40**: Expiration timestamp (expiration tag)
- **NIP-42**: Client auth (AUTH, kind 22242)
- **NIP-45**: Event counts (COUNT)
- **NIP-62**: Request to vanish (kind 62)
- **NIP-67**: EOSE hints (more/finish/auth)

---

## See Also

- [Nostr Protocol Spec](https://github.com/nostr-protocol/nostr)
- `docs/API_REFERENCE.md` — C API for protocol parsing/serialization
- `src/protocol/protocol.h` — Implementation headers
- `src/protocol/protocol.c` — Implementation