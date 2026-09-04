# Project Summary

## Project Status

**nostrogotho** — C99 Nostr relay (mongoose + bundled SQLite3 + secp256k1).
Build system: nob (see `nob.c`, config in `src_build/nob_configed.c`).

**2026-09-03 NIP completeness audit: COMPLETE.** All NIPs with reference
specs in `thirdparty/nips/` are implemented and wired; details in
[NOSTR_COMPATABILITY.md](NOSTR_COMPATABILITY.md).

Advertised `supported_nips`: `[1, 9, 11, 13, 16, 17, 26, 33, 40, 42, 45, 62, 67]`.

## Deliverables

- `build/main.exe` — the relay binary (run `.\nob.exe` to rebuild).
- `src/nips/nip01.c` — dispatcher + validation + NIP-16/NIP-33 replaceable /
  addressable handling (consolidated per spec "Moved to NIP-01").
- `src/nips/nip{09,11,13,17,26,40,42,45,62,67}.c` — individual NIP modules.
- `src/storage.c` — SQLite backend; `src/server.c` — mongoose WebSocket server.

## Milestones

| Milestone | Status |
| --------- | ------ |
| NIP-01 core protocol (EVENT/REQ/CLOSE/OK/EOSE/NOTICE) | ✅ |
| NIP-16 + NIP-33 consolidated into NIP-01 (files removed) | ✅ 2026-09-03 |
| NIP-40 expiration wired (accept + query paths) | ✅ 2026-09-03 |
| NIP-45 COUNT response via `nip45_build_count_response` | ✅ 2026-09-03 |
| NIP-11 document generated from real runtime limits | ✅ 2026-09-03 |
| NIP-13 nonce target-commitment validation | ✅ 2026-09-03 |
| NIP-26 delegated-author queries + delegator deletion | ✅ 2026-09-03 |
| NIP-42 `restricted` prefix + challenge regeneration | ✅ 2026-09-03 |
| NIP-67 `auth` hint with preceding AUTH challenge | ✅ 2026-09-03 |
| NIP-62 relay-tag MUST enforcement | ✅ 2026-09-03 |
| Runtime validation (test_ws.py / test_ws2.py / NIP-11 curl) | ✅ 2026-09-03 |

## Next Steps

- [ ] NIP-62: delete gift-wraps (1059/21059) `p`-tagging the vanishing pubkey.
- [ ] NIP-45: optional `approximate` / HyperLogLog `hll` counting.
- [ ] NIP-67: `created_at` boundary-tie advancement in the storage layer.
- [ ] NIP-11: optional metadata (`description`, `software`, `version`,
      `contact`, admin `pubkey`) from configuration.
- [ ] Server configuration file with NIP-11 metadata and relay runtime options / limits.
Example `nostrogotho.config`:

```json
{
  "name": <string identifying relay>,
  "description": <string with detailed information>,
  "banner": <a link to an image (e.g. in .jpg, or .png format)>,
  "icon": <a link to an icon (e.g. in .jpg, or .png format>,
  "pubkey": <administrative contact pubkey>,
  "self": <relay's own pubkey>,
  "contact": <administrative alternate contact>,
  "supported_nips": <a list of NIP numbers supported by the relay>,
  "software": <string identifying relay software URL>,
  "version": <string version identifier>,
  "terms_of_service": <a link to a text file describing the relay's term of service>
}
```
- [ ] Fix pre-existing `crypto.c:485` `%ld` vs `time_t` format warning.
- [ ] Optional background GC for expired (NIP-40) rows.
