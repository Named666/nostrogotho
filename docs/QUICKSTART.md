# Quick Start

## Requirements

- Windows with GCC/MinGW **or** Linux with `gcc` (`gcc --version` works).
- This repo with its vendored `thirdparty/` directory (Mongoose, SQLite
  amalgamation, secp256k1 sources). No `apt-get` step, no system
  `libsqlite3-dev` / `libssl-dev` / `libsecp256k1-dev`.
- Build from the repository root. The two-stage driver is `nob.c`:
  `gcc` builds the driver (`nob.exe` / `nob`), the driver builds
  `build/main.exe` on Windows and `build/main` on Linux.

## Build

From the repository root:

```powershell
# Windows (PowerShell)
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob.exe
.\nob.exe
```

```bash
# Linux (sh)
gcc -std=c99 -Wall -Wextra -Wpedantic nob.c -o nob
./nob
```

What this does (`nob.c` -> `src_build/nob_win.c` /
`src_build/nob_linux.c`, shared logic in `src_build/nob_common.h`):

1. Generates `build/config.h` on first run (optional build switches).
2. Compiles all `src/*.c`, `src/*/*.c`, and `src/nips/*.c`
   (except `src/nips/nip_template.c`) plus vendored sources.
3. Links OS libs: `bcrypt`, `ws2_32`, `winpthread` on Windows;
   `pthread`, `m`, `dl` on Linux.
4. Emits `build/main.exe` (Windows) or `build/main` (Linux).

Other driver modes (`nob [win|linux] [-hr] [-test] [-asan] [-- relay-args...]`;
bare `nob` auto-detects the host OS):

```powershell
# Windows
.\nob.exe -test            # build and run the C + Node suites
.\nob.exe win -hr -- -service-url ws://localhost:7447
                           # hot-reload supervisor: rebuilds the
                           # `build/nostrogotho.dll` policy module on save
                           # without dropping sockets
.\nob.exe --help           # driver usage
```

```bash
# Linux
./nob -test                # build and run the C + Node suites
./nob linux -hr -- -service-url ws://localhost:7447
                           # same supervisor; module is `build/nostrogotho.so`
./nob -asan                # Linux-only ASan+UBSan build (`build/main_asan`)
```

## Start Locally

`build/main(.exe)` reads `relay_config_t` (`src/relay/config.h`, defaults in
`src/relay/config.c`) with precedence:

```
compiled defaults < config file < environment < CLI
```

On first run the relay creates `./config.json` with defaults if it is
missing. The checked-in `config.json` is the canonical example:

```json
{
  "database": "./nostrogotho.sqlite",
  "port": 7447,
  "service_url": "wss://relay.example.com",
  "verbosity": 0,
  "limits": {
    "max_subscriptions_per_connection": 50,
    "max_filters_per_subscription": 10,
    "max_subscription_id_length": 100,
    "max_query_limit": 500,
    "max_event_content_length": 65536,
    "max_event_tags": 100,
    "max_ws_message_length": 5242880,
    "min_pow_difficulty": 0,
    "created_at_lower_limit": 0,
    "created_at_upper_limit": 900
  },
  "hot_reload": {
    "enabled": false,
    "module_path": "build/nostrogotho.dll"
  }
}
```

> `service_url` must be changed from the `wss://relay.example.com`
> placeholder. `relay_config_validate()` (`src/relay/config.c`) rejects an
> empty value and rejects the placeholder itself, because NIP-42
> challenges and NIP-62 vanish targeting depend on it.

Minimal local run (note: use a real URL even locally):

```powershell
# Windows
.\build\main.exe -database .\relay.sqlite -port 7447 -service-url ws://localhost:7447
```

```bash
# Linux
./build/main -database ./relay.sqlite -port 7447 -service-url ws://localhost:7447
```

Inspect the NIP-11 relay information document from another terminal:

```powershell
# Windows
curl.exe -H "Accept: application/nostr+json" http://localhost:7447/
```

```bash
# Linux
curl -H "Accept: application/nostr+json" http://localhost:7447/
```

CLI reference (`src/main.c:print_usage`, `parse_int`, env block;
same on both OSes, only the binary name changes):

```powershell
.\build\main.exe --help
# Usage: main [-database path] [-port num] [-service-url url] [--debug[=LEVEL]] [--config path] [--help]
#   --config path                  Config file (default: ./config.json; created with defaults if missing)
#   -database path / --db path     SQLite database (default: ./nostrogotho.sqlite)
#   -port num / --port num          WebSocket port (default: 7447)
#   -service-url url               Public relay URL for NIP-42/NIP-62
#   --debug[=LEVEL]                0=ERROR only, 1=+WARN, 2=+INFO, 3=all (default when bare: 3)
#   --hot-reload                   Load relay policy from a reloadable module
#   --module path                  Module path (default: build/nostrogotho.dll on Windows, build/nostrogotho.so on Linux)
#   -min-pow bits                  Minimum NIP-13 difficulty (default: 0 = disabled)
#   -created-at-lower-limit sec    Maximum accepted event age, 0 disables (default: 0)
#   -created-at-upper-limit sec    Maximum accepted future offset, 0 disables (default: 900)
```

Environment overrides (layer 3, applied after the file, before CLI):

| Env var | Maps to |
|---|---|
| `CONFIG_PATH` | config file path (or pass `--config`) |
| `DATABASE_URL` | `database_path` |
| `SERVICE_URL` | `service_url` |
| `MIN_POW_DIFFICULTY` | `min_pow_difficulty` |
| `CREATED_AT_LOWER_LIMIT` | `created_at_lower_limit` |
| `CREATED_AT_UPPER_LIMIT` | `created_at_upper_limit` |
| `NHR_MODULE_PATH` | `hot_reload_module_path` |
| `VERBOSITY` | `verbosity` (0-3, see `src/log.h:log_verbosity_t`) |

`--debug` and `VERBOSITY` write the same field. Startup logs the resolved
source mix (`src/main.c`):

```
path=./config.json loaded=file env_overrides=0 cli_overrides=2 port=7447 verbosity=0
```

Unknown `config.json` keys are ignored with a `WARN` after verbosity is set
(`relay_config_warn_unknown()` in `src/relay/config_file.c`); wrong-type
values are hard errors naming the field.

## Public Deployment

Use a reverse proxy to terminate TLS and expose a `wss://` URL. Pass exactly
that public URL through `-service-url` (or `SERVICE_URL` / `service_url` in
`config.json`); it is required for clients using NIP-42 authentication and
relay-targeted NIP-62 vanish requests. Persist the database outside transient
directories and include it in backups.

Example environment configuration:

```powershell
# Windows
$env:DATABASE_URL = "C:\relay-data\nostr.sqlite"
$env:SERVICE_URL = "wss://relay.example.com"
$env:MIN_POW_DIFFICULTY = "16"
$env:CREATED_AT_UPPER_LIMIT = "900"
.\build\main.exe
```

```bash
# Linux
export DATABASE_URL="/var/lib/nostr/nostr.sqlite"
export SERVICE_URL="wss://relay.example.com"
export MIN_POW_DIFFICULTY="16"
export CREATED_AT_UPPER_LIMIT="900"
./build/main
```

## Validate A Change

```powershell
# Windows
.\nob.exe -test
git diff --check
```

```bash
# Linux
./nob -test
git diff --check
```

`-test` builds and runs the C suite (`src_build/nob_common.h`,
`NOB_TEST_EXE`) plus the Node suites (`tests/test_*.js`; needs Node 18+ on
`PATH`). `git diff --check` catches whitespace errors before a
commit. For logging while debugging, rerun with `--debug` (level 3) or
`--debug=2`:

```powershell
# Windows
.\build\main.exe --debug=2 -service-url ws://localhost:7447
```

```bash
# Linux
./build/main --debug=2 -service-url ws://localhost:7447
```

Check the database with SQLite (table is `event`, tag index is
`event_tag_index` — see `docs/NOSTR_EVENT_STORAGE_SPEC.md`):

```powershell
sqlite3 nostrogotho.sqlite ".schema"
sqlite3 nostrogotho.sqlite "SELECT id, pubkey, created_at, kind FROM event LIMIT 10;"
```

## Next Steps

1. **Configure:** `docs/INDEX.md` "Build Configuration" for every
   `relay_config_t` field and its default (`src/relay/config.c`).
2. **Extend:** `docs/nip_development_workflow.md` for adding a NIP via
   `src/nips/nip_template.c` + `nip_capability.h` (copy file, rename
   `nipxx_` symbols, keep only needed caps, rebuild — no registry edits).
3. **Store/query:** `docs/NOSTR_EVENT_STORAGE_SPEC.md` for
   `storage_event_scope_t` + `find/count/delete/upsert` (`src/storage.h`).
4. **Tags:** `docs/event_api_design.md` + `src/protocol/event_tags.h`
   (`event_tag_get`, `event_tag_get_all`, `event_tag_value`,
   `event_tag_has*`, `event_tag_count`).
5. **Wire:** `src/protocol/protocol.h`
   (`protocol_parse_client_message`, `protocol_serialize_ok/event/eose/
   count/closed/notice/auth`, `protocol_message_free`).
6. **Reference:** `docs/API_REFERENCE.md` for the full C surface.