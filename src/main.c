#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "crypto.h"
#include "relay/relay.h"
#include "transport/server.h"
#include "storage.h"
#include "nhr.h"
#include "log.h"

static storage_context_t storage_ctx = {0};

static bool parse_int(const char *text, int *value) {
    char *end;
    long parsed;
    if (!text || !*text) return false;
    parsed = strtol(text, &end, 10);
    if (*end || parsed < INT_MIN || parsed > INT_MAX) return false;
    *value = (int) parsed;
    return true;
}

static void sigint_handler(int sig) {
    (void)sig;
    /* Note: relay_stop would need a global relay reference or signal-safe way to stop */
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [-database path] [-port num] [-service-url url] [--debug[=LEVEL]] [--config path] [--help]\n", prog_name);
    printf("  --config path                  Config file (default: ./config.json; created with defaults if missing)\n");
    printf("  -database path                 SQLite database (default: ./nostrogotho.sqlite)\n");
    printf("  -port num                      WebSocket port (default: 7447)\n");
    printf("  -service-url url               Public relay URL for NIP-42/NIP-62\n");
    printf("  --debug[=LEVEL]                Set debug verbosity level (0=ERROR only, 1=+WARN, 2=+INFO, 3=all)\n");
    printf("  --hot-reload                   Load relay policy from a reloadable module\n");
    printf("  --module path                  Module path (default: build/nostrogotho.so/.dll)\n");
    printf("  -min-pow bits                  Minimum NIP-13 difficulty\n");
    printf("  -created-at-lower-limit sec    Maximum accepted age, 0 disables\n");
    printf("  -created-at-upper-limit sec    Maximum accepted future offset, 0 disables\n");
    printf("  --help       Show this help message\n");
}

static bool parse_debug_level(const char *arg, log_verbosity_t *verbosity) {
    if (!arg) {
        *verbosity = LOG_VERBOSITY_DEBUG; /* --debug without value defaults to level 3 */
        return true;
    }
    int level = atoi(arg);
    if (level < 0 || level > 3) {
        return false;
    }
    *verbosity = (log_verbosity_t)level;
    return true;
}

static bool init_storage(const char *db_path) {
    if (!crypto_init()) {
        log_error("MAIN", "INIT", "Failed to initialize crypto");
        return false;
    }

    storage_context_init_sqlite3(&storage_ctx);
    if (!storage_ctx.init ||
        !storage_ctx.init(db_path ? db_path : "./nostrogotho.sqlite")) {
        log_error("MAIN", "INIT", "Failed to initialize SQLite storage");
        crypto_deinit();
        return false;
    }

    return true;
}

static void cleanup(void) {
    if (storage_ctx.deinit) {
        storage_ctx.deinit();
    }
    crypto_deinit();
}

int main(int argc, const char **argv) {
    /* Layer 1: compiled defaults. */
    relay_config_t config;
    relay_config_init(&config);

    /* Layer 2: config file (created with defaults when missing). */
    const char *config_path = getenv("CONFIG_PATH");
    const char *cli_config_path = NULL;
    const char *cli_db = NULL;
    const char *cli_service_url = NULL;
    const char *cli_module = NULL;
    bool cli_hot_reload = false;
    bool cli_min_pow = false, cli_lower = false, cli_upper = false;
    int cli_port = 0, cli_pow = 0, cli_low = 0, cli_up = 0;
    bool cli_debug = false;
    log_verbosity_t cli_verbosity = LOG_VERBOSITY_QUIET;
    int env_overrides = 0, cli_overrides = 0;
    char errbuf[256];
    bool file_loaded;
    int tmp;

    /* Pass 1: CLI scan (collect; apply after file so CLI wins). */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            cli_config_path = argv[++i];
        } else if ((strcmp(argv[i], "--db") == 0 || strcmp(argv[i], "-database") == 0) && i + 1 < argc) {
            cli_db = argv[++i];
        } else if ((strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-port") == 0) && i + 1 < argc) {
            if (!parse_int(argv[++i], &cli_port)) {
                log_error("MAIN", "CONFIG", "Invalid port number: %s", argv[i]);
                return 1;
            }
            cli_overrides++;
        } else if (strcmp(argv[i], "-service-url") == 0 && i + 1 < argc) {
            cli_service_url = argv[++i];
        } else if (strncmp(argv[i], "--debug", 7) == 0) {
            const char *level_arg = NULL;
            if (argv[i][7] == '=') {
                level_arg = argv[i] + 8;
            } else if (argv[i][7] == '\0') {
                level_arg = NULL;
            } else {
                log_error("MAIN", "CONFIG", "Unknown option: %s", argv[i]);
                return 1;
            }
            if (!parse_debug_level(level_arg, &cli_verbosity)) {
                log_error("MAIN", "CONFIG", "Invalid debug level: %s (must be 0-3)", level_arg ? level_arg : "missing");
                return 1;
            }
            cli_debug = true;
        } else if (strcmp(argv[i], "--hot-reload") == 0) {
            cli_hot_reload = true;
        } else if (strcmp(argv[i], "--module") == 0 && i + 1 < argc) {
            cli_module = argv[++i];
        } else if (strcmp(argv[i], "-min-pow") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &cli_pow)) return 1;
            cli_min_pow = true;
        } else if (strcmp(argv[i], "-created-at-lower-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &cli_low)) return 1;
            cli_lower = true;
        } else if (strcmp(argv[i], "-created-at-upper-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &cli_up)) return 1;
            cli_upper = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            log_error("MAIN", "CONFIG", "Unknown or incomplete option: %s", argv[i]);
            return 1;
        }
    }
    if (cli_db) cli_overrides++;
    if (cli_service_url) cli_overrides++;
    if (cli_debug) cli_overrides++;
    if (cli_hot_reload) cli_overrides++;
    if (cli_module) cli_overrides++;
    if (cli_min_pow) cli_overrides++;
    if (cli_lower) cli_overrides++;
    if (cli_upper) cli_overrides++;

    /* Layer 2: config file (auto-created with defaults when missing). */
    if (!config_path) config_path = "./config.json";
    if (cli_config_path) config_path = cli_config_path;
    {
        FILE *probe = fopen(config_path, "r");
        if (!probe) {
            if (!relay_config_write_defaults(config_path)) {
                log_error("MAIN", "CONFIG", "No config at %s and failed to create defaults", config_path);
                return 1;
            }
            log_info("MAIN", "CONFIG", "Created %s with defaults", config_path);
            file_loaded = false;
        } else {
            fclose(probe);
            if (!relay_config_load(config_path, &config, errbuf, sizeof(errbuf))) {
                log_error("MAIN", "CONFIG", "Invalid config %s: %s", config_path, errbuf);
                return 1;
            }
            file_loaded = true;
        }
    }

    /* Layer 3: environment overrides. */
    {
        const char *v;
        if ((v = getenv("DATABASE_URL")) && v[0]) {
            snprintf(config.database_path, sizeof(config.database_path), "%s", v);
            env_overrides++;
        }
        if ((v = getenv("SERVICE_URL")) && v[0]) {
            snprintf(config.service_url, sizeof(config.service_url), "%s", v);
            env_overrides++;
        }
        if ((v = getenv("MIN_POW_DIFFICULTY")) && v[0]) {
            if (!parse_int(v, &tmp) || tmp < 0) {
                log_error("MAIN", "CONFIG", "Invalid MIN_POW_DIFFICULTY: %s", v);
                return 1;
            }
            config.min_pow_difficulty = tmp;
            env_overrides++;
        }
        if ((v = getenv("CREATED_AT_LOWER_LIMIT")) && v[0]) {
            if (!parse_int(v, &tmp) || tmp < 0) {
                log_error("MAIN", "CONFIG", "Invalid CREATED_AT_LOWER_LIMIT: %s", v);
                return 1;
            }
            config.created_at_lower_limit = (time_t)tmp;
            env_overrides++;
        }
        if ((v = getenv("CREATED_AT_UPPER_LIMIT")) && v[0]) {
            if (!parse_int(v, &tmp) || tmp < 0) {
                log_error("MAIN", "CONFIG", "Invalid CREATED_AT_UPPER_LIMIT: %s", v);
                return 1;
            }
            config.created_at_upper_limit = (time_t)tmp;
            env_overrides++;
        }
        if ((v = getenv("NHR_MODULE_PATH")) && v[0]) {
            snprintf(config.hot_reload_module_path,
                     sizeof(config.hot_reload_module_path), "%s", v);
            env_overrides++;
        }
        if ((v = getenv("VERBOSITY")) && v[0]) {
            if (!parse_int(v, &tmp)) {
                log_error("MAIN", "CONFIG", "Invalid VERBOSITY: %s", v);
                return 1;
            }
            config.verbosity = tmp;
            env_overrides++;
        }
    }

    /* Layer 4: CLI overrides (highest precedence). */
    if (cli_db) {
        snprintf(config.database_path, sizeof(config.database_path), "%s", cli_db);
    }
    if (cli_port) config.port = cli_port;
    if (cli_service_url) {
        snprintf(config.service_url, sizeof(config.service_url), "%s", cli_service_url);
    }
    if (cli_debug) config.verbosity = (int)cli_verbosity;
    if (cli_hot_reload) config.hot_reload_enabled = true;
    if (cli_module) {
        snprintf(config.hot_reload_module_path,
                 sizeof(config.hot_reload_module_path), "%s", cli_module);
    }
    if (cli_min_pow) config.min_pow_difficulty = cli_pow;
    if (cli_lower) config.created_at_lower_limit = (time_t)cli_low;
    if (cli_upper) config.created_at_upper_limit = (time_t)cli_up;

    /* Validation gate: fail fast before touching storage or sockets. */
    if (!relay_config_validate(&config, errbuf, sizeof(errbuf))) {
        log_error("MAIN", "CONFIG", "Invalid configuration: %s", errbuf);
        return 1;
    }

    log_init();
    log_set_verbosity((log_verbosity_t)config.verbosity);
    if (file_loaded) relay_config_warn_unknown(config_path);
    log_info("MAIN", "CONFIG",
             "path=%s loaded=%s env_overrides=%d cli_overrides=%d port=%d verbosity=%d",
             config_path, file_loaded ? "file" : "defaults-created",
             env_overrides, cli_overrides, config.port, config.verbosity);

    if (!init_storage(config.database_path)) {
        return 1;
    }

    relay_t *relay = relay_create(&config, &storage_ctx);
    if (!relay) {
        log_error("MAIN", "INIT", "Failed to create relay");
        cleanup();
        return 1;
    }

    log_info("MAIN", "STARTUP", "Relay starting on port %d (verbosity=%d)",
             config.port, config.verbosity);

    /* Initialize hot reload if configured */
    if (config.hot_reload_enabled) {
        if (!relay_init_hot_reload(relay, config.hot_reload_module_path)) {
            log_error("MAIN", "HOT_RELOAD", "Failed to initialize hot reload with module: %s", config.hot_reload_module_path);
            relay_destroy(relay);
            cleanup();
            return 1;
        }
        log_info("MAIN", "HOT_RELOAD", "Hot reload enabled, watching module: %s", config.hot_reload_module_path);
    }

    signal(SIGINT, sigint_handler);
    bool result = config.hot_reload_enabled
        ? server_run_hot(config.port, relay, config.hot_reload_module_path)
        : server_run(config.port, relay);
    relay_destroy(relay);
    cleanup();
    return result ? 0 : 1;
}
