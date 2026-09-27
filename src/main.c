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

static bool init_storage(const char *db_path) {
    if (!crypto_init()) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return false;
    }

    storage_context_init_sqlite3(&storage_ctx);
    if (!storage_ctx.init ||
        !storage_ctx.init(db_path ? db_path : "./nostrogotho.sqlite")) {
        fprintf(stderr, "Failed to initialize SQLite storage\n");
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
    const char *db_path = getenv("DATABASE_URL");
    const char *service_url = getenv("SERVICE_URL");
    int port = 7447;
    int min_pow = 0;
    int lower_limit = 0;
    int upper_limit = 900;
    bool hot_reload = false;
    const char *module_path = getenv("NHR_MODULE_PATH");

    if (!parse_int(getenv("MIN_POW_DIFFICULTY") ? getenv("MIN_POW_DIFFICULTY") : "0", &min_pow) ||
        !parse_int(getenv("CREATED_AT_LOWER_LIMIT") ? getenv("CREATED_AT_LOWER_LIMIT") : "0", &lower_limit) ||
        !parse_int(getenv("CREATED_AT_UPPER_LIMIT") ? getenv("CREATED_AT_UPPER_LIMIT") : "900", &upper_limit) ||
        min_pow < 0 || lower_limit < 0 || upper_limit < 0) {
        fprintf(stderr, "Invalid relay security-limit environment variable\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--db") == 0 || strcmp(argv[i], "-database") == 0) && i + 1 < argc) {
            db_path = argv[++i];
        } else if ((strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-port") == 0) && i + 1 < argc) {
            if (!parse_int(argv[++i], &port)) return 1;
            if (port < 1 || port > 65535) {
                fprintf(stderr, "Invalid port number: %d (must be 1-65535)\n", port);
                return 1;
            }
        } else if (strcmp(argv[i], "-service-url") == 0 && i + 1 < argc) {
            service_url = argv[++i];
        } else if (strcmp(argv[i], "--debug") == 0) {
            /* debug logging will be set in relay config */
        } else if (strcmp(argv[i], "--hot-reload") == 0) {
            hot_reload = true;
        } else if (strcmp(argv[i], "--module") == 0 && i + 1 < argc) {
            module_path = argv[++i];
        } else if (strcmp(argv[i], "-min-pow") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &min_pow) || min_pow < 0) return 1;
        } else if (strcmp(argv[i], "-created-at-lower-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &lower_limit) || lower_limit < 0) return 1;
        } else if (strcmp(argv[i], "-created-at-upper-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &upper_limit) || upper_limit < 0) return 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-database path] [-port num] [-service-url url] [--debug] [--help]\n", argv[0]);
            printf("  -database path                 SQLite database (default: ./nostrogotho.sqlite)\n");
            printf("  -port num                      WebSocket port (default: 7447)\n");
            printf("  -service-url url               Public relay URL for NIP-42/NIP-62\n");
            printf("  --debug                        Print connects, disconnects and events to console\n");
            printf("  --hot-reload                   Load relay policy from a reloadable module\n");
            printf("  --module path                  Module path (default: build/nostrogotho.so/.dll)\n");
            printf("  -min-pow bits                  Minimum NIP-13 difficulty\n");
            printf("  -created-at-lower-limit sec    Maximum accepted age, 0 disables\n");
            printf("  -created-at-upper-limit sec    Maximum accepted future offset, 0 disables\n");
            printf("  --help       Show this help message\n");
            return 0;
        } else {
            fprintf(stderr, "Unknown or incomplete option: %s\n", argv[i]);
            return 1;
        }
    }

    if (!init_storage(db_path)) {
        return 1;
    }

    relay_config_t config;
    relay_config_init(&config);
    config.database_path = db_path ? db_path : "./nostrogotho.sqlite";
    config.port = port;
    config.service_url = service_url ? service_url : "";
    config.min_pow_difficulty = min_pow;
    config.created_at_lower_limit = (time_t)lower_limit;
    config.created_at_upper_limit = (time_t)upper_limit;
    config.debug_logging = false; /* TODO: parse --debug flag */

    relay_t *relay = relay_create(&config, &storage_ctx);
    if (!relay) {
        fprintf(stderr, "Failed to create relay\n");
        cleanup();
        return 1;
    }

    /* Initialize hot reload if requested */
    if (hot_reload) {
        const char *mod_path = module_path ? module_path : 
#ifdef _WIN32
            "build/nostrogotho.dll";
#else
            "build/nostrogotho.so";
#endif
        if (!relay_init_hot_reload(relay, mod_path)) {
            fprintf(stderr, "Failed to initialize hot reload with module: %s\n", mod_path);
            relay_destroy(relay);
            cleanup();
            return 1;
        }
        fprintf(stderr, "Hot reload enabled, watching module: %s\n", mod_path);
    }

    signal(SIGINT, sigint_handler);
    bool result = hot_reload
        ? server_run_hot(port, relay, module_path ? module_path :
  #ifdef _WIN32
          "build/nostrogotho.dll"
  #else
          "build/nostrogotho.so"
  #endif
        )
        : server_run(port, relay);
    relay_destroy(relay);
    cleanup();
    return result ? 0 : 1;
}
