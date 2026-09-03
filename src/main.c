#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "server.h"
#include "storage.h"

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
    server_stop();
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
        } else if (strcmp(argv[i], "-service-url") == 0 && i + 1 < argc) {
            service_url = argv[++i];
        } else if (strcmp(argv[i], "-min-pow") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &min_pow) || min_pow < 0) return 1;
        } else if (strcmp(argv[i], "-created-at-lower-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &lower_limit) || lower_limit < 0) return 1;
        } else if (strcmp(argv[i], "-created-at-upper-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &upper_limit) || upper_limit < 0) return 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-database path] [-port num] [-service-url url] [--help]\n", argv[0]);
            printf("  -database path                 SQLite database (default: ./nostrogotho.sqlite)\n");
            printf("  -port num                      WebSocket port (default: 7447)\n");
            printf("  -service-url url               Public relay URL for NIP-42/NIP-62\n");
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

    server_configure(&storage_ctx, service_url ? service_url : "", min_pow,
                     (time_t) lower_limit, (time_t) upper_limit);
    signal(SIGINT, sigint_handler);
    const bool result = server_run(port);
    cleanup();
    return result ? 0 : 1;
}
