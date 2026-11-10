#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "ng_config.h"
#include "crypto.h"
#include "server.h"
#include "storage.h"
#include "ratelimit.h"

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

/* Runtime config (config.h), loaded before opening any database; the
 * result is handed to storage (durability) and the server (everything else). */
static ng_config_t cfg;

static bool load_config(const char *path, bool required) {
    ng_config_error_t err;
    ng_config_defaults(&cfg);
    ng_status_t st = ng_config_load(&cfg, path, required, &err);
    if (st == NG_E_IO && err.line == 0) { perror(path); return false; }
    if (st != NG_OK) {
        fprintf(stderr, "%s:%u: invalid config line%s%s%s: %s (see nostrogotho.conf for keys and values)\n",
                path, err.line, err.key[0] ? " (key '" : "", err.key, err.key[0] ? "')" : "",
                ng_status_str(st));
        return false;
    }
    return true;
}

/* Environment / command-line values override the config file. */
static void apply_config(const char *service_url, int min_pow, int lower_limit, int upper_limit) {
    ng_relay_info_t *info = &cfg.info;
    if (service_url) snprintf(info->relay_url, sizeof(info->relay_url), "%s", service_url);
    if (min_pow >= 0) info->min_pow_difficulty = min_pow;
    if (lower_limit >= 0) info->created_at_lower_limit = lower_limit;
    if (upper_limit >= 0) info->created_at_upper_limit = upper_limit;
    storage_set_sync_full(cfg.db_sync == NG_DB_SYNC_FULL);
    storage_set_search(cfg.limits.search != 0);
    ng_limits_apply(&cfg.limits);
    ng_relay_info_apply(info);
    server_set_config(&cfg);
    if (!info->relay_url[0])
        fprintf(stderr, "warning: relay_url is not set (nostrogotho.conf or SERVICE_URL): NIP-42 AUTH accepts any "
                        "ws(s):// relay tag (the per-connection challenge still binds it to this relay) and NIP-62 "
                        "honors only ALL_RELAYS requests\n");
}

/* Rate limits and bans (ratelimit.h). */
static bool apply_policy(void) {
    const ng_policy_t *p = &cfg.policy;
    rl_config_t rc;
    memset(&rc, 0, sizeof(rc));
    rc.per_min[RL_EVENT_IP] = p->event_ip_per_min;         rc.burst[RL_EVENT_IP] = p->event_ip_burst;
    rc.per_min[RL_EVENT_PUBKEY] = p->event_pubkey_per_min; rc.burst[RL_EVENT_PUBKEY] = p->event_pubkey_burst;
    rc.per_min[RL_REQ_IP] = p->req_ip_per_min;             rc.burst[RL_REQ_IP] = p->req_ip_burst;
    rc.banned_pubkeys = p->banned_pubkeys;
    rc.banned_ips = p->banned_ips;
    rc.ban_file = p->ban_file;
    unsigned line = 0;
    ng_status_t st = rl_configure(&rc, &line);
    if (st == NG_OK) return true;
    if (st == NG_E_IO) perror(p->ban_file);
    else if (line) fprintf(stderr, "%s:%u: invalid ban entry (expected \"pubkey <hex>\" or \"ip <address>\")\n", p->ban_file, line);
    else fprintf(stderr, "invalid banned_pubkeys / banned_ips entry: %s\n", ng_status_str(st));
    return false;
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
    rl_shutdown();
    crypto_deinit();
}

int main(int argc, const char **argv) {
    const char *db_path = getenv("DATABASE_URL");
    const char *service_url = getenv("SERVICE_URL");
    const char *config_path = "nostrogotho.conf";
    bool config_required = false;
    int port = 7447;
    int min_pow = -1, lower_limit = -1, upper_limit = -1;     /* -1: from the config */

    if ((getenv("MIN_POW_DIFFICULTY") && (!parse_int(getenv("MIN_POW_DIFFICULTY"), &min_pow) || min_pow < 0)) ||
        (getenv("CREATED_AT_LOWER_LIMIT") && (!parse_int(getenv("CREATED_AT_LOWER_LIMIT"), &lower_limit) || lower_limit < 0)) ||
        (getenv("CREATED_AT_UPPER_LIMIT") && (!parse_int(getenv("CREATED_AT_UPPER_LIMIT"), &upper_limit) || upper_limit < 0))) {
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
            server_set_debug(true);
        } else if (strcmp(argv[i], "-min-pow") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &min_pow) || min_pow < 0) return 1;
        } else if (strcmp(argv[i], "-created-at-lower-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &lower_limit) || lower_limit < 0) return 1;
        } else if (strcmp(argv[i], "-created-at-upper-limit") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &upper_limit) || upper_limit < 0) return 1;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
            config_required = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-database path] [-port num] [-service-url url] [--debug] [--help]\n", argv[0]);
            printf("  -database path                 SQLite database (default: ./nostrogotho.sqlite)\n");
            printf("  -port num                      WebSocket port (default: 7447)\n");
            printf("  -service-url url               Public relay URL for NIP-42/NIP-62\n");
            printf("  --config path                  Runtime config (default: ./nostrogotho.conf, optional)\n");
            printf("  --debug                        Print connects, disconnects and events to console\n");
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

    if (!load_config(config_path, config_required)) return 1;
    apply_config(service_url && *service_url ? service_url : NULL, min_pow, lower_limit, upper_limit);
    if (!apply_policy()) return 1;

    if (!init_storage(db_path)) {
        return 1;
    }

    server_configure(&storage_ctx, ng_relay_info.relay_url, ng_relay_info.min_pow_difficulty,
                     (time_t) ng_relay_info.created_at_lower_limit, (time_t) ng_relay_info.created_at_upper_limit);
    signal(SIGINT, sigint_handler);
    const bool result = server_run(port);
    cleanup();
    return result ? 0 : 1;
}
