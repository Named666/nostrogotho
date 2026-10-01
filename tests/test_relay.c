#include <mongoose.h>
#include <stdio.h>
#include "relay/relay.h"
#include "storage.h"

static storage_context_t storage_ctx = {0};

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    (void)c;
    (void)ev;
    (void)ev_data;
    printf("Event: %d\n", ev);
}

int main() {
    storage_context_init_sqlite3(&storage_ctx);
    printf("Storage context init done\n");
    
    if (!storage_ctx.init || !storage_ctx.init("./test_debug.sqlite")) {
        printf("Storage init failed\n");
        return 1;
    }
    printf("Storage init OK\n");

    relay_config_t config;
    relay_config_init(&config);
    snprintf(config.database_path, sizeof(config.database_path), "%s",
             "./test_debug.sqlite");
    config.port = 7457;
    config.service_url[0] = '\0';
    config.verbosity = LOG_VERBOSITY_DEBUG;

    relay_t *relay = relay_create(&config, &storage_ctx);
    if (!relay) {
        printf("Failed to create relay\n");
        return 1;
    }
    printf("Relay created\n");

    // Now try to run like server_run
    char listen_url[64];
    snprintf(listen_url, sizeof(listen_url), "ws://0.0.0.0:%d", config.port);
    printf("Listen URL: %s\n", listen_url);

    // Re-init manager like server_run does
    mg_mgr_init(&relay->manager);
    printf("Manager re-inited\n");

    if (!mg_http_listen(&relay->manager, listen_url, relay_event_handler, relay)) {
        printf("mg_http_listen FAILED\n");
        mg_mgr_free(&relay->manager);
        return 1;
    }
    printf("mg_http_listen OK\n");

    mg_mgr_free(&relay->manager);
    /* Don't leave the probe database behind. */
    remove("./test_debug.sqlite");
    remove("./test_debug.sqlite-shm");
    remove("./test_debug.sqlite-wal");
    remove("./test_debug.sqlite-journal");
    return 0;
}