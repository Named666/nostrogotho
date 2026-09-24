#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <sys/random.h>
#include <errno.h>
#endif
#include "crypto.h"
#include "nip42.h"
#include "nip_event.h"
#include "nip_plugin.h"

typedef struct nip42_client {
    struct mg_connection *connection;
    char challenge[17];
    char pubkey[MAX_PUBKEY_SIZE + 1];
    struct nip42_client *next;
} nip42_client_t;

static nip42_client_t *clients;

/* nip42_random_bytes - Fill a buffer with cryptographically-strong random
 * bytes. Uses BCryptGenRandom on Windows, getrandom(2) on Linux, and falls
 * back to /dev/urandom. Returns false if no source is available. */
static bool nip42_random_bytes(unsigned char *buf, size_t len) {
#ifdef _WIN32
    return BCryptGenRandom(NULL, buf, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    size_t filled = 0;
#ifdef __linux__
    while (filled < len) {
        ssize_t n = getrandom(buf + filled, len - filled, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break; /* fall back to /dev/urandom */
        }
        filled += (size_t)n;
    }
#endif
    if (filled < len) {
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (!urandom) return false;
        size_t got = fread(buf + filled, 1, len - filled, urandom);
        fclose(urandom);
        if (got != len - filled) return false;
    }
    return true;
#endif
}

static nip42_client_t *find_client(struct mg_connection *connection) {
    for (nip42_client_t *client = clients; client; client = client->next) {
        if (client->connection == connection) return client;
    }
    return NULL;
}

bool nip42_open(struct mg_connection *connection, char challenge[17]) {
    unsigned char random[8];
    nip42_client_t *client = calloc(1, sizeof(*client));
    if (!client || !nip42_random_bytes(random, sizeof(random))) {
        free(client);
        return false;
    }
    client->connection = connection;
    for (size_t index = 0; index < sizeof(random); index++) {
        snprintf(client->challenge + index * 2, 3, "%02x", random[index]);
    }
    memcpy(challenge, client->challenge, sizeof(client->challenge));
    client->next = clients;
    clients = client;
    return true;
}

void nip42_close(struct mg_connection *connection) {
    nip42_client_t **link = &clients;
    while (*link) {
        if ((*link)->connection == connection) {
            nip42_client_t *client = *link;
            *link = client->next;
            free(client);
            return;
        }
        link = &(*link)->next;
    }
}

const char *nip42_authenticated_pubkey(struct mg_connection *connection) {
    nip42_client_t *client = find_client(connection);
    return client && client->pubkey[0] ? client->pubkey : NULL;
}

/* nip42_open_challenge - Generate a fresh challenge for an existing client
 * (used before emitting a NIP-67 "auth" hint). Returns false when the
 * connection has no client record. */
bool nip42_open_challenge(struct mg_connection *connection, char challenge[17]) {
    unsigned char random[8];
    nip42_client_t *client = find_client(connection);
    if (!client || !nip42_random_bytes(random, sizeof(random))) {
        return false;
    }
    for (size_t index = 0; index < sizeof(random); index++) {
        snprintf(client->challenge + index * 2, 3, "%02x", random[index]);
    }
    memcpy(challenge, client->challenge, sizeof(client->challenge));
    return true;
}

bool nip42_authenticate(struct mg_connection *connection, const event_t *event,
                        const char *service_url, time_t now) {
    nip42_client_t *client = find_client(connection);
    bool valid_event;
#ifdef NHR_BUILD_MODULE
    extern bool nhr_module_accepts_event(const event_t *event);
    valid_event = nhr_module_accepts_event(event);
#else
    valid_event = check_event(event);
#endif
    if (!client || event->kind != 22242 || !valid_event ||
        llabs((long long) now - (long long) event->created_at) > 600 ||
        !nip_event_has_tag(event, "challenge", client->challenge) ||
        !nip_event_has_relay_tag(event, service_url)) return false;
    strcpy(client->pubkey, event->pubkey);
    return true;
}

bool nip42_save_state(nip42_state_t *state,
                      const nip42_connection_t *connections,
                      size_t connection_count) {
    size_t count = 0;
    if (!state) return false;
    memset(state, 0, sizeof(*state));
    state->version = 1;
    for (nip42_client_t *client = clients; client; client = client->next) {
        uintptr_t connection_id = 0;
        for (size_t i = 0; i < connection_count; i++) {
            if (connections[i].connection == client->connection) {
                connection_id = connections[i].id;
                break;
            }
        }
        if (!connection_id) continue;
        if (count >= sizeof(state->clients) / sizeof(state->clients[0])) return false;
        state->clients[count].connection_id = connection_id;
        snprintf(state->clients[count].challenge,
                 sizeof(state->clients[count].challenge), "%s", client->challenge);
        snprintf(state->clients[count].pubkey,
                 sizeof(state->clients[count].pubkey), "%s", client->pubkey);
        count++;
    }
    state->count = (uint32_t)count;
    return true;
}

bool nip42_restore_state(const nip42_state_t *state,
                         const nip42_connection_t *connections,
                         size_t connection_count) {
    if (!state || state->version != 1 ||
        state->count > sizeof(state->clients) / sizeof(state->clients[0])) return false;
    for (uint32_t i = 0; i < state->count; i++) {
        struct mg_connection *connection = NULL;
        for (size_t j = 0; j < connection_count; j++) {
            if (connections[j].id == state->clients[i].connection_id) {
                connection = connections[j].connection;
                break;
            }
        }
        if (!connection) continue; /* Client disconnected since the snapshot. */
        nip42_client_t *client = find_client(connection);
        if (!client) {
            client = (nip42_client_t *)calloc(1, sizeof(*client));
            if (!client) return false;
            client->connection = connection;
            client->next = clients;
            clients = client;
        }
        memcpy(client->challenge, state->clients[i].challenge,
               sizeof(client->challenge));
        memcpy(client->pubkey, state->clients[i].pubkey,
               sizeof(client->pubkey));
    }
    return true;
}

/* ============================================================================
 * NIP-42: Authentication of Clients to Relays (plugin registration)
 *
 * Participates in the relay lifecycle via the plugin hooks:
 *   - on_connect / on_disconnect: challenge state per connection
 *   - on_message: consumes ["AUTH", <signed event>] messages
 *   - accept_publish: enforces the "-" (auth-required) tag policy
 * The relay URL (for the "relay" tag check) is captured from the shared
 * relay configuration during init().
 * ============================================================================ */

static char nip42_service_url[256];

static void nip42_plugin_init(const relay_config_t *config, void *ctx) {
    (void) ctx;
    snprintf(nip42_service_url, sizeof(nip42_service_url), "%s",
             config->service_url ? config->service_url : "");
}

/* "-" tag policy from NIP-42: an event tagged "-" requires an authenticated
 * connection whose pubkey matches the event author. */
static bool nip42_plugin_accept_publish(struct mg_connection *connection,
                                        const event_t *event,
                                        char *reason, size_t reason_size,
                                        void *ctx) {
    (void) ctx;
    if (!nip_event_has_tag(event, "-", NULL)) return true;

    const char *auth_pubkey = nip42_authenticated_pubkey(connection);
    if (!auth_pubkey) {
        snprintf(reason, reason_size, "auth-required: authentication required");
        return false;
    }
    if (strcmp(auth_pubkey, event->pubkey) != 0) {
        snprintf(reason, reason_size,
                 "restricted: authenticated pubkey does not match event author");
        return false;
    }
    return true;
}

static bool nip42_plugin_on_message(struct mg_connection *connection,
                                    json_value_t *values, size_t count,
                                    void *ctx) {
    (void) ctx;
    const char *method = json_array_get_string(values, count, 0);
    if (!method || strcmp(method, "AUTH") != 0) return false;

    if (count != 2 || values[1].type != JSON_TYPE_OBJECT) {
        nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: invalid auth");
        return true;
    }

    event_t event;
    time_t now = time(NULL);
    if (!json_parse_event(values[1].value.string_val, &event)) {
        nip_plugin_send_status(connection, "NOTICE", NULL, false, "error: invalid auth");
        return true;
    }

    if (!nip42_authenticate(connection, &event, nip42_service_url, now)) {
        nip_plugin_send_status(connection, "OK", event.id, false,
                               "error: failed to authenticate");
    } else {
        nip_plugin_send_status(connection, "OK", event.id, true, "");
    }
    event_release(&event);
    return true;
}

static void nip42_plugin_on_connect(struct mg_connection *connection, void *ctx) {
    (void) ctx;
    char challenge[17];
    if (!nip42_open(connection, challenge)) return;
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "AUTH");
    json_builder_append_string(&builder, challenge);
    nip_plugin_send_json(connection, json_builder_finish(&builder));
}

static void nip42_plugin_on_disconnect(struct mg_connection *connection, void *ctx) {
    (void) ctx;
    nip42_close(connection);
}

static nip_plugin_t nip42_plugin = {
    .name = "nip42",
    .init = nip42_plugin_init,
    .on_connect = nip42_plugin_on_connect,
    .on_disconnect = nip42_plugin_on_disconnect,
    .on_message = nip42_plugin_on_message,
    .accept_publish = nip42_plugin_accept_publish,
};

__attribute__((constructor)) static void nip42_register_at_startup(void) {
    nip_plugin_register(&nip42_plugin);
}