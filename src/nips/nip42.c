#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

static nip42_client_t *find_client(struct mg_connection *connection) {
    for (nip42_client_t *client = clients; client; client = client->next) {
        if (client->connection == connection) return client;
    }
    return NULL;
}

bool nip42_open(struct mg_connection *connection, char challenge[17]) {
    unsigned char random[8];
    nip42_client_t *client = calloc(1, sizeof(*client));
    if (!client || BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
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
    if (!client || BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
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
    if (!client || event->kind != 22242 || !check_event(event) ||
        llabs((long long) now - (long long) event->created_at) > 600 ||
        !nip_event_has_tag(event, "challenge", client->challenge) ||
        !nip_event_has_relay_tag(event, service_url)) return false;
    strcpy(client->pubkey, event->pubkey);
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

static void nip42_plugin_init(const relay_config_t *config) {
    snprintf(nip42_service_url, sizeof(nip42_service_url), "%s",
             config->service_url ? config->service_url : "");
}

/* "-" tag policy from NIP-42: an event tagged "-" requires an authenticated
 * connection whose pubkey matches the event author. */
static bool nip42_plugin_accept_publish(struct mg_connection *connection,
                                        const event_t *event,
                                        char *reason, size_t reason_size) {
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
                                    json_value_t *values, size_t count) {
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

static void nip42_plugin_on_connect(struct mg_connection *connection) {
    char challenge[17];
    if (!nip42_open(connection, challenge)) return;
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "AUTH");
    json_builder_append_string(&builder, challenge);
    nip_plugin_send_json(connection, json_builder_finish(&builder));
}

static void nip42_plugin_on_disconnect(struct mg_connection *connection) {
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