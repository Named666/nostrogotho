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
    char challenge[17];
    char pubkey[MAX_PUBKEY_SIZE + 1];
} nip42_client_t;

/* Per-connection auth state lives in a relay_conn slot: O(1) lookup and no
 * shared list, so it is safe with connections spread across worker threads
 * (each connection's state is only touched by its pinned worker). */
static int nip42_slot = -1;

__attribute__((constructor)) static void nip42_slot_init(void) {
    nip42_slot = relay_conn_slot_alloc();
}

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

static nip42_client_t *find_client(relay_conn_t *connection) {
    return (nip42_client_t *) relay_conn_get_slot(connection, nip42_slot);
}

bool nip42_open(relay_conn_t *connection, char challenge[17]) {
    unsigned char random[8];
    nip42_client_t *client = find_client(connection);
    bool fresh = client == NULL;
    if (fresh) client = calloc(1, sizeof(*client));
    if (!client || !nip42_random_bytes(random, sizeof(random))) {
        if (fresh) free(client);
        return false;
    }
    for (size_t index = 0; index < sizeof(random); index++) {
        snprintf(client->challenge + index * 2, 3, "%02x", random[index]);
    }
    memcpy(challenge, client->challenge, sizeof(client->challenge));
    relay_conn_set_slot(connection, nip42_slot, client);
    return true;
}

void nip42_close(relay_conn_t *connection) {
    free(find_client(connection));
    relay_conn_set_slot(connection, nip42_slot, NULL);
}

const char *nip42_authenticated_pubkey(relay_conn_t *connection) {
    nip42_client_t *client = find_client(connection);
    return client && client->pubkey[0] ? client->pubkey : NULL;
}

/* nip42_open_challenge - Generate a fresh challenge for an existing client
 * (used before emitting a NIP-67 "auth" hint). Returns false when the
 * connection has no client record. */
bool nip42_open_challenge(relay_conn_t *connection, char challenge[17]) {
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

bool nip42_authenticate(relay_conn_t *connection, const event_t *event,
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

static void nip42_plugin_init(const relay_config_t *config, void *ctx) {
    (void) ctx;
    snprintf(nip42_service_url, sizeof(nip42_service_url), "%s",
             config->service_url ? config->service_url : "");
}

/* "-" tag policy from NIP-42: an event tagged "-" requires an authenticated
 * connection whose pubkey matches the event author. */
static bool nip42_plugin_accept_publish(relay_conn_t *connection,
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

static bool nip42_plugin_on_message(relay_conn_t *connection,
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

static void nip42_plugin_on_connect(relay_conn_t *connection, void *ctx) {
    (void) ctx;
    char challenge[17];
    if (!nip42_open(connection, challenge)) return;
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "AUTH");
    json_builder_append_string(&builder, challenge);
    nip_plugin_send_json(connection, json_builder_finish(&builder));
}

static void nip42_plugin_on_disconnect(relay_conn_t *connection, void *ctx) {
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