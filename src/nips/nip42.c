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
#include "../json_lite.h"
#include "../json_util.h"

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

const char *nip42_authenticate(relay_conn_t *connection, const event_t *event,
                               const char *service_url, time_t now) {
    nip42_client_t *client = find_client(connection);
    if (!client) return "error: connection has no AUTH state";
    if (event->kind != 22242) return "invalid: AUTH event must be kind 22242";
    switch (check_event_status(event)) {
    case CHECK_EVENT_OK: break;
    case CHECK_EVENT_BAD_ID: return "invalid: event id does not match the event hash";
    case CHECK_EVENT_BAD_SIG: return "invalid: bad signature";
    default: return "invalid: malformed event";
    }
    if (llabs((long long) now - (long long) event->created_at) > 600)
        return "invalid: created_at must be within 10 minutes";
    if (!nip_event_has_tag(event, "challenge", client->challenge))
        return "invalid: challenge tag does not match";
    if (!nip_event_has_relay_tag(event, service_url ? service_url : ""))
        return "invalid: relay tag does not match this relay";
    strcpy(client->pubkey, event->pubkey);
    return NULL;
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

void nip42_send_challenge(relay_conn_t *connection) {
    char challenge[17];
    if (!nip42_open_challenge(connection, challenge)) return;
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "AUTH");
    json_builder_append_string(&builder, challenge);
    const char *j = json_builder_finish(&builder);
    nip_plugin_send_json(connection, j ? j : "[\"NOTICE\",\"error: server out of memory\"]");
    json_builder_free(&builder);
}

/* The JSON text t (a tags array) contains the tag ["-"] (whitespace allowed). */
static bool tags_text_protected(const char *t, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (t[i] != '[') continue;
        size_t j = i + 1;
        while (j < n && (t[j] == ' ' || t[j] == '\t' || t[j] == '\n' || t[j] == '\r')) j++;
        if (j + 3 > n || memcmp(t + j, "\"-\"", 3) != 0) continue;
        j += 3;
        while (j < n && (t[j] == ' ' || t[j] == '\t' || t[j] == '\n' || t[j] == '\r')) j++;
        if (j < n && t[j] == ']') return true;
    }
    return false;
}

/* NIP-70: a repost (kind 6 / 16) whose content embeds a protected event. */
static bool embeds_protected(const event_t *event) {
    if ((event->kind != 6 && event->kind != 16) || !event->content || !event->content_len) return false;
    jstr_t tags = jl_get_tok(jl_str(event->content), "$.tags");
    return tags.buf && tags_text_protected(tags.buf, tags.len);
}

/* NIP-70 protected events: an event tagged ["-"] is accepted only from an
 * authenticated (NIP-42) connection whose pubkey is the event author. */
static bool nip42_plugin_accept_publish(relay_conn_t *connection,
                                        const event_t *event,
                                        char *reason, size_t reason_size,
                                        void *ctx) {
    (void) ctx;
    if (embeds_protected(event)) {
        snprintf(reason, reason_size, "blocked: reposts must not embed a protected event");
        return false;
    }
    if (!nip_event_has_tag(event, "-", NULL)) return true;

    const char *auth_pubkey = nip42_authenticated_pubkey(connection);
    if (!auth_pubkey) {
        nip42_send_challenge(connection);
        snprintf(reason, reason_size, "auth-required: this event may only be published by its author");
        return false;
    }
    if (strcmp(auth_pubkey, event->pubkey) != 0) {
        snprintf(reason, reason_size,
                 "restricted: this event may only be published by its author");
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
        nip_plugin_send_status(connection, "NOTICE", NULL, false, "invalid: AUTH needs one event");
        return true;
    }

    event_t event;
    time_t now = time(NULL);
    const char *bad = NULL;
    if (!json_parse_event_why(values[1].value.string_val, &event, &bad)) {
        char hint[MAX_ID_SIZE + 1];
        if (json_event_id_hint(values[1].value.string_val, hint))
            nip_plugin_send_status(connection, "OK", hint, false, bad ? bad : "invalid: malformed event");
        else
            nip_plugin_send_status(connection, "NOTICE", NULL, false, bad ? bad : "invalid: malformed event");
        return true;
    }

    const char *why = nip42_authenticate(connection, &event, nip42_service_url, now);
    nip_plugin_send_status(connection, "OK", event.id, why == NULL, why ? why : "");
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
    {
        const char *j = json_builder_finish(&builder);
        nip_plugin_send_json(connection, j ? j : "[\"NOTICE\",\"error: server out of memory\"]");
        json_builder_free(&builder);
    }
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