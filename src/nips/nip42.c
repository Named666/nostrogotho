/* ============================================================================
 * NIP-42: Relay Authentication
 *
 * Single-file NIP: challenge/auth session API + reload state migration +
 * AUTH interception + restricted-tag publication policy + capability table +
 * self-registration. Compiling this file enables the NIP; deleting it
 * removes it. No header, no registration list.
 *
 * Auth state (challenge + authenticated pubkey) lives in the host-owned
 * connection_session, NOT in module statics. Sessions outlive module reload,
 * so authentication survives a NIP change/add/remove with no migration step.
 * The versioned state blob below is belt-and-braces + rolling-update compat.
 * Its declarations (shared with nhr_module.c) live in nip_capability.h.
 * ============================================================================ */

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
#include "nip_capability.h"
#include "crypto.h"
#include "model/tag_iter.h"
#include "relay/connection_session.h"
#include "protocol/protocol.h"
#include "relay/relay.h"            /* host builds: relay_send_json() */
#ifdef NHR_BUILD_MODULE
#include "nhr_module.h"             /* module builds: session/send shims */
#endif

/* Fill a buffer with cryptographically-strong random bytes. Uses
 * BCryptGenRandom on Windows, getrandom(2) on Linux, /dev/urandom fallback.
 * Returns false if no source is available. */
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
        size_t got = 0;
        if (urandom == NULL) {
            return false;
        }
        /* `fread` may short-read on signals; loop until full. */
        while (got < len - filled) {
            size_t n = fread(buf + filled + got, 1, len - filled - got, urandom);
            if (n == 0) {
                if (ferror(urandom)) {
                    break;
                }
                break;
            }
            got += n;
        }
        fclose(urandom);
        urandom = NULL;
        if (got != len - filled) {
            return false;
        }
    }
    return true;
#endif
}

/* Generate a fresh 16-hex-char challenge string. */
static bool nip42_make_challenge(char challenge[17]) {
    unsigned char random[8];
    if (!challenge || !nip42_random_bytes(random, sizeof(random))) return false;
    for (size_t index = 0; index < sizeof(random); index++) {
        snprintf(challenge + index * 2, 3, "%02x", random[index]);
    }
    challenge[16] = '\0';
    return true;
}

/* ============================================================================
 * Connection-ID auth API (session-backed)
 *
 * In module builds the session is reached through the nhr_module_session_*
 * shims (host services); in host builds directly.
 * ============================================================================ */

#ifdef NHR_BUILD_MODULE
#define NIP42_SESS_CHALLENGE(id) nhr_module_session_challenge(id)
#define NIP42_SESS_SET_CHALLENGE(id, ch) nhr_module_session_set_challenge((id), (ch))
#define NIP42_SESS_PUBKEY(id) nhr_module_session_auth_pubkey(id)
#define NIP42_SESS_SET_PUBKEY(id, pk) nhr_module_session_set_auth((id), (pk))
#define NIP42_SESS_CLEAR(id) nhr_module_session_clear_auth(id)
#else
#define NIP42_SESS_CHALLENGE(id) \
    (connection_session_get(id) ? \
     connection_session_get_challenge(connection_session_get(id)) : NULL)
#define NIP42_SESS_SET_CHALLENGE(id, ch) \
    (connection_session_get(id) ? \
     (connection_session_set_challenge(connection_session_get(id), (ch)), true) : false)
#define NIP42_SESS_PUBKEY(id) \
    (connection_session_get(id) ? \
     connection_session_get_auth_pubkey(connection_session_get(id)) : NULL)
#define NIP42_SESS_SET_PUBKEY(id, pk) \
    (connection_session_get(id) ? \
     (connection_session_set_auth(connection_session_get(id), (pk)), true) : false)
#define NIP42_SESS_CLEAR(id) \
    do { \
        connection_session_t *s_ = connection_session_get(id); \
        if (s_) { \
            connection_session_set_auth(s_, NULL); \
            connection_session_set_challenge(s_, NULL); \
        } \
    } while (0)
#endif

bool nip42_open_by_id(connection_id_t connection_id, char challenge[17]) {
    char fresh[17];
    if (!challenge || !nip42_make_challenge(fresh)) return false;
    if (!NIP42_SESS_SET_CHALLENGE(connection_id, fresh)) return false;
    memcpy(challenge, fresh, sizeof(fresh));
    return true;
}

bool nip42_open_challenge_by_id(connection_id_t connection_id, char challenge[17]) {
    /* Refresh the challenge for a live session. Sessions always exist for
     * connected clients (the relay creates them before capability notify). */
    return nip42_open_by_id(connection_id, challenge);
}

void nip42_close_by_id(connection_id_t connection_id) {
    NIP42_SESS_CLEAR(connection_id);
}

const char *nip42_authenticated_pubkey_by_id(connection_id_t connection_id) {
    const char *pubkey = NIP42_SESS_PUBKEY(connection_id);
    return pubkey && pubkey[0] ? pubkey : NULL;
}

bool nip42_authenticate_by_id(connection_id_t connection_id, const event_t *event,
                              const char *service_url, time_t now) {
    const char *challenge;
    bool valid_event;
    if (!event) return false;
#ifdef NHR_BUILD_MODULE
    extern bool nhr_module_accepts_event(const event_t *event);
    valid_event = nhr_module_accepts_event(event);
#else
    valid_event = check_event(event);
#endif
    challenge = NIP42_SESS_CHALLENGE(connection_id);
    if (!challenge || !challenge[0] || event->kind != 22242 || !valid_event ||
        llabs((long long) now - (long long) event->created_at) > 600 ||
        !tag_has(event, "challenge", challenge) ||
        !tag_has(event, "relay", service_url)) return false;
    return NIP42_SESS_SET_PUBKEY(connection_id, event->pubkey);
}

/* ============================================================================
 * Reload state migration (belt-and-braces snapshot of session auth state)
 * ============================================================================ */

#define NIP42_STATE_MAX (sizeof(((nip42_state_t *)0)->clients) / \
                         sizeof(((nip42_state_t *)0)->clients[0]))

#ifndef NHR_BUILD_MODULE
typedef struct {
    nip42_state_t *state;
    size_t count;
    bool overflow;
} nip42_save_ctx_t;

static void nip42_save_one_session(connection_session_t *session, void *userdata) {
    nip42_save_ctx_t *ctx = (nip42_save_ctx_t *)userdata;
    const char *challenge;
    const char *pubkey;
    if (!session || !ctx || ctx->overflow) return;
    if (ctx->count >= NIP42_STATE_MAX) {
        ctx->overflow = true;
        return;
    }
    challenge = connection_session_get_challenge(session);
    pubkey = connection_session_get_auth_pubkey(session);
    if ((!challenge || !challenge[0]) && (!pubkey || !pubkey[0])) return;
    ctx->state->clients[ctx->count].connection_id =
        connection_session_get_id(session);
    snprintf(ctx->state->clients[ctx->count].challenge,
             sizeof(ctx->state->clients[ctx->count].challenge),
             "%s", challenge ? challenge : "");
    snprintf(ctx->state->clients[ctx->count].pubkey,
             sizeof(ctx->state->clients[ctx->count].pubkey),
             "%s", pubkey ? pubkey : "");
    ctx->count++;
}
#endif

bool nip42_save_state(nip42_state_t *state,
                      const nip42_connection_t *connections,
                      size_t connection_count) {
    (void)connections;
    (void)connection_count;
    if (!state) return false;
    memset(state, 0, sizeof(*state));
    state->version = 1;
#ifdef NHR_BUILD_MODULE
    {
        /* Module build: enumerate host sessions through shims. */
        connection_snapshot_t snapshot[256];
        size_t count = nhr_module_session_snapshot(snapshot, 256);
        size_t kept = 0;
        if (count > 256) return false;
        for (size_t i = 0; i < count; i++) {
            const char *challenge = nhr_module_session_challenge(snapshot[i].id);
            const char *pubkey = nhr_module_session_auth_pubkey(snapshot[i].id);
            if ((!challenge || !challenge[0]) && (!pubkey || !pubkey[0])) continue;
            if (kept >= NIP42_STATE_MAX) return false;
            state->clients[kept].connection_id = snapshot[i].id;
            snprintf(state->clients[kept].challenge,
                     sizeof(state->clients[kept].challenge),
                     "%s", challenge ? challenge : "");
            snprintf(state->clients[kept].pubkey,
                     sizeof(state->clients[kept].pubkey),
                     "%s", pubkey ? pubkey : "");
            kept++;
        }
        state->count = (uint32_t)kept;
    }
#else
    {
        nip42_save_ctx_t ctx;
        ctx.state = state;
        ctx.count = 0;
        ctx.overflow = false;
        connection_session_iterate(nip42_save_one_session, &ctx);
        if (ctx.overflow) return false;
        state->count = (uint32_t)ctx.count;
    }
#endif
    return true;
}

bool nip42_restore_state(const nip42_state_t *state,
                         const nip42_connection_t *connections,
                         size_t connection_count) {
    (void)connections;
    (void)connection_count;
    if (!state || state->version != 1 || state->count > NIP42_STATE_MAX) return false;
    /* Sessions survive reload, so entries normally already match. Re-apply
     * unconditionally: sessions for disconnected clients are gone (skipped),
     * live sessions converge to the snapshot. */
    for (uint32_t i = 0; i < state->count; i++) {
        connection_id_t id = state->clients[i].connection_id;
#ifdef NHR_BUILD_MODULE
        nhr_module_session_set_challenge(id, state->clients[i].challenge);
        if (state->clients[i].pubkey[0]) {
            nhr_module_session_set_auth(id, state->clients[i].pubkey);
        }
#else
        connection_session_t *session = connection_session_get(id);
        if (!session) continue; /* Client disconnected since the snapshot. */
        connection_session_set_challenge(session, state->clients[i].challenge);
        if (state->clients[i].pubkey[0]) {
            connection_session_set_auth(session, state->clients[i].pubkey);
        }
#endif
    }
    return true;
}

/* ============================================================================
 * Capabilities
 * ============================================================================ */

/* Send a JSON message by opaque ID without touching transport types. Host
 * builds use the relay-owned helper; module builds go through host services. */
static void nip42_send_json(connection_id_t connection_id, const char *json) {
    if (!json) return;
#ifdef NHR_BUILD_MODULE
    nhr_module_send_json(connection_id, json, strlen(json));
#else
    relay_send_json(connection_id, json);
#endif
}

typedef struct {
    char service_url[256];
} nip42_ctx_t;

/* Shared static ctx: re-derived in lifecycle init on every startup/reload,
 * so no heap allocation and nothing to leak or migrate. Auth state itself
 * lives in host-owned connection_session_t and survives reload untouched. */
static nip42_ctx_t nip42_ctx;

static void nip42_lifecycle_init(const relay_config_t *config, void *ctx);
static void nip42_lifecycle_shutdown(void *ctx);
static void nip42_connection_on_connect(connection_id_t connection_id, void *ctx);
static void nip42_connection_on_disconnect(connection_id_t connection_id, void *ctx);
static bool nip42_message_intercept_fn(connection_id_t connection_id, const protocol_message_t *msg, void *ctx);
static bool nip42_publication_policy_fn(connection_id_t connection_id, const event_t *event, char *reason, size_t reason_size, void *ctx);
static void nip42_send_auth_challenge_fn(connection_id_t connection_id, void *ctx);

/* Single capability table. (Protocol response carries the auth-challenge
 * hook only; EOSE/COUNT/hints are owned by NIP-67/NIP-45/NIP-17.) */
static nip_capability_t nip42_caps[] = {
    {
        .name = "nip42-lifecycle",
        .type = NIP_CAP_LIFECYCLE,
        .ctx = &nip42_ctx,
        .caps.lifecycle = { .init = nip42_lifecycle_init, .shutdown = nip42_lifecycle_shutdown },
        .next = NULL,
    },
    {
        .name = "nip42-connection",
        .type = NIP_CAP_CONNECTION,
        .ctx = &nip42_ctx,
        .caps.connection = { .on_connect = nip42_connection_on_connect,
                             .on_disconnect = nip42_connection_on_disconnect },
        .next = NULL,
    },
    {
        .name = "nip42-message",
        .type = NIP_CAP_MESSAGE_INTERCEPT,
        .ctx = &nip42_ctx,
        .caps.message_intercept = { .on_message = nip42_message_intercept_fn },
        .next = NULL,
    },
    {
        .name = "nip42-pub-policy",
        .type = NIP_CAP_PUBLICATION_POLICY,
        .ctx = &nip42_ctx,
        .caps.publication_policy = { .accept_publish = nip42_publication_policy_fn },
        .next = NULL,
    },
    {
        .name = "nip42-protocol-response",
        .type = NIP_CAP_PROTOCOL_RESPONSE,
        .ctx = &nip42_ctx,
        .caps.protocol_response = { .build_eose = NULL, .build_count = NULL,
                                    .needs_auth_hint = NULL,
                                    .send_auth_challenge = nip42_send_auth_challenge_fn },
        .next = NULL,
    },
};

static void nip42_lifecycle_init(const relay_config_t *config, void *ctx) {
    nip42_ctx_t *cap_ctx = (nip42_ctx_t *)ctx;
    if (!cap_ctx || !config) return;

    snprintf(cap_ctx->service_url, sizeof(cap_ctx->service_url), "%s",
             config->service_url ? config->service_url : "");
}

static void nip42_lifecycle_shutdown(void *ctx) {
    (void)ctx;
}

static void nip42_connection_on_connect(connection_id_t connection_id, void *ctx) {
    nip42_send_auth_challenge_fn(connection_id, ctx);
}

/* Refresh the NIP-42 challenge and send ["AUTH", challenge]. Used on
 * connect and before EOSE when a gift-wrap query needs the auth hint. */
static void nip42_send_auth_challenge_fn(connection_id_t connection_id, void *ctx) {
    (void)ctx;
    char challenge[17];
    if (!nip42_open_challenge_by_id(connection_id, challenge)) return;

    char *auth_msg = protocol_serialize_auth(challenge);
    if (auth_msg) {
        nip42_send_json(connection_id, auth_msg);
        protocol_free_string(auth_msg);
    }
}

static void nip42_connection_on_disconnect(connection_id_t connection_id, void *ctx) {
    (void)ctx;
    nip42_close_by_id(connection_id);
}

static bool nip42_message_intercept_fn(connection_id_t connection_id, const protocol_message_t *msg, void *ctx) {
    nip42_ctx_t *cap_ctx = (nip42_ctx_t *)ctx;
    const event_t *event;
    const char *service_url;
    char *ok;
    bool authenticated;

    if (!msg || msg->command != PROTOCOL_CMD_AUTH) return false;
    /* Only client AUTH responses (signed kind:22242 event) are consumed.
     * Anything else falls through to the relay default (NOTICE). */
    if (!msg->payload.auth.has_event) return false;
    event = &msg->payload.auth.event;
    service_url = (cap_ctx && cap_ctx->service_url[0]) ? cap_ctx->service_url : "";

    authenticated = nip42_authenticate_by_id(connection_id, event,
                                             service_url, time(NULL));
    /* NIP answers with OK; the relay owns framing, transport owns sending —
     * this helper only carries an opaque connection ID. */
    ok = protocol_serialize_ok(event->id, authenticated,
                               authenticated ? "" : "error: failed to authenticate");
    if (ok) {
        nip42_send_json(connection_id, ok);
        protocol_free_string(ok);
    }
    return true;
}

static bool nip42_publication_policy_fn(connection_id_t connection_id, const event_t *event,
                                        char *reason, size_t reason_size, void *ctx) {
    (void)ctx;
    (void)connection_id;

    if (!tag_has(event, "-", NULL)) return true;

    const char *auth_pubkey = nip42_authenticated_pubkey_by_id(connection_id);
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

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip42, nip42_caps)