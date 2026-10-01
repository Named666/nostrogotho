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
 * Its declarations (shared with nhr_module.c) live in nip42.h.
 *
 * Transport/session/crypto access goes ONLY through nips/nip_env.h, which
 * resolves to direct relay calls in host builds and to Nhr_Host shims in
 * module builds. This file contains no NHR_BUILD_MODULE branches.
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
#include "nips/nip42.h"      /* own public API declarations */
#include "nips/nip_env.h"    /* unified host env: send/session/validate */
#include "log.h"
#include "protocol/event_tags.h"
#include "protocol/tag_iter.h"
#include "protocol/protocol.h"

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
 * Connection-ID auth API (session-backed, via nip_env)
 * ============================================================================ */

bool nip42_open_by_id(connection_id_t connection_id, char challenge[17]) {
    char fresh[17];
    if (!challenge || !nip42_make_challenge(fresh)) return false;
    if (!nip_env_session_set_challenge(connection_id, fresh)) return false;
    memcpy(challenge, fresh, sizeof(fresh));
    return true;
}

bool nip42_open_challenge_by_id(connection_id_t connection_id, char challenge[17]) {
    /* Refresh the challenge for a live session. Sessions always exist for
     * connected clients (the relay creates them before capability notify). */
    return nip42_open_by_id(connection_id, challenge);
}

void nip42_close_by_id(connection_id_t connection_id) {
    nip_env_session_clear_auth(connection_id);
}

const char *nip42_authenticated_pubkey_by_id(connection_id_t connection_id) {
    const char *pubkey = nip_env_session_auth_pubkey(connection_id);
    return pubkey && pubkey[0] ? pubkey : NULL;
}

/* Check if a specific pubkey is authenticated for this connection (supports multiple per NIP-42) */
bool nip42_is_pubkey_authenticated(connection_id_t connection_id, const char *pubkey) {
    if (!pubkey) return false;
    return nip_env_session_has_auth(connection_id, pubkey);
}

/* Send an auth challenge on demand (per NIP-42: "At any moment the relay may send an AUTH message") */
bool nip42_send_auth_challenge(connection_id_t connection_id) {
    char challenge[17];
    if (!nip42_open_challenge_by_id(connection_id, challenge)) return false;

    char *auth_msg = protocol_serialize_auth(challenge);
    if (!auth_msg) return false;

    nip_env_send_json(connection_id, auth_msg);

    protocol_free_string(auth_msg);
    return true;
}

static const char *nip42_extract_domain(const char *url) {
    if (!url) return NULL;
    
    const char *domain_start = url;
    if (strncmp(url, "wss://", 6) == 0) {
        domain_start = url + 6;
    } else if (strncmp(url, "ws://", 5) == 0) {
        domain_start = url + 5;
    } else if (strncmp(url, "https://", 8) == 0) {
        domain_start = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        domain_start = url + 7;
    }
    
    const char *domain_end = domain_start;
    while (*domain_end && *domain_end != '/' && *domain_end != ':' && *domain_end != '?') {
        domain_end++;
    }
    
    static char domain[256];
    size_t len = domain_end - domain_start;
    if (len >= sizeof(domain)) len = sizeof(domain) - 1;
    memcpy(domain, domain_start, len);
    domain[len] = '\0';
    
    return domain;
}

bool nip42_authenticate_by_id(connection_id_t connection_id, const event_t *event,
                              const char *service_url, time_t now) {
    const char *challenge;
    bool valid_event;
    if (!event) return false;
    valid_event = nip_env_accepts_event(event);
    log_debug("NIP", "AUTH", "connection_id=%llu event_kind=%d valid_event=%d", (unsigned long long)connection_id, event->kind, valid_event);
    challenge = nip_env_session_challenge(connection_id);
    log_debug("NIP", "AUTH", "challenge=%s", challenge ? challenge : "NULL");
    if (!challenge || !challenge[0] || event->kind != 22242 || !valid_event ||
        llabs((long long) now - (long long) event->created_at) > 600 ||
        !event_tag_has_value(event, "challenge", challenge)) {
        log_debug("NIP", "AUTH", "validation failed");
        return false;
    }
    /* Check relay URL - domain matching per spec (URL normalization) */
    if (service_url && service_url[0]) {
        const char *event_relay = NULL;
        /* Extract relay tag from event */
        tag_iter_t it;
        tag_iter_init(&it, event);
        struct mg_str key, tag;
        while (tag_iter_next(&it, &key, &tag)) {
            char *name = tag_iter_element(&it, 0);
            if (name && strcmp(name, "relay") == 0) {
                event_relay = tag_iter_element(&it, 1);
                free(name);
                break;
            }
            free(name);
        }
        if (event_relay) {
            const char *service_domain = nip42_extract_domain(service_url);
            const char *event_domain = nip42_extract_domain(event_relay);
            if (strcmp(service_domain, event_domain) != 0) {
                log_debug("NIP", "AUTH", "relay domain mismatch: service=%s event=%s", service_domain, event_domain);
                return false;
            }
        }
    }
    log_debug("NIP", "AUTH", "adding pubkey=%s", event->pubkey);
    return nip_env_session_add_auth(connection_id, event->pubkey);
}

/* ============================================================================
 * Reload state migration (belt-and-braces snapshot of session auth state)
 * ============================================================================ */

#define NIP42_STATE_MAX (sizeof(((nip42_state_t *)0)->clients) / \
                         sizeof(((nip42_state_t *)0)->clients[0]))

bool nip42_save_state(nip42_state_t *state,
                      const nip42_connection_t *connections,
                      size_t connection_count) {
    /* Single path in every build: enumerate host sessions through nip_env.
     * Sessions themselves survive reload, so this snapshot is belt-and-
     * braces + rolling-update compat only. */
    connection_snapshot_t snapshot[NIP42_STATE_MAX];
    size_t count;
    size_t kept = 0;
    size_t i;
    (void)connections;
    (void)connection_count;
    if (!state) return false;
    memset(state, 0, sizeof(*state));
    state->version = 1;
    count = nip_env_session_snapshot(snapshot, NIP42_STATE_MAX);
    if (count > NIP42_STATE_MAX) return false;
    for (i = 0; i < count; i++) {
        const char *challenge = nip_env_session_challenge(snapshot[i].id);
        const char *pubkey = nip_env_session_auth_pubkey(snapshot[i].id);
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
        /* set_* fails for disconnected clients: skip them. */
        if (!nip_env_session_set_challenge(id, state->clients[i].challenge)) continue;
        if (state->clients[i].pubkey[0]) {
            nip_env_session_set_auth(id, state->clients[i].pubkey);
        }
    }
    return true;
}

/* ============================================================================
 * Capabilities
 * ============================================================================ */

typedef struct {
    char service_url[256];
    bool enabled;                 /* nip42.enabled: false disables all hooks */
    bool auth_required_for_write; /* nip42.auth_required_for_write */
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
static bool nip42_query_authorize_fn(connection_id_t connection_id, filter_t *filters, size_t count,
                                     char *reason, size_t reason_size, void *ctx);
static bool nip42_query_modify_fn(connection_id_t connection_id, const filter_t *filters, size_t count,
                                   bool has_more, int total_count, void *ctx);

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
    {
        .name = "nip42-query-policy",
        .type = NIP_CAP_QUERY_POLICY,
        .ctx = &nip42_ctx,
        .caps.query_policy = { .authorize_query = nip42_query_authorize_fn,
                               .modify_results = nip42_query_modify_fn },
        .next = NULL,
    },
};

static void nip42_lifecycle_init(const relay_config_t *config, void *ctx) {
    nip42_ctx_t *cap_ctx = (nip42_ctx_t *)ctx;
    if (!cap_ctx || !config) return;

    snprintf(cap_ctx->service_url, sizeof(cap_ctx->service_url), "%s",
             config->service_url);
    cap_ctx->enabled = config->nip42_enabled;
    cap_ctx->auth_required_for_write = config->nip42_auth_required_for_write;
}

static void nip42_lifecycle_shutdown(void *ctx) {
    (void)ctx;
}

static void nip42_connection_on_connect(connection_id_t connection_id, void *ctx) {
    nip42_ctx_t *cap_ctx = (nip42_ctx_t *)ctx;
    if (cap_ctx && !cap_ctx->enabled) return;
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
        nip_env_send_json(connection_id, auth_msg);
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

    if (cap_ctx && !cap_ctx->enabled) return false;
    if (!msg || msg->command != PROTOCOL_CMD_AUTH) return false;
    /* Only client AUTH responses (signed kind:22242 event) are consumed.
     * Anything else falls through to the relay default (NOTICE). */
    if (!msg->payload.auth.has_event) return false;
    event = &msg->payload.auth.event;
    service_url = (cap_ctx && cap_ctx->service_url[0]) ? cap_ctx->service_url : "";

    log_debug("NIP", "AUTH_INTERCEPT", "connection_id=%llu event_id=%.16s kind=%d", (unsigned long long)connection_id, event->id, event->kind);
    authenticated = nip42_authenticate_by_id(connection_id, event,
                                             service_url, time(NULL));
    log_debug("NIP", "AUTH_INTERCEPT", "authenticated=%d", authenticated);
    /* NIP answers with OK; the relay owns framing, transport owns sending —
     * this helper only carries an opaque connection ID. */
    ok = protocol_serialize_ok(event->id, authenticated,
                               authenticated ? "" : "error: failed to authenticate");
    if (ok) {
        nip_env_send_json(connection_id, ok);
        protocol_free_string(ok);
    }
    return true;
}

static bool nip42_publication_policy_fn(connection_id_t connection_id, const event_t *event,
                                        char *reason, size_t reason_size, void *ctx) {
    nip42_ctx_t *cap_ctx = (nip42_ctx_t *)ctx;
    if (cap_ctx && !cap_ctx->enabled) return true;

    /* Operator-configured write gate: unauthenticated connections cannot
     * publish at all. Spec flow: OK with auth-required: prefix. */
    if (cap_ctx && cap_ctx->auth_required_for_write &&
        nip_env_session_auth_count(connection_id) == 0) {
        snprintf(reason, reason_size,
                 "auth-required: authentication required for event writes");
        return false;
    }

    if (!event_tag_has(event, "-")) return true;

    /* Check if event author is among authenticated pubkeys for this connection */
    if (!nip42_is_pubkey_authenticated(connection_id, event->pubkey)) {
        const char *auth_pubkey = nip42_authenticated_pubkey_by_id(connection_id);
        if (!auth_pubkey) {
            snprintf(reason, reason_size, "auth-required: authentication required");
        } else {
            snprintf(reason, reason_size,
                     "restricted: authenticated pubkey does not match event author");
        }
        return false;
    }
    return true;
}

/* ============================================================================
 * Query Policy: NIP-42 auth-required / restricted for REQ/COUNT
 * ============================================================================ */

/* Check if a filter targets kinds that require authentication (e.g., DMs kind 4).
 * Returns true if the filter targets restricted kinds. */
static bool nip42_filter_requires_auth(const filter_t *filter) {
    if (!filter) return false;
    
    /* Kind 4 (encrypted direct messages) requires auth per NIP-42 */
    for (size_t i = 0; i < filter->kinds_count; i++) {
        if (filter->kinds[i] == 4) return true;
        /* Add other restricted kinds here as needed */
    }
    return false;
}

/* Check if an authenticated pubkey is authorized for a filter.
 * For DMs (kind 4), the pubkey must be a participant: either listed in
 * the filter's authors or in its 'p' tags. A wildcard kind-4 query with
 * neither is overly broad and must be rejected (no full-table DM leak). */
static bool nip42_is_authorized_for_filter(connection_id_t connection_id,
                                            const filter_t *filter,
                                            const char *auth_pubkey) {
    (void)connection_id;
    if (!filter || !auth_pubkey) return false;
    
    /* For kind 4, check if the authenticated pubkey is a participant */
    for (size_t i = 0; i < filter->kinds_count; i++) {
        if (filter->kinds[i] == 4) {
            /* Participant as author */
            for (size_t a = 0; a < filter->authors_count; a++) {
                if (filter->authors[a] && strcmp(filter->authors[a], auth_pubkey) == 0) {
                    return true;
                }
            }
            /* Participant as 'p' tag */
            for (size_t t = 0; t < filter->tags_count; t++) {
                const tag_t *tag = &filter->tags[t];
                if (tag->count > 1 && tag->elements[0] && strcmp(tag->elements[0], "p") == 0) {
                    for (size_t v = 1; v < tag->count; v++) {
                        if (tag->elements[v] && strcmp(tag->elements[v], auth_pubkey) == 0) {
                            return true; /* Participant in the DM conversation */
                        }
                    }
                }
            }
            return false; /* Kind 4 but not a participant */
        }
    }
    return true; /* Non-restricted kind or no kind filter */
}

/* True if ANY authenticated pubkey on this connection authorizes the filter.
 * NIP-42: "Clients MAY provide signed events from multiple pubkeys...
 * Relays MUST treat all pubkeys as authenticated accordingly." */
static bool nip42_any_pubkey_authorizes(connection_id_t connection_id,
                                        const filter_t *filter) {
    size_t n = nip_env_session_auth_count(connection_id);
    size_t i;
    for (i = 0; i < n; i++) {
        const char *pk = nip_env_session_auth_at(connection_id, i);
        if (pk && nip42_is_authorized_for_filter(connection_id, filter, pk)) {
            return true;
        }
    }
    return false;
}

/* Query authorization hook: called before query execution.
 * Returns true to allow, false to reject with CLOSED message.
 * Fills reason buffer with appropriate prefix (auth-required: or restricted:) */
static bool nip42_query_authorize_fn(connection_id_t connection_id, filter_t *filters, size_t count,
                                     char *reason, size_t reason_size, void *ctx) {
    (void)ctx;

    if (!filters || count == 0) return true;

    {
        nip42_ctx_t *cap_ctx = (nip42_ctx_t *)ctx;
        if (cap_ctx && !cap_ctx->enabled) return true;
    }
    /* Check if any filter requires authentication */
    bool requires_auth = false;
    for (size_t i = 0; i < count; i++) {
        if (nip42_filter_requires_auth(&filters[i])) {
            requires_auth = true;
            break;
        }
    }
    
    if (!requires_auth) return true; /* No auth needed for this query */
    
    /* Check if connection is authenticated (ANY pubkey counts per NIP-42). */
    const char *auth_pubkey = nip42_authenticated_pubkey_by_id(connection_id);
    if (!auth_pubkey) {
        log_debug("NIP", "QUERY_AUTH", "connection_id=%llu auth-required (no auth)", (unsigned long long)connection_id);
        if (reason && reason_size > 0) {
            snprintf(reason, reason_size, "auth-required: we can't serve DMs to unauthenticated users");
        }
        return false; /* Will trigger CLOSED with auth-required */
    }
    
    /* Check if ANY authenticated pubkey is authorized for the restricted filters */
    bool authorized = false;
    for (size_t i = 0; i < count; i++) {
        if (nip42_filter_requires_auth(&filters[i]) &&
            nip42_any_pubkey_authorizes(connection_id, &filters[i])) {
            authorized = true;
            break;
        }
        if (!nip42_filter_requires_auth(&filters[i])) {
            authorized = true;
            break;
        }
    }
    
    if (!authorized) {
        log_debug("NIP", "QUERY_AUTH", "connection_id=%llu restricted (auth=%s)", (unsigned long long)connection_id, auth_pubkey);
        if (reason && reason_size > 0) {
            snprintf(reason, reason_size, "restricted: authenticated pubkey not authorized for this query");
        }
        return false; /* Will trigger CLOSED with restricted */
    }
    
    log_debug("NIP", "QUERY_AUTH", "connection_id=%llu authorized (auth=%s)", (unsigned long long)connection_id, auth_pubkey);
    return true;
}

/* Query modify hook: called after query execution.
 * Can add auth hint to EOSE if needed. */
static bool nip42_query_modify_fn(connection_id_t connection_id, const filter_t *filters, size_t count,
                                  bool has_more, int total_count, void *ctx) {
    (void)connection_id;
    (void)filters;
    (void)count;
    (void)has_more;
    (void)total_count;
    (void)ctx;
    /* No result modification needed; auth hint handled by protocol_response capability */
    return true;
}

/* ============================================================================
 * Registration (using macro to eliminate boilerplate)
 * ============================================================================ */

NIP_REGISTER(nip42, nip42_caps)
