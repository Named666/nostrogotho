/* ============================================================================
 * NIP_ENV.C - Unified host environment for NIP code
 *
 * This is the ONLY file in src/nips/ that branches on NHR_BUILD_MODULE.
 * Host builds call the relay/session/crypto layer directly; module builds
 * forward to the host through the nhr_module_* shims (Nhr_Host services).
 * Every other NIP file calls nip_env_* unconditionally.
 * ============================================================================ */

#include "nips/nip_env.h"
#include <string.h>
#ifdef NHR_BUILD_MODULE
#include "nhr_module.h"
#else
#include "crypto.h"
#include "relay/relay.h"
#endif

void nip_env_send_json(connection_id_t connection_id, const char *json) {
    if (!json) return;
#ifdef NHR_BUILD_MODULE
    nhr_module_send_json(connection_id, json, strlen(json));
#else
    relay_send_json(connection_id, json);
#endif
}

const char *nip_env_session_challenge(connection_id_t connection_id) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_challenge(connection_id);
#else
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_challenge(session) : NULL;
#endif
}

bool nip_env_session_set_challenge(connection_id_t connection_id,
                                   const char *challenge) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_set_challenge(connection_id, challenge);
#else
    connection_session_t *session = connection_session_get(connection_id);
    if (!session) return false;
    connection_session_set_challenge(session, challenge);
    return true;
#endif
}

const char *nip_env_session_auth_pubkey(connection_id_t connection_id) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_auth_pubkey(connection_id);
#else
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_auth_pubkey(session) : NULL;
#endif
}

bool nip_env_session_set_auth(connection_id_t connection_id,
                              const char *pubkey) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_set_auth(connection_id, pubkey);
#else
    connection_session_t *session = connection_session_get(connection_id);
    if (!session) return false;
    connection_session_set_auth(session, pubkey);
    return true;
#endif
}

bool nip_env_session_add_auth(connection_id_t connection_id,
                              const char *pubkey) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_add_auth(connection_id, pubkey);
#else
    connection_session_t *session = connection_session_get(connection_id);
    if (!session || !pubkey) return false;
    connection_session_add_auth_pubkey(session, pubkey);
    return true;
#endif
}

bool nip_env_session_has_auth(connection_id_t connection_id,
                              const char *pubkey) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_has_auth(connection_id, pubkey);
#else
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_has_auth_pubkey(session, pubkey) : false;
#endif
}

size_t nip_env_session_auth_count(connection_id_t connection_id) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_auth_count(connection_id);
#else
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_auth_pubkey_count(session) : 0;
#endif
}

const char *nip_env_session_auth_at(connection_id_t connection_id,
                                    size_t index) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_auth_at(connection_id, index);
#else
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_auth_pubkey_at(session, index) : NULL;
#endif
}

void nip_env_session_clear_auth(connection_id_t connection_id) {
#ifdef NHR_BUILD_MODULE
    nhr_module_session_clear_auth(connection_id);
#else
    connection_session_t *session = connection_session_get(connection_id);
    if (!session) return;
    connection_session_set_auth(session, NULL);
    connection_session_set_challenge(session, NULL);
#endif
}

size_t nip_env_session_snapshot(connection_snapshot_t *out, size_t capacity) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_session_snapshot(out, capacity);
#else
    if (!out || !capacity) return 0;
    return connection_session_snapshot(out, capacity);
#endif
}

bool nip_env_accepts_event(const event_t *event) {
#ifdef NHR_BUILD_MODULE
    return nhr_module_accepts_event(event);
#else
    return check_event(event);
#endif
}
