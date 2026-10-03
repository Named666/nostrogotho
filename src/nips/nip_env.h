#ifndef NIP_ENV_H_
#define NIP_ENV_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "nostrogotho.h"
#include "relay/connection_session.h"

/* ============================================================================
 * NIP_ENV.H - Unified host environment for NIP code
 *
 * NIP files call ONLY these helpers for transport, session-auth state, and
 * event validation. The same calls work in monolithic builds and in hot-
 * reload module builds: nip_env.c selects the backend (direct relay calls
 * vs. Nhr_Host shims) in the single #ifdef in this module. NIP .c files
 * must not include relay/relay.h, relay/connection_session.h, crypto.h, or
 * nhr_module.h directly, and must not test NHR_BUILD_MODULE themselves.
 *
 * Borrowed strings follow the session lifetime rule: valid until the next
 * session mutation for that connection; copy them if retained.
 * ============================================================================ */

/* Send a JSON frame to a connection by opaque ID. No-op when unknown. */
void nip_env_send_json(connection_id_t connection_id, const char *json);

/* NIP-42 challenge / auth-pubkey session state (host-owned, survives reload). */
const char *nip_env_session_challenge(connection_id_t connection_id);
bool nip_env_session_set_challenge(connection_id_t connection_id,
                                   const char *challenge);
const char *nip_env_session_auth_pubkey(connection_id_t connection_id);
bool nip_env_session_set_auth(connection_id_t connection_id,
                              const char *pubkey);
bool nip_env_session_add_auth(connection_id_t connection_id,
                              const char *pubkey);
bool nip_env_session_has_auth(connection_id_t connection_id,
                              const char *pubkey);
size_t nip_env_session_auth_count(connection_id_t connection_id);
const char *nip_env_session_auth_at(connection_id_t connection_id,
                                    size_t index);
void nip_env_session_clear_auth(connection_id_t connection_id);

/* Enumerate live host sessions (id + transport handle pairs). */
size_t nip_env_session_snapshot(connection_snapshot_t *out, size_t capacity);

/* Full event validation: ID + signature + NIP-26 delegation, in every build.
 * (Module builds forward crypto to the host and check delegation locally,
 * mirroring host check_event().) */
bool nip_env_accepts_event(const event_t *event);

/* Count leading zero bits in a hex string (for NIP-13 PoW). */
unsigned nip_env_count_leading_zero_bits(const char *hex);

#endif /* NIP_ENV_H_ */
