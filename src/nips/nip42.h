#ifndef NIP42_H_
#define NIP42_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "nostrogotho.h"
#include "relay/connection_session.h"

/* ============================================================================
 * NIP-42: Relay Authentication — Public API
 *
 * Connection-ID auth API only (state lives in host-owned sessions, survives
 * reload with no migration blob per PLAN 1.1 stateless reload). Capability
 * registration and internals remain in nip42.c.
 * ============================================================================ */

/* Connection-ID auth API (state lives in host-owned sessions). */
bool nip42_open_by_id(connection_id_t connection_id, char challenge[17]);
bool nip42_open_challenge_by_id(connection_id_t connection_id, char challenge[17]);
void nip42_close_by_id(connection_id_t connection_id);
const char *nip42_authenticated_pubkey_by_id(connection_id_t connection_id); /* Returns first pubkey for backward compat */
bool nip42_is_pubkey_authenticated(connection_id_t connection_id, const char *pubkey); /* Check if specific pubkey is authenticated */
bool nip42_authenticate_by_id(connection_id_t connection_id, const event_t *event,
                              const char *service_url, time_t now);

/* Send an auth challenge on demand (per NIP-42: "At any moment the relay may send an AUTH message") */
bool nip42_send_auth_challenge(connection_id_t connection_id);

/* (No save/restore blob: sessions are host-owned and survive reload untouched.) */
/* save/restore removed: stateless reload per PLAN 1.1. */

#endif /* NIP42_H_ */