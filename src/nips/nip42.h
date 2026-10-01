#ifndef NIP42_H_
#define NIP42_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "nostrogotho.h"
#include "relay/connection_session.h"

/* Forward declaration for transport handle (opaque, never dereferenced by NIP code) */
struct mg_connection;

/* ============================================================================
 * NIP-42: Relay Authentication — Public API
 * 
 * This header exposes the NIP-42 session/auth API and migration types needed
 * by nhr_module.c (reload state), nip17.c (delivery gating), and other NIPs.
 * The NIP-42 capability registration and internal logic remain in nip42.c.
 * ============================================================================ */

/* Opaque transport handle for migration (host-owned identity is the
 * connection_id_t; `connection` is the raw transport handle). */
typedef struct {
    uintptr_t id;
    struct mg_connection *connection;
} nip42_connection_t;

/* Versioned auth-state snapshot for reload migration. Host-allocated,
 * host-freed; empty state (count 0) is a valid reload, not a failure. */
typedef struct {
    uint32_t version;
    uint32_t count;
    struct {
        uintptr_t connection_id;
        char challenge[17];
        char pubkey[MAX_PUBKEY_SIZE + 1];
    } clients[1024];
} nip42_state_t;

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

/* State migration for hot reload (called by nhr_module.c). */
bool nip42_save_state(nip42_state_t *state,
                      const nip42_connection_t *connections,
                      size_t connection_count);
bool nip42_restore_state(const nip42_state_t *state,
                         const nip42_connection_t *connections,
                         size_t connection_count);

#endif /* NIP42_H_ */