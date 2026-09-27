#ifndef CONNECTION_SESSION_H_
#define CONNECTION_SESSION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <mongoose.h>
#include "nostrogotho.h"

/* ============================================================================
 * CONNECTION_SESSION.H - Connection/Session Abstraction
 * 
 * Unified connection state owned by relay/protocol layer.
 * Replaces NIP-42's hidden global client list.
 * ============================================================================ */

typedef struct connection_session connection_session_t;

/* Opaque connection ID type */
typedef uintptr_t connection_id_t;

/* Connection snapshot for hot-reload state preservation */
typedef struct connection_snapshot {
    uintptr_t id;
    void *connection;
} connection_snapshot_t;

/* Authentication state */
typedef enum {
    AUTH_STATE_NONE = 0,
    AUTH_STATE_CHALLENGED,
    AUTH_STATE_AUTHENTICATED
} auth_state_t;

/* Create a new session for a connection, returns the connection ID */
connection_id_t connection_session_create(uintptr_t connection_id,
                                          struct mg_connection *connection);

/* Destroy a session */
void connection_session_destroy(connection_session_t *session);

/* Get session by connection ID */
connection_session_t *connection_session_get(uintptr_t connection_id);

/* Get session by Mongoose connection pointer */
connection_session_t *connection_session_get_by_mg_connection(struct mg_connection *connection);

/* Get authenticated pubkey */
const char *connection_session_get_auth_pubkey(connection_session_t *session);

/* Set authenticated pubkey */
void connection_session_set_auth(connection_session_t *session, const char *pubkey);

/* Set/get challenge for NIP-42 */
void connection_session_set_challenge(connection_session_t *session, const char *challenge);
const char *connection_session_get_challenge(connection_session_t *session);

/* Get/set authentication state */
void connection_session_set_auth_state(connection_session_t *session, auth_state_t state);
auth_state_t connection_session_get_auth_state(connection_session_t *session);

/* Store per-connection protocol state */
void connection_session_set_protocol_state(connection_session_t *session, void *state);
void *connection_session_get_protocol_state(connection_session_t *session);

/* Get connection ID */
uintptr_t connection_session_get_id(connection_session_t *session);

/* Get Mongoose connection */
struct mg_connection *connection_session_get_mg_connection(connection_session_t *session);

/* Iterate all active sessions */
typedef void (*connection_session_iter_fn)(connection_session_t *session, void *userdata);
void connection_session_iterate(connection_session_iter_fn fn, void *userdata);

/* Clean up all sessions */
void connection_session_cleanup_all(void);

/* Snapshot all connections for hot-reload state preservation */
size_t connection_session_snapshot(connection_snapshot_t *connections, size_t capacity);

/* Restore connections from snapshot after hot-reload */
bool connection_session_restore(const connection_snapshot_t *connections, size_t count);

#endif /* CONNECTION_SESSION_H_ */