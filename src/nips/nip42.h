#ifndef NIP42_H_
#define NIP42_H_

#include <stdbool.h>
#include <time.h>
#include "json_lite.h"
#include "relay_conn.h"
#include "nostrogotho.h"

/* Create and track a NIP-42 challenge for a newly opened connection. */
bool nip42_open(relay_conn_t *connection, char challenge[17]);
/* Generate a fresh challenge for an already-tracked connection (NIP-67 auth
 * hint path). Returns false when the connection has no client record. */
bool nip42_open_challenge(relay_conn_t *connection, char challenge[17]);
/* Discard all authentication state when a connection closes. */
void nip42_close(relay_conn_t *connection);
/* Return the authenticated pubkey for a connection, or NULL when unauthenticated. */
const char *nip42_authenticated_pubkey(relay_conn_t *connection);
/* Validate and record a NIP-42 authentication event. */
bool nip42_authenticate(relay_conn_t *connection, const event_t *event,
                        const char *service_url, time_t now);

#endif /* NIP42_H_ */