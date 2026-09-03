#ifndef NIP42_H_
#define NIP42_H_

#include <stdbool.h>
#include <time.h>
#include <mongoose.h>
#include "nostrogotho.h"

/* Create and track a NIP-42 challenge for a newly opened connection. */
bool nip42_open(struct mg_connection *connection, char challenge[17]);
/* Discard all authentication state when a connection closes. */
void nip42_close(struct mg_connection *connection);
/* Return the authenticated pubkey for a connection, or NULL when unauthenticated. */
const char *nip42_authenticated_pubkey(struct mg_connection *connection);
/* Validate and record a NIP-42 authentication event. */
bool nip42_authenticate(struct mg_connection *connection, const event_t *event,
                        const char *service_url, time_t now);

#endif /* NIP42_H_ */