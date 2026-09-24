#ifndef NIP42_H_
#define NIP42_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <mongoose.h>
#include "nostrogotho.h"

typedef struct {
    uintptr_t id;
    struct mg_connection *connection;
} nip42_connection_t;

/* Create and track a NIP-42 challenge for a newly opened connection. */
bool nip42_open(struct mg_connection *connection, char challenge[17]);
/* Generate a fresh challenge for an already-tracked connection (NIP-67 auth
 * hint path). Returns false when the connection has no client record. */
bool nip42_open_challenge(struct mg_connection *connection, char challenge[17]);
/* Discard all authentication state when a connection closes. */
void nip42_close(struct mg_connection *connection);
/* Return the authenticated pubkey for a connection, or NULL when unauthenticated. */
const char *nip42_authenticated_pubkey(struct mg_connection *connection);
/* Validate and record a NIP-42 authentication event. */
bool nip42_authenticate(struct mg_connection *connection, const event_t *event,
                        const char *service_url, time_t now);

/* Explicit NIP-42 module state migration. `host` owns the returned blob and
 * the caller frees it with the corresponding host allocator. */
typedef struct {
    uint32_t version;
    uint32_t count;
    struct {
        uintptr_t connection_id;
        char challenge[17];
        char pubkey[MAX_PUBKEY_SIZE + 1];
    } clients[1024];
} nip42_state_t;
bool nip42_save_state(nip42_state_t *state,
                      const nip42_connection_t *connections,
                      size_t connection_count);
bool nip42_restore_state(const nip42_state_t *state,
                         const nip42_connection_t *connections,
                         size_t connection_count);

#endif /* NIP42_H_ */