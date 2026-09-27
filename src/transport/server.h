#ifndef SERVER_H_
#define SERVER_H_

#include <mongoose.h>
#include "relay/relay.h"

/* Transport layer: runs the Mongoose event loop and delegates to relay_t.
 * This is the sole owner of WebSocket/HTTP frame sending; upper layers call
 * transport_send_json() and never touch Mongoose transport directly. */

bool server_run_hot(int port, relay_t *relay, const char *published_module_path);
bool server_run(int port, relay_t *relay);
void server_stop(relay_t *relay);

/* Send a complete JSON frame over a WebSocket connection. No-op on NULLs. */
void transport_send_json(struct mg_connection *connection, const char *json);

#endif /* SERVER_H_ */