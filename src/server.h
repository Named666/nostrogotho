#ifndef SERVER_H_
#define SERVER_H_

#include <stdbool.h>

#include "ng_config.h"
#include "storage.h"

/* Relay server entry points (backend_ngws.c + server.c).
 * Threading: configure / set_debug / set_config are called from the main
 * thread before server_run; server_run blocks that thread until the relay
 * stops; server_stop is safe from any thread or a signal-handling thread.
 * Ownership: storage stays the caller's and must outlive server_run;
 * config and strings are copied. */

void server_configure(storage_context_t *storage, const char *relay_url,
					  int min_pow_difficulty, time_t created_at_lower_limit,
					  time_t created_at_upper_limit);

/* Enable or disable console debug logging (connect/disconnect/event traces). */
void server_set_debug(bool enabled);

/* Runtime options parsed from nostrogotho.conf (config.h); copied. Call
 * before server_run (not thread-safe with a running server). */
void server_set_config(const ng_config_t *cfg);

/* Run the relay listener until it is stopped or its event loop exits. */
bool server_run(int port);

/* Request that a running relay event loop exits. */
void server_stop(void);

#endif /* SERVER_H_ */