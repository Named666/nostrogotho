#ifndef SERVER_H_
#define SERVER_H_

#include <stdbool.h>
#include <time.h>

#include "storage.h"
#include "nhr.h"

bool server_make_relay_config(storage_context_t *storage, const char *relay_url,
							  int min_pow, time_t lower_limit,
							  time_t upper_limit, relay_config_t *config);
bool server_run_hot(int port, Nhr_Runtime *runtime,
					const char *published_module_path);

void server_configure(storage_context_t *storage, const char *relay_url,
					  int min_pow_difficulty, time_t created_at_lower_limit,
					  time_t created_at_upper_limit);

/* Enable or disable console debug logging (connect/disconnect/event traces). */
void server_set_debug(bool enabled);

/* Run the relay listener until it is stopped or its event loop exits. */
bool server_run(int port);

/* Request that a running relay event loop exits. */
void server_stop(void);

#endif /* SERVER_H_ */