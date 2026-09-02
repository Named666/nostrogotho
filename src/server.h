#ifndef SERVER_H_
#define SERVER_H_

#include <stdbool.h>

#include "storage.h"

void server_configure(storage_context_t *storage, const char *relay_url,
					  int min_pow_difficulty, time_t created_at_lower_limit,
					  time_t created_at_upper_limit);

/* Run the relay listener until it is stopped or its event loop exits. */
bool server_run(int port);

/* Request that a running relay event loop exits. */
void server_stop(void);

#endif /* SERVER_H_ */