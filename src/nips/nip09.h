#ifndef NIP09_H_
#define NIP09_H_

#include <stdbool.h>
#include "storage.h"

/* Apply the authorized targets in a NIP-09 deletion event. */
bool nip09_delete_targets(const event_t *event, storage_context_t *storage);

/* Register this NIP's event listener(s) with the NIP-01 dispatcher. */
void nip09_register_listeners(void);

#endif /* NIP09_H_ */