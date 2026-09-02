#ifndef NIP62_H_
#define NIP62_H_
#include <stdbool.h>
#include "cagliostr.h"
/* Check whether a Request to Vanish applies to this relay. */
bool nip62_should_vanish(const event_t *event, const char *service_url);
/* Register this NIP's event listener(s) with the NIP-01 dispatcher. */
void nip62_register_listeners(void);
#endif /* NIP62_H_ */