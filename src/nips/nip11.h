#ifndef NIP11_H_
#define NIP11_H_

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/*
 * NIP-11 Relay Information Document
 *
 * The document is built from the relay's actual runtime configuration so the
 * advertised capabilities are always honest. The plugin's init() hook
 * (server_configure) renders it once; nip11_information_document() then
 * returns the JSON. Transport code owns HTTP negotiation and uses
 * this payload only after Accept matching.
 */

/* nip11_information_document - Render the NIP-11 document.
 * Returns the document rendered at init ("{}" before), valid until the
 * next init. */
const char *nip11_information_document(void);

#endif /* NIP11_H_ */