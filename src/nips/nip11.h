#ifndef NIP11_H_
#define NIP11_H_

#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/*
 * NIP-11 Relay Information Document
 *
 * The document is built from the relay's actual runtime configuration so the
 * advertised capabilities are always honest. Call nip11_configure() once at
 * startup (server_configure does this); nip11_information_document() then
 * returns the rendered JSON. Transport code owns HTTP negotiation and uses
 * this payload only after Accept matching.
 */

/* nip11_configure - Provide the values advertised in the information document.
 *
 * All fields are optional; pass zero/false/empty for "not set" and the field
 * is omitted (or reported as disabled) in the document.
 */
void nip11_configure(int max_message_length, int max_subscriptions,
                     int max_filters, int max_subid_length,
                     int max_event_tags, int max_content_length,
                     int min_pow_difficulty, int max_limit, int default_limit,
                     time_t created_at_lower_limit,
                     time_t created_at_upper_limit, bool auth_required);

/* nip11_information_document - Render the NIP-11 document.
 * Returns a pointer to a static buffer valid until the next call. */
const char *nip11_information_document(void);

#endif /* NIP11_H_ */