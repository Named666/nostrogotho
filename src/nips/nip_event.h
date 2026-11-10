#ifndef NIP_EVENT_H_
#define NIP_EVENT_H_

#include <stdbool.h>
#include "json_lite.h"
#include "relay_conn.h"
#include "nostrogotho.h"

/* Shared event-tag queries used by independent NIP policy modules. */
bool nip_event_has_tag(const event_t *event, const char *name, const char *value);
/* A ["relay", url] tag equal to relay (case-insensitive, trailing '/'
 * ignored). relay == "" matches any ws:// or wss:// URL (relay_url unset). */
bool nip_event_has_relay_tag(const event_t *event, const char *relay);
char *nip_tag_element(jstr_t tag, size_t index);
/* Second element of the first tag named name (malloc'd), NULL if none. */
char *nip_event_tag_value(const event_t *event, const char *name);

#endif /* NIP_EVENT_H_ */