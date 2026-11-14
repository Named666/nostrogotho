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
/* True when tag's first element is the string name; *value is then the
 * second element's raw token (buf NULL if absent). Never allocates. */
bool nip_tag_named(jstr_t tag, const char *name, jstr_t *value);
/* Second element of the first tag named name (malloc'd), NULL if none. */
char *nip_event_tag_value(const event_t *event, const char *name);

#endif /* NIP_EVENT_H_ */