#include "nip62.h"
#include "nip_event.h"
bool nip62_should_vanish(const event_t *event, const char *service_url) {
    return nip_event_has_tag(event, "relay", "ALL_RELAYS") ||
           (service_url && *service_url && nip_event_has_relay_tag(event, service_url));
}