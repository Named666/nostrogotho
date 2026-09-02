#include "nip17.h"
#include "nip_event.h"
bool nip17_can_deliver(const event_t *event, const char *authenticated_pubkey) {
    return (event->kind != 1059 && event->kind != 21059) ||
           (authenticated_pubkey && nip_event_has_tag(event, "p", authenticated_pubkey));
}