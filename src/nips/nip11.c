#include "nip11.h"

/* Keep protocol claims next to the NIP implementation rather than the HTTP loop. */
const char *nip11_information_document(void) {
    return "{\"name\":\"nostrogotho\",\"supported_nips\":[1,9,11,13,16,26,33,40,62,67],"
           "\"limitation\":{\"max_message_length\":5242880,\"max_subscriptions\":20,"
           "\"max_filters\":10,\"max_limit\":500}}";
}