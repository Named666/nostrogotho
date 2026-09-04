#include <mongoose.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nip_event.h"

/* The tag slice yielded by mg_json_next is itself a complete JSON array
 * (e.g. ["d","<identifier>"]), so element extraction is a plain $[index]
 * lookup on it. Wrapping the slice in another bracket pair would make
 * $[index] resolve to an array, which mg_json_get_str rejects with NULL. */
char *nip_tag_element(struct mg_str tag, size_t index) {
    char path[16];
    snprintf(path, sizeof(path), "$[%llu]", (unsigned long long) index);
    return mg_json_get_str(tag, path);
}

bool nip_event_has_tag(const event_t *event, const char *name, const char *value) {
    struct mg_str key, tag, tags = mg_str(event->tags_json); size_t offset = 0;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *tag_name = nip_tag_element(tag, 0), *tag_value = nip_tag_element(tag, 1);
        bool found = tag_name && strcmp(tag_name, name) == 0 && (!value || (tag_value && strcmp(tag_value, value) == 0));
        free(tag_name); free(tag_value); if (found) return true;
    }
    return false;
}

bool nip_event_has_relay_tag(const event_t *event, const char *relay) {
    struct mg_str key, tag, tags = mg_str(event->tags_json); size_t offset = 0, relay_length = strlen(relay);
    while (relay_length && relay[relay_length - 1] == '/') relay_length--;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0), *value = nip_tag_element(tag, 1); size_t value_length = value ? strlen(value) : 0;
        while (value_length && value[value_length - 1] == '/') value_length--;
        bool found = name && value && strcmp(name, "relay") == 0 && value_length == relay_length && memcmp(value, relay, relay_length) == 0;
        free(name); free(value); if (found) return true;
    }
    return false;
}