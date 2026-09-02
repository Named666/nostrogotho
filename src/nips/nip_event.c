#include <mongoose.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nip_event.h"

char *nip_tag_element(struct mg_str tag, size_t index) {
    size_t length = tag.len + 3; char *json = malloc(length); char path[32]; char *value;
    if (!json) return NULL;
    json[0] = '['; memcpy(json + 1, tag.buf, tag.len); json[tag.len + 1] = ']'; json[tag.len + 2] = '\0';
    snprintf(path, sizeof(path), "$[%llu]", (unsigned long long) index);
    value = mg_json_get_str(mg_str(json), path); free(json); return value;
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