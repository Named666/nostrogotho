#include "protocol.h"
#include "json_util.h"
#include "nostrogotho.h"
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * PROTOCOL.C - Nostr Protocol Parsing and Serialization Implementation
 * ============================================================================ */

void protocol_message_free(protocol_message_t *msg) {
    if (!msg) return;
    
    switch (msg->command) {
        case PROTOCOL_CMD_EVENT:
            event_release(&msg->payload.event.event);
            break;
        case PROTOCOL_CMD_REQ:
            free(msg->payload.req.subscription_id);
            for (size_t i = 0; i < msg->payload.req.filters_count; i++) {
                filter_release(&msg->payload.req.filters[i]);
            }
            free(msg->payload.req.filters);
            break;
        case PROTOCOL_CMD_CLOSE:
            free(msg->payload.close.subscription_id);
            break;
        case PROTOCOL_CMD_AUTH:
            free(msg->payload.auth.challenge);
            if (msg->payload.auth.has_event) {
                event_release(&msg->payload.auth.event);
            }
            break;
        case PROTOCOL_CMD_COUNT:
            free(msg->payload.count.subscription_id);
            for (size_t i = 0; i < msg->payload.count.filters_count; i++) {
                filter_release(&msg->payload.count.filters[i]);
            }
            free(msg->payload.count.filters);
            break;
        default:
            break;
    }
    memset(msg, 0, sizeof(*msg));
}

bool
protocol_collect_filters(json_value_t *values, size_t count, filter_t **out,
                         size_t *out_count, size_t max_filters) {
    filter_t *filters = NULL;
    size_t filter_capacity = 0;
    size_t idx = 0;
    uint8_t retval = 0;

    if (values == NULL || out == NULL || out_count == NULL) {
        return 0;
    }
    *out = NULL;
    *out_count = 0;
    if (count >= 3 && values[2].type == JSON_TYPE_ARRAY) {
        json_value_t inner[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
        size_t inner_count = 0;
        if (values[2].value.string_val == NULL) {
            return 0;
        }
        inner_count = json_array_parse(values[2].value.string_val, inner, MAX_JSON_ARRAY_ELEMENTS);
        if (inner_count == 0) {
            json_array_free(inner, inner_count);
            return 0;
        }
        filter_capacity = inner_count;
        filters = calloc(filter_capacity, sizeof(*filters));
        if (filters == NULL) {
            json_array_free(inner, inner_count);
            return 0;
        }
        for (idx = 0; idx < inner_count; ++idx) {
            if (inner[idx].type == JSON_TYPE_OBJECT && inner[idx].value.string_val != NULL) {
                if (*out_count >= max_filters) {
                    /* Strict limit: more valid filters than allowed. The old
                     * code silently truncated, so an over-limit REQ was
                     * accepted with filters missing (and the manager-side
                     * limit check was dead code). Release and reject. */
                    for (size_t r = 0; r < *out_count; r++) filter_release(&filters[r]);
                    free(filters);
                    json_array_free(inner, inner_count);
                    return 0;
                }
                if (json_parse_filter(inner[idx].value.string_val, &filters[*out_count])) {
                    (*out_count)++;
                } else {
                    filter_release(&filters[*out_count]);
                    memset(&filters[*out_count], 0, sizeof(filters[*out_count]));
                }
            }
        }
        json_array_free(inner, inner_count);
    } else {
        if (count <= 2) {
            return 0;
        }
        filter_capacity = count - 2;
        filters = calloc(filter_capacity, sizeof(*filters));
        if (filters == NULL) {
            return 0;
        }
        for (idx = 2; idx < count; ++idx) {
            if (values[idx].type == JSON_TYPE_OBJECT && values[idx].value.string_val != NULL) {
                if (*out_count >= max_filters) {
                    /* Strict limit (see array form above). */
                    for (size_t r = 0; r < *out_count; r++) filter_release(&filters[r]);
                    free(filters);
                    return 0;
                }
                if (json_parse_filter(values[idx].value.string_val, &filters[*out_count])) {
                    (*out_count)++;
                } else {
                    filter_release(&filters[*out_count]);
                    memset(&filters[*out_count], 0, sizeof(filters[*out_count]));
                }
            }
        }
    }
    if (*out_count == 0) {
        free(filters);
        filters = NULL;
        return 0;
    }
    *out = filters;
    retval = 1;
    return retval;
}

/**
 * \brief           Duplicate finished builder output onto the heap
 * \param[in]       builder: Finished builder with NUL-terminated buffer
 * \return          Heap-allocated copy, `NULL` on allocation failure
 */
static char*
prv_builder_dup(const json_builder_t *builder) {
    const char *tmp = NULL;
    char *dup = NULL;
    if (builder == NULL) {
        return NULL;
    }
    /* json_builder_finish takes non-const in header; buffer is read-only here */
    tmp = json_builder_finish((json_builder_t *)builder);
    if (tmp == NULL) {
        return NULL;
    }
    dup = malloc(strlen(tmp) + 1);
    if (!dup) return NULL;
    strcpy(dup, tmp);
    return dup;
}

/**
 * \brief           Serialize an `OK` response
 * \param[in]       event_id: Event id string
 * \param[in]       accepted: `1` if accepted, `0` otherwise
 * \param[in]       reason: Human-readable reason
 * \return          Heap-allocated JSON string, `NULL` on failure
 */
char*
protocol_serialize_ok(const char *event_id, bool accepted, const char *reason) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "OK");
    json_builder_append_string(&builder, event_id != NULL ? event_id : "");
    json_builder_append_bool(&builder, accepted);
    json_builder_append_string(&builder, reason != NULL ? reason : "");
    return prv_builder_dup(&builder);
}

/**
 * \brief           Serialize an `EVENT` response
 * \param[in]       subscription_id: Subscription id
 * \param[in]       event: Event to serialize
 * \return          Heap-allocated JSON string, `NULL` on failure
 */
char*
protocol_serialize_event(const char *subscription_id, const event_t *event) {
    json_builder_t builder;
    if (event == NULL) {
        return NULL;
    }
    json_builder_start(&builder);
    json_builder_append_string(&builder, "EVENT");
    json_builder_append_string(&builder, subscription_id != NULL ? subscription_id : "");
    json_serialize_event(event, &builder);
    return prv_builder_dup(&builder);
}

/**
 * \brief           Serialize an `EOSE` response
 * \param[in]       subscription_id: Subscription id
 * \param[in]       has_more: `1` if more data follows
 * \param[in]       auth_hint: `1` if auth is required
 * \return          Heap-allocated JSON string, `NULL` on failure
 */
char*
protocol_serialize_eose(const char *subscription_id, bool has_more, bool auth_hint) {
    json_builder_t builder;
    const char *status = "finish";
    if (auth_hint) {
        status = "auth";
    } else if (has_more) {
        status = "more";
    }
    json_builder_start(&builder);
    json_builder_append_string(&builder, "EOSE");
    json_builder_append_string(&builder, subscription_id != NULL ? subscription_id : "");
    json_builder_start_array(&builder);
    json_builder_append_string(&builder, status);
    json_builder_end_array(&builder);
    return prv_builder_dup(&builder);
}

/**
 * \brief           Serialize a `COUNT` response
 * \param[in]       subscription_id: Subscription id
 * \param[in]       count: Matching event count
 * \return          Heap-allocated JSON string, `NULL` on failure
 */
char*
protocol_serialize_count(const char *subscription_id, unsigned long count) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "COUNT");
    json_builder_append_string(&builder, subscription_id != NULL ? subscription_id : "");
    json_builder_start_object(&builder);
    json_builder_object_key_number(&builder, "count", (long long)count);
    json_builder_end_object(&builder);
    return prv_builder_dup(&builder);
}

/**
 * \brief           Serialize a `CLOSED` response
 * \param[in]       subscription_id: Subscription id
 * \param[in]       ok: `1` if clean close
 * \param[in]       reason: Human-readable reason
 * \return          Heap-allocated JSON string, `NULL` on failure
 */
char*
protocol_serialize_closed(const char *subscription_id, bool ok, const char *reason) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "CLOSED");
    json_builder_append_string(&builder, subscription_id != NULL ? subscription_id : "");
    json_builder_append_bool(&builder, ok);
    json_builder_append_string(&builder, reason != NULL ? reason : "");
    return prv_builder_dup(&builder);
}

/**
 * \brief           Serialize a `NOTICE` response
 * \param[in]       message: Notice text
 * \return          Heap-allocated JSON string, `NULL` on failure
 */
char*
protocol_serialize_notice(const char *message) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "NOTICE");
    json_builder_append_string(&builder, message != NULL ? message : "");
    return prv_builder_dup(&builder);
}

/**
 * \brief           Serialize an `AUTH` challenge
 * \param[in]       challenge: Challenge string
 * \return          Heap-allocated JSON string, `NULL` on failure
 */
char*
protocol_serialize_auth(const char *challenge) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "AUTH");
    json_builder_append_string(&builder, challenge != NULL ? challenge : "");
    return prv_builder_dup(&builder);
}

/**
 * \brief           Free a string returned by `protocol_serialize_*`
 * \param[in]       str: Heap string to free, `NULL`-safe
 */
void
protocol_free_string(char *str) {
    if (str == NULL) {
        return;
    }
    free(str);
}