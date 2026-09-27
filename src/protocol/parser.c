#include "protocol/parser.h"
#include "protocol/protocol.h"
#include "json_util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdio.h>

bool protocol_parse_client_message(const char *data, size_t length,
                                   const relay_config_t *config,
                                   protocol_message_t *out,
                                   char *reject_reason, size_t reason_size) {
    if (!data || !out || !config) return false;

    if (length > config->max_ws_message_length) {
        if (reject_reason && reason_size) {
            snprintf(reject_reason, reason_size, "error: message too large");
        }
        return false;
    }

    json_value_t values[MAX_JSON_ARRAY_ELEMENTS] = {{0}};
    char *payload = malloc(length + 1);
    if (!payload) return false;
    memcpy(payload, data, length);
    payload[length] = '\0';

    size_t count = json_array_parse(payload, values, MAX_JSON_ARRAY_ELEMENTS);
    const char *method = json_array_get_string(values, count, 0);

    bool result = false;
    if (!method || count < 2) {
        if (reject_reason && reason_size) {
            snprintf(reject_reason, reason_size, "error: invalid request");
        }
        goto cleanup;
    }

    memset(out, 0, sizeof(*out));

    if (strcmp(method, "REQ") == 0) {
        const char *sub = json_array_get_string(values, count, 1);
        filter_t *filters = NULL;
        size_t filter_count = 0;

        if (!sub || strlen(sub) > config->max_subscription_id_length || count < 3 ||
            !protocol_collect_filters(values, count, &filters, &filter_count,
                                      (size_t)config->max_filters_per_subscription)) {
            if (reject_reason && reason_size) {
                snprintf(reject_reason, reason_size, "error: invalid filter");
            }
            goto cleanup;
        }

        out->command = PROTOCOL_CMD_REQ;
        out->payload.req.subscription_id = strdup(sub);
        out->payload.req.filters = filters;
        out->payload.req.filters_count = filter_count;
        result = true;

    } else if (strcmp(method, "COUNT") == 0) {
        const char *sub = json_array_get_string(values, count, 1);
        filter_t *filters = NULL;
        size_t filter_count = 0;

        if (!sub || strlen(sub) > config->max_subscription_id_length || count < 3 ||
            !protocol_collect_filters(values, count, &filters, &filter_count,
                                      (size_t)config->max_filters_per_subscription)) {
            if (reject_reason && reason_size) {
                snprintf(reject_reason, reason_size, "error: invalid filter");
            }
            goto cleanup;
        }

        out->command = PROTOCOL_CMD_COUNT;
        out->payload.count.subscription_id = strdup(sub);
        out->payload.count.filters = filters;
        out->payload.count.filters_count = filter_count;
        result = true;

    } else if (strcmp(method, "CLOSE") == 0) {
        const char *sub = json_array_get_string(values, count, 1);
        if (!sub) {
            if (reject_reason && reason_size) {
                snprintf(reject_reason, reason_size, "error: invalid close");
            }
            goto cleanup;
        }
        out->command = PROTOCOL_CMD_CLOSE;
        out->payload.close.subscription_id = strdup(sub);
        result = true;

    } else if (strcmp(method, "EVENT") == 0) {
        event_t event;
        if (count != 2 || values[1].type != JSON_TYPE_OBJECT || !json_parse_event(values[1].value.string_val, &event)) {
            if (reject_reason && reason_size) {
                snprintf(reject_reason, reason_size, "error: invalid event");
            }
            goto cleanup;
        }
        out->command = PROTOCOL_CMD_EVENT;
        out->payload.event.event = event;
        result = true;

    } else if (strcmp(method, "AUTH") == 0) {
        if (count != 2) {
            if (reject_reason && reason_size) {
                snprintf(reject_reason, reason_size, "error: invalid auth");
            }
            goto cleanup;
        }
        if (values[1].type == JSON_TYPE_OBJECT) {
            if (!json_parse_event(values[1].value.string_val, &out->payload.auth.event)) {
                if (reject_reason && reason_size) {
                    snprintf(reject_reason, reason_size, "error: invalid auth event");
                }
                goto cleanup;
            }
            out->payload.auth.has_event = true;
        } else {
            const char *challenge = json_array_get_string(values, count, 1);
            if (!challenge) {
                if (reject_reason && reason_size) {
                    snprintf(reject_reason, reason_size, "error: invalid auth");
                }
                goto cleanup;
            }
            out->payload.auth.challenge = strdup(challenge);
        }
        out->command = PROTOCOL_CMD_AUTH;
        result = true;
    } else {
        if (reject_reason && reason_size) {
            snprintf(reject_reason, reason_size, "error: invalid request");
        }
    }

cleanup:
    json_array_free(values, count);
    free(payload);
    return result;
}

void protocol_free_message(protocol_message_t *msg) {
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