#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <stdbool.h>
#include <stddef.h>
#include "relay/config.h"
#include "nostrogotho.h"
#include "json_util.h"

/* ============================================================================
 * PROTOCOL.H - Nostr Protocol Parsing and Serialization
 * 
 * Separates wire JSON from internal protocol objects.
 * Provides strict boundary between transport and protocol logic.
 * ============================================================================ */

typedef enum {
    PROTOCOL_CMD_UNKNOWN = 0,
    PROTOCOL_CMD_EVENT,
    PROTOCOL_CMD_REQ,
    PROTOCOL_CMD_CLOSE,
    PROTOCOL_CMD_AUTH,
    PROTOCOL_CMD_COUNT
} protocol_command_t;

typedef struct {
    protocol_command_t command;
    union {
        struct {
            event_t event;
        } event;
        struct {
            char *subscription_id;
            filter_t *filters;
            size_t filters_count;
        } req;
        struct {
            char *subscription_id;
        } close;
        struct {
            /* Relay -> client challenge (string form, e.g. ["AUTH","<hex>"]).
             * NULL when this message carries a client AUTH response event. */
            char *challenge;
            /* Client -> relay AUTH response (object form,
             * e.g. ["AUTH",<signed kind:22242 event>). Valid iff has_event. */
            bool has_event;
            event_t event;
        } auth;
        struct {
            char *subscription_id;
            filter_t *filters;
            size_t filters_count;
        } count;
    } payload;
} protocol_message_t;

/* Free a protocol message and all owned resources */
void protocol_message_free(protocol_message_t *msg);

/* Wire-safety cap on filters per REQ/COUNT; relay policy may enforce a
 * smaller limit via the max_filters argument below. */
#define PROTOCOL_MAX_FILTERS 10

/* Collect REQ/COUNT filters from parsed wire values (flat or single nested
 * array form). Invalid filters are skipped. Returns false when no usable
 * filter remains; caller owns *out via filter_release + free. */
bool protocol_collect_filters(json_value_t *values, size_t count,
                              filter_t **out, size_t *out_count,
                              size_t max_filters);

/* Serialize an OK response */
char *protocol_serialize_ok(const char *event_id, bool accepted, const char *reason);

/* Serialize an EVENT response for a subscription */
char *protocol_serialize_event(const char *subscription_id, const event_t *event);

/* Serialize an EOSE response */
char *protocol_serialize_eose(const char *subscription_id, bool has_more, bool auth_hint);

/* Serialize a COUNT response */
char *protocol_serialize_count(const char *subscription_id, unsigned long count);

/* Serialize a CLOSED response */
char *protocol_serialize_closed(const char *subscription_id, bool ok, const char *reason);

/* Serialize a NOTICE response */
char *protocol_serialize_notice(const char *message);

/* Serialize an AUTH response */
char *protocol_serialize_auth(const char *challenge);

/* Free a serialized response string */
void protocol_free_string(char *str);

/* Parse a client message with relay config limits (higher-level than protocol_parse_message) */
bool protocol_parse_client_message(const char *data, size_t length,
                                   const relay_config_t *config,
                                   protocol_message_t *out,
                                   char *reject_reason, size_t reason_size);

#endif /* PROTOCOL_H_ */