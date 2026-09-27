#ifndef PROTOCOL_PARSER_H_
#define PROTOCOL_PARSER_H_

#include <stdbool.h>
#include <stddef.h>
#include "protocol/protocol.h"
#include "relay/config.h"

bool protocol_parse_client_message(const char *data, size_t length,
                                   const relay_config_t *config,
                                   protocol_message_t *out,
                                   char *reject_reason, size_t reason_size);

void protocol_free_message(protocol_message_t *msg);

#endif