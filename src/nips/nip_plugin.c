#include "nip_plugin.h"
#include <string.h>

/* ============================================================================
 * NIP Plugin Registry
 *
 * A simple intrusive linked list. Registration happens from per-module
 * constructors, which run before main() on MinGW/GCC, so by the time
 * server_configure() runs the full set of compiled-in plugins is known.
 * ============================================================================
 */

static nip_plugin_t *registry;

void nip_plugin_register(nip_plugin_t *plugin) {
    if (!plugin || !plugin->name) return;
    plugin->next = registry;
    registry = plugin;
}

nip_plugin_t *nip_plugins(void) {
    return registry;
}

void nip_plugins_init(const relay_config_t *config) {
    for (nip_plugin_t *plugin = registry; plugin; plugin = plugin->next) {
        if (plugin->init) plugin->init(config);
    }
}

void nip_plugin_send_json(struct mg_connection *connection, const char *json) {
    if (connection && json) mg_ws_send(connection, json, strlen(json), WEBSOCKET_OP_TEXT);
}

void nip_plugin_send_status(struct mg_connection *connection, const char *type,
                            const char *id, bool ok, const char *message) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, type);
    if (id) json_builder_append_string(&builder, id);
    if (strcmp(type, "OK") == 0) json_builder_append_bool(&builder, ok);
    json_builder_append_string(&builder, message);
    nip_plugin_send_json(connection, json_builder_finish(&builder));
}
