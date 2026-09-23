#include "nip_plugin.h"
#include "nip01.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * NIP Plugin Registry
 *
 * A simple intrusive linked list. Registration happens from per-module
 * constructors, which run before main() on MinGW/GCC, so by the time
 * server_configure() runs the full set of compiled-in plugins is known.
 *
 * nip_plugin_register() is the single registration entry point: it links the
 * plugin into the registry AND wires any declared kinds into the NIP-01
 * event dispatcher. There is no separate kind-listener registry.
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
        if (plugin->init) plugin->init(config, plugin->ctx);
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

/* ============================================================================
 * Ergonomic result / storage helpers
 * ============================================================================
 */

nip01_process_result_t nip_plugin_accept(void) {
    nip01_process_result_t result = {0};
    result.accepted = true;
    result.should_broadcast = true;
    return result;
}

nip01_process_result_t nip_plugin_reject(const char *message) {
    nip01_process_result_t result = {0};
    result.accepted = false;
    if (message) {
        snprintf(result.response_msg, sizeof(result.response_msg), "%s", message);
    }
    return result;
}

bool nip_plugin_store(storage_context_t *storage, const event_t *event) {
    return storage && storage->insert_record && storage->insert_record(event);
}

nip01_process_result_t nip_plugin_store_and_broadcast(storage_context_t *storage,
                                                      const event_t *event) {
    if (!storage || !storage->insert_record) {
        return nip_plugin_reject("error: storage unavailable");
    }
    if (!storage->insert_record(event)) {
        return nip_plugin_reject("duplicate: event already exists");
    }
    return nip_plugin_accept();
}

nip01_process_result_t nip_plugin_store_only(storage_context_t *storage,
                                             const event_t *event) {
    nip01_process_result_t result = nip_plugin_store_and_broadcast(storage, event);
    result.should_broadcast = false;
    return result;
}
