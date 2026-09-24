#include "nip_plugin.h"
#include "nip01.h"
#include <stdio.h>
#include <string.h>

/* ============================================================================
 * NIP Plugin Registry
 *
 * A simple intrusive linked list. Registration happens from per-image
 * constructors before module INIT. Each shared image owns a private copy of
 * this registry; init() only attaches services/configuration.
 *
 * nip_plugin_register() is the single registration entry point: it links the
 * plugin into the registry AND wires any declared kinds into the NIP-01
 * event dispatcher. There is no separate kind-listener registry.
 * ============================================================================
 */

static nip_plugin_t *registry;
static nip_plugin_send_json_fn host_send_json;
static nip_plugin_tag_index_fn tag_indexer;
static nip_plugin_query_index_fn query_indexer;

void nip_plugin_set_send_json(nip_plugin_send_json_fn send_json) {
    host_send_json = send_json;
}

void nip_plugin_set_tag_indexer(nip_plugin_tag_index_fn indexer) {
    tag_indexer = indexer;
}

void nip_plugin_set_query_indexer(nip_plugin_query_index_fn indexer) {
    query_indexer = indexer;
}

bool nip_plugin_extract_index_tags(const event_t *event,
                                   storage_tag_match_t **matches,
                                   size_t *count) {
    if (!matches || !count) return false;
    *matches = NULL;
    *count = 0;
    return !tag_indexer || tag_indexer(event, matches, count);
}

bool nip_plugin_query_index_tags(const filter_t *filters,
                                 size_t filters_count,
                                 storage_tag_match_t **matches,
                                 size_t *count) {
    if (!matches || !count) return false;
    *matches = NULL;
    *count = 0;
    return !query_indexer || query_indexer(filters, filters_count,
                                           matches, count);
}

void nip_plugin_reset_registry(void) {
    host_send_json = NULL;
    tag_indexer = NULL;
    query_indexer = NULL;
}

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
    if (!connection || !json || !host_send_json) return;
    if (host_send_json) host_send_json(connection, json, strlen(json));
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
    storage_tag_match_t *matches = NULL;
    size_t count = 0;
    bool indexed = nip_plugin_extract_index_tags(event, &matches, &count);
    bool stored = storage && storage->insert_record && indexed &&
                  storage->insert_record(event, matches, count);
    if (matches) {
        for (size_t i = 0; i < count; i++) {
            free((void *)matches[i].tag_name);
            free((void *)matches[i].tag_value);
        }
        free(matches);
    }
    return stored;
}

nip01_process_result_t nip_plugin_store_and_broadcast(storage_context_t *storage,
                                                      const event_t *event) {
    if (!storage || !storage->insert_record) {
        return nip_plugin_reject("error: storage unavailable");
    }
    if (!nip_plugin_store(storage, event)) {
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
