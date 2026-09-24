#include "nhr_module.h"
#include "nips/nip01.h"
#include "nips/nip_plugin.h"
#include "nips/nip26.h"
#include "nips/nip_event.h"
#include "nips/nip42.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static storage_context_t module_storage_adapter;
static const Nhr_Host *module_host;
static void module_crypto_sha256(const uint8_t *data, size_t length,
                                 uint8_t digest[32]);
static bool module_crypto_verify(const char *signature, const char *pubkey,
                                 const uint8_t digest[32]);

static void module_crypto_sha256(const uint8_t *data, size_t length,
                                 uint8_t digest[32]) {
    if (module_host && module_host->crypto_sha256) {
        module_host->crypto_sha256(module_host->userdata, data, length, digest);
    }
}

unsigned count_leading_zero_bits(const char *hex) {
    return module_host && module_host->crypto_count_leading_zero_bits
        ? module_host->crypto_count_leading_zero_bits(module_host->userdata, hex)
        : 0;
}

static bool module_crypto_verify(const char *signature, const char *pubkey,
                                 const uint8_t digest[32]) {
    return module_host && module_host->crypto_signature_verify &&
           module_host->crypto_signature_verify(module_host->userdata,
                                                signature, pubkey, digest);
}

static event_t *module_storage_get_event(const char *id) {
    event_t *event = (event_t *)malloc(sizeof(*event));
    char *tags = NULL, *content = NULL;
    if (!event || !module_host || !module_host->storage_get_event_copy) {
        free(event);
        return NULL;
    }
    if (!module_host->storage_get_event_copy(module_host->userdata, id, event,
                                             &tags, &content)) {
        free(event);
        return NULL;
    }
    if (tags) {
        event->tags_json = string_dup(tags);
        free(tags);
        if (!event->tags_json) { free(content); free(event); return NULL; }
    }
    if (content) {
        event->content = string_dup(content);
        free(content);
        if (!event->content) { free(event->tags_json); free(event); return NULL; }
    }
    event->tags_json_len = event->tags_json ? strlen(event->tags_json) : 0;
    event->content_len = event->content ? strlen(event->content) : 0;
    return event;
}

static bool module_storage_insert(const event_t *event,
                                  const storage_tag_match_t *tags,
                                  size_t count) {
#ifdef NHR_BUILD_MODULE
    (void)tags;
    (void)count;
    storage_tag_match_t *matches = NULL;
    size_t match_count = 0;
    bool ok;
    if (!module_host || !module_host->storage_insert_record ||
        !nip26_extract_index_tags(event, &matches, &match_count)) return false;
    ok = module_host->storage_insert_record(module_host->userdata, event,
                                             matches, match_count);
    nip26_free_index_tags(matches, match_count);
    return ok;
#else
    return module_host && module_host->storage_insert_record &&
           module_host->storage_insert_record(module_host->userdata, event,
                                              tags, count);
#endif
}

static int module_storage_delete_id(const char *id, const char *pubkey) {
    return module_host && module_host->storage_delete_by_id_and_pubkey
        ? module_host->storage_delete_by_id_and_pubkey(module_host->userdata,
                                                       id, pubkey) : -1;
}

static int module_storage_delete_kind(int kind, const char *pubkey,
                                      time_t created_at) {
    return module_host && module_host->storage_delete_by_kind_and_pubkey
        ? module_host->storage_delete_by_kind_and_pubkey(module_host->userdata,
                                                         kind, pubkey,
                                                         created_at) : -1;
}

static bool module_storage_delete_matching(const storage_event_scope_t *scope,
                                           storage_event_predicate_t predicate,
                                           void *userdata, size_t *deleted,
                                           char *next_id, size_t next_id_size,
                                           bool *more) {
    return module_host && module_host->storage_delete_matching &&
           module_host->storage_delete_matching(module_host->userdata, scope,
                                                predicate, userdata, deleted,
                                                next_id, next_id_size, more);
}

static bool module_storage_send_records(send_records_callback_t sender,
                                        const char *sub,
                                        const filter_t *filters,
                                        size_t filters_count, bool do_count,
                                        bool *has_more, int *out_count,
                                        const storage_tag_match_t *indexed_tags,
                                        size_t indexed_tags_count) {
    return module_host && module_host->storage_send_records &&
           module_host->storage_send_records(module_host->userdata, sender,
                                             sub, filters, filters_count,
                                             do_count, has_more, out_count,
                                             indexed_tags, indexed_tags_count);
}

static void module_storage_adapter_init(void) {
    memset(&module_storage_adapter, 0, sizeof(module_storage_adapter));
    module_storage_adapter.get_event_by_id = module_storage_get_event;
    module_storage_adapter.insert_record = module_storage_insert;
    module_storage_adapter.delete_record_by_id_and_pubkey = module_storage_delete_id;
    module_storage_adapter.delete_record_by_kind_and_pubkey = module_storage_delete_kind;
    module_storage_adapter.delete_matching = module_storage_delete_matching;
    module_storage_adapter.send_records = module_storage_send_records;
    module_storage_adapter.init = NULL;
    module_storage_adapter.deinit = NULL;
}

static bool module_check_event(const event_t *event) {
    if (!module_host || !module_host->crypto_check_event ||
        !module_host->crypto_check_event(module_host->userdata, event)) return false;
    /* NIP-26 delegation validation remains replaceable policy. */
    struct mg_str key, tag, tags = mg_str(event && event->tags_json ? event->tags_json : "[]");
    size_t offset = 0;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "delegation") == 0) {
            char *delegator = nip_tag_element(tag, 1);
            char *conditions = nip_tag_element(tag, 2);
            char *signature = nip_tag_element(tag, 3);
            bool valid = delegator && conditions && signature &&
                         nip26_check_delegation(event, delegator, conditions,
                                               signature);
            free(delegator);
            free(conditions);
            free(signature);
            free(name);
            if (!valid) return false;
        } else {
            free(name);
        }
    }
    return true;
}

bool NHR_CALL nhr_module_accepts_event(const event_t *event) {
    return module_check_event(event);
}

typedef struct {
    struct mg_connection *connection;
    const char *sub;
    const filter_t *filters;
    size_t filter_count;
    bool do_count;
    bool *has_more;
    int *total_count;
} module_query_context_t;

static module_query_context_t *module_query_context;

static relay_config_t module_config;
static storage_context_t *module_storage;

static void module_plugin_send_json(struct mg_connection *connection,
                                    const char *json, size_t length) {
    if (!module_host || !module_host->send_json) return;
    module_host->send_json(module_host->userdata, connection, json, length);
}

static void module_send_json(struct mg_connection *connection, const char *json) {
    if (!module_host || !module_host->send_json || !json) return;
    module_host->send_json(module_host->userdata, connection, json, strlen(json));
}

static void module_storage_sender_bridge(const char *json) {
    if (module_query_context && json) {
        module_send_json(module_query_context->connection, json);
    }
}

static void module_send_status(struct mg_connection *connection,
                               const char *type, const char *id, bool ok,
                               const char *message) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_append_string(&builder, type);
    if (id) json_builder_append_string(&builder, id);
    if (strcmp(type, "OK") == 0) json_builder_append_bool(&builder, ok);
    json_builder_append_string(&builder, message ? message : "");
    module_send_json(connection, json_builder_finish(&builder));
}

static void module_send_owned_json(struct mg_connection *connection, char *json) {
    if (!json) return;
    module_send_json(connection, json);
    free(json);
}

static void module_plugins_init(const relay_config_t *config) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->init) plugin->init(config, plugin->ctx);
    }
}

uint32_t NHR_CALL nhr_module_abi_version(void) {
    return NHR_ABI_VERSION;
}

bool NHR_CALL nhr_module_init(const Nhr_Host *host, const relay_config_t *config,
                              void *storage_handle) {
    if (!host || host->abi_version != NHR_ABI_VERSION ||
        host->struct_size < sizeof(*host) || !config) return false;
    module_host = host;
    module_config = *config;
    (void)storage_handle;
    module_storage_adapter_init();
    module_storage = &module_storage_adapter;
    module_config.storage = module_storage;
    /* The library loader has run constructors for this image. INIT installs
     * this generation's host-service callbacks and configures its registry.
     * reset_registry clears callback slots only, not the constructor chain. */
    nip_plugin_reset_registry();
    nip_plugin_set_tag_indexer(nip26_extract_index_tags);
    nip_plugin_set_query_indexer(nip26_query_index_tags);
    nip26_set_crypto_services(module_crypto_sha256, module_crypto_verify);
    nip_plugin_set_send_json(module_plugin_send_json);
    module_plugins_init(&module_config);
    return true;
}

void NHR_CALL nhr_module_shutdown(void) {
    nip_plugin_set_send_json(NULL);
    nip_plugin_set_tag_indexer(NULL);
    nip_plugin_set_query_indexer(NULL);
    nip26_set_crypto_services(NULL, NULL);
    /* Drop module-to-host references before the image is unloaded. */
    module_host = NULL;
    module_storage = NULL;
    memset(&module_config, 0, sizeof(module_config));
}

void NHR_CALL nhr_module_on_connect(struct mg_connection *connection) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_connect) plugin->on_connect(connection, plugin->ctx);
    }
}

static void module_issue_rechallenge(struct mg_connection *connection) {
    char challenge[17];
    json_builder_t builder;
    if (!nip42_open_challenge(connection, challenge) &&
        !nip42_open(connection, challenge)) return;
    json_builder_start(&builder);
    json_builder_append_string(&builder, "AUTH");
    json_builder_append_string(&builder, challenge);
    module_send_owned_json(connection, string_dup(json_builder_finish(&builder)));
}

void NHR_CALL nhr_module_on_disconnect(struct mg_connection *connection) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_disconnect) plugin->on_disconnect(connection, plugin->ctx);
    }
}

bool NHR_CALL nhr_module_on_message(struct mg_connection *connection,
                                    json_value_t *values, size_t count) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->on_message && plugin->on_message(connection, values, count,
                                                     plugin->ctx)) return true;
    }
    return false;
}

bool NHR_CALL nhr_module_accept_publish(struct mg_connection *connection,
                                        const event_t *event, char *reason,
                                        size_t reason_size) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->accept_publish &&
            !plugin->accept_publish(connection, event, reason, reason_size,
                                    plugin->ctx)) {
            if (!reason[0]) snprintf(reason, reason_size,
                                     "invalid: event not accepted");
            return false;
        }
    }
    return true;
}

bool NHR_CALL nhr_module_can_deliver(const event_t *event,
                                     struct mg_connection *connection) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->can_deliver &&
            !plugin->can_deliver(event, connection, plugin->ctx)) return false;
    }
    return true;
}

bool NHR_CALL nhr_module_eose_auth_hint(struct mg_connection *connection,
                                        const filter_t *filters, size_t count) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->eose_auth_hint &&
            plugin->eose_auth_hint(connection, filters, count, plugin->ctx)) return true;
    }
    return false;
}

static bool module_tag_matches(const event_t *event,
                               const storage_tag_match_t *matches,
                               size_t count) {
    struct mg_str key, tag, tags = mg_str(event && event->tags_json ? event->tags_json : "[]");
    size_t offset = 0;
    for (size_t m = 0; event && m < count; m++) {
        tags = mg_str(event->tags_json ? event->tags_json : "[]");
        offset = 0;
        while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
            char *name = nip_tag_element(tag, 0);
            char *value = nip_tag_element(tag, 1);
            bool matched = name && value &&
                          strcmp(name, matches[m].tag_name) == 0 &&
                          strcmp(value, matches[m].tag_value) == 0;
            free(name);
            free(value);
            if (matched) return true;
        }
    }
    return false;
}

bool NHR_CALL nhr_module_matches_filter(const filter_t *filter,
                                       const event_t *event) {
    if (!filter || !event) return false;
    if (filter->since && event->created_at < filter->since) return false;
    if (filter->until && event->created_at > filter->until) return false;
    if (filter->ids_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->ids_count; i++) {
            if (strncmp(event->id, filter->ids[i], strlen(filter->ids[i])) == 0) matched = true;
        }
        if (!matched) return false;
    }
    if (filter->authors_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->authors_count; i++) {
            if (strncmp(event->pubkey, filter->authors[i], strlen(filter->authors[i])) == 0) matched = true;
        }
        for (size_t i = 0; !matched && i < filter->authors_count; i++) {
            storage_tag_match_t *indexes = NULL;
            size_t index_count = 0;
            filter_t single = *filter;
            single.authors = &filter->authors[i];
            single.authors_count = 1;
            if (!nip26_query_index_tags(&single, 1, &indexes, &index_count)) return false;
            bool delegated = module_tag_matches(event, indexes, index_count);
            nip26_free_index_tags(indexes, index_count);
            if (delegated) matched = true;
        }
        if (!matched) return false;
    }
    if (filter->kinds_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->kinds_count; i++) if (event->kind == filter->kinds[i]) matched = true;
        if (!matched) return false;
    }
    for (size_t i = 0; i < filter->tags_count; i++) {
        bool matched = false;
        tag_t *tag = &filter->tags[i];
        for (size_t j = 1; j < tag->count; j++) {
            if (nip_event_has_tag(event, tag->elements[0], tag->elements[j])) matched = true;
        }
        if (!matched) return false;
    }
    if (filter->search && *filter->search &&
        !strstr(event->content ? event->content : "", filter->search)) return false;
    return true;
}

char *NHR_CALL nhr_module_build_eose(const char *sub, bool has_more,
                                     bool auth_hint) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->build_eose) {
            return plugin->build_eose(sub, has_more, auth_hint, plugin->ctx);
        }
    }
    return NULL;
}

char *NHR_CALL nhr_module_build_count(const char *sub, unsigned long count) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->build_count) return plugin->build_count(sub, count, plugin->ctx);
    }
    return NULL;
}

const char *NHR_CALL nhr_module_info_document(void) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->info_document) return plugin->info_document(plugin->ctx);
    }
    return NULL;
}

void NHR_CALL nhr_module_timer(void) {
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (plugin->timer) plugin->timer(module_storage, plugin->ctx);
    }
}

nip01_process_result_t NHR_CALL nhr_module_process_event(
    struct mg_connection *connection, const event_t *event,
    const char *relay_url,
    size_t max_content_length, time_t lower_limit, time_t upper_limit,
    int min_pow_difficulty) {
    return nip01_process_event(connection, event, module_storage, relay_url,
                               max_content_length, lower_limit, upper_limit,
                               min_pow_difficulty);
}

bool NHR_CALL nhr_module_query_events(struct mg_connection *connection,
                                      const char *sub, filter_t *filters,
                                      size_t count, bool do_count,
                                      bool *has_more, int *total_count) {
    module_query_context_t ctx;
    storage_tag_match_t *indexed_tags = NULL;
    size_t indexed_count = 0;
    bool ok;
    char *response = NULL;
    if (!module_storage || !module_storage->send_records) return false;
    if (!nip26_query_index_tags(filters, count, &indexed_tags, &indexed_count)) {
        return false;
    }
    ctx.connection = connection;
    ctx.sub = sub;
    ctx.filters = filters;
    ctx.filter_count = count;
    ctx.do_count = do_count;
    ctx.has_more = has_more;
    ctx.total_count = total_count;
    if (has_more) *has_more = false;
    if (total_count) *total_count = 0;
    module_query_context = &ctx;
    if (do_count) {
        ok = module_storage->send_records(module_storage_sender_bridge, sub,
                                          filters, count, true, has_more,
                                          total_count, indexed_tags,
                                          indexed_count);
        if (ok) response = nhr_module_build_count(sub,
                                      (unsigned long)(total_count ? *total_count : 0));
    } else {
        ok = module_storage->send_records(module_storage_sender_bridge, sub,
                                          filters, count, false, has_more,
                                          total_count, indexed_tags,
                                          indexed_count);
        if (ok) {
            bool auth_hint = nhr_module_eose_auth_hint(connection, filters, count);
            response = nhr_module_build_eose(sub, has_more ? *has_more : false,
                                             auth_hint);
        }
    }
    if (response) {
        module_send_json(connection, response);
        free(response);
    }
    module_query_context = NULL;
    nip26_free_index_tags(indexed_tags, indexed_count);
    return ok;
}

Nhr_State NHR_CALL nhr_module_pre_reload(void) {
    Nhr_State state = {0};
    Nhr_Connection *snapshot;
    nip42_state_t *data;
    nip42_connection_t *connections;
    if (!module_host || !module_host->connection_snapshot || !module_host->alloc) return state;
    snapshot = (Nhr_Connection *)malloc(4096 * sizeof(*snapshot));
    if (!snapshot) return state;
    size_t count = module_host->connection_snapshot(module_host->userdata,
                                                    snapshot, 4096);
    if (count > 1024) { free(snapshot); return state; }
    connections = (nip42_connection_t *)calloc(count ? count : 1,
                                                sizeof(*connections));
    if (!connections) { free(snapshot); return state; }
    for (size_t i = 0; i < count; i++) {
        connections[i].id = snapshot[i].id;
        connections[i].connection = (struct mg_connection *)snapshot[i].connection;
    }
    free(snapshot);
    data = (nip42_state_t *)module_host->alloc(sizeof(*data));
    if (!data || !nip42_save_state(data, connections, count)) {
        if (data) module_host->free(data);
        free(connections);
        state.data = NULL;
        state.size = 0;
        return state;
    }
    state.data = data;
    state.size = sizeof(*data);
    state.version = NHR_STATE_VERSION;
    free(connections);
    return state;
}

bool NHR_CALL nhr_module_post_reload(const Nhr_Host *host,
                                     const relay_config_t *config,
                                     void *storage_handle,
                                     Nhr_State state) {
    if (state.version != NHR_STATE_VERSION ||
        state.size != sizeof(nip42_state_t) || !state.data) return false;
    if (!host || host->abi_version != NHR_ABI_VERSION ||
        host->struct_size < sizeof(*host) || !config) return false;
    module_host = host;
    module_config = *config;
    module_storage_adapter_init();
    module_storage = &module_storage_adapter;
    module_config.storage = module_storage;
    nip_plugin_reset_registry();
    nip_plugin_set_tag_indexer(nip26_extract_index_tags);
    nip_plugin_set_query_indexer(nip26_query_index_tags);
    nip26_set_crypto_services(module_crypto_sha256, module_crypto_verify);
    nip_plugin_set_send_json(module_plugin_send_json);
    module_plugins_init(&module_config);
    (void)storage_handle;
    if (state.data && state.size == sizeof(nip42_state_t)) {
        Nhr_Connection *snapshot = (Nhr_Connection *)malloc(4096 * sizeof(*snapshot));
        if (!snapshot) return false;
        if (!host->connection_snapshot) { free(snapshot); return false; }
        size_t count = host->connection_snapshot(host->userdata, snapshot, 4096);
        if (count > 4096) count = 4096;
        nip42_connection_t *connections = (nip42_connection_t *)calloc(
            count ? count : 1, sizeof(*connections));
        if (!connections) { free(snapshot); return false; }
        for (size_t i = 0; i < count; i++) {
            connections[i].id = snapshot[i].id;
            connections[i].connection = (struct mg_connection *)snapshot[i].connection;
        }
        const nip42_state_t *migration = (const nip42_state_t *)state.data;
        bool restored = migration->version == NHR_STATE_VERSION &&
                migration->count <= 1024 &&
                nip42_restore_state(migration,
                                            connections, count);
        if (!restored) {
            for (size_t i = 0; i < count; i++) {
                module_issue_rechallenge(connections[i].connection);
            }
        }
        free(connections);
        free(snapshot);
    } else {
        Nhr_Connection *snapshot = (Nhr_Connection *)malloc(4096 * sizeof(*snapshot));
        if (snapshot && host->connection_snapshot) {
            size_t count = host->connection_snapshot(host->userdata, snapshot, 4096);
            if (count > 4096) count = 4096;
            for (size_t i = 0; i < count; i++) {
                module_issue_rechallenge((struct mg_connection *)snapshot[i].connection);
            }
        }
        free(snapshot);
    }
    return true;
}

void NHR_CALL nhr_module_free_string(char *string) {
    free(string);
}
