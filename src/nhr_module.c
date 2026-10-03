#include "nhr_module.h"
#include "nip_capability.h" /* registry types + composition functions */
#include "nips/nip26.h"      /* nip26_check_delegation, nip26_extract_index_tags */
#include "nips/nip42.h"      /* nip42 auth API (stateless reload: no save/restore blob) */
#include "crypto.h"
#include "protocol/tag_iter.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const Nhr_Host *g_host = NULL;
static relay_config_t g_config = {0};
static nip_registry_t *g_module_registry = NULL;

/* Session-auth + send shims: thin forwards to host services. Safe to call
 * with no host (dispatch never runs then); callers get empty defaults. */
const char *nhr_module_session_challenge(uintptr_t connection_id) {
    if (!g_host || !g_host->connection_get_challenge) return NULL;
    return g_host->connection_get_challenge(g_host->userdata, connection_id);
}

bool nhr_module_session_set_challenge(uintptr_t connection_id,
                                      const char *challenge) {
    if (!g_host || !g_host->connection_set_challenge) return false;
    return g_host->connection_set_challenge(g_host->userdata, connection_id,
                                            challenge);
}

const char *nhr_module_session_auth_pubkey(uintptr_t connection_id) {
    if (!g_host || !g_host->connection_get_auth_pubkey) return NULL;
    return g_host->connection_get_auth_pubkey(g_host->userdata, connection_id);
}

bool nhr_module_session_set_auth(uintptr_t connection_id, const char *pubkey) {
    if (!g_host || !g_host->connection_set_auth) return false;
    return g_host->connection_set_auth(g_host->userdata, connection_id, pubkey);
}

void nhr_module_session_clear_auth(uintptr_t connection_id) {
    if (!g_host || !g_host->connection_clear_auth) return;
    g_host->connection_clear_auth(g_host->userdata, connection_id);
}

bool nhr_module_session_add_auth(uintptr_t connection_id, const char *pubkey) {
    if (!g_host || !pubkey) return false;
    if (g_host->connection_add_auth) {
        return g_host->connection_add_auth(g_host->userdata, connection_id, pubkey);
    }
    /* Older host (ABI v2): fall back to set_auth (single pubkey). */
    if (!g_host->connection_set_auth) return false;
    return g_host->connection_set_auth(g_host->userdata, connection_id, pubkey);
}

bool nhr_module_session_has_auth(uintptr_t connection_id, const char *pubkey) {
    const char *first;
    size_t i;
    if (!g_host || !pubkey) return false;
    if (g_host->connection_has_auth) {
        return g_host->connection_has_auth(g_host->userdata, connection_id, pubkey);
    }
    /* Older host (ABI v2): only the first pubkey is visible. */
    if (!g_host->connection_get_auth_pubkey) return false;
    if (g_host->connection_get_auth_at) {
        size_t n = g_host->connection_get_auth_count
            ? g_host->connection_get_auth_count(g_host->userdata, connection_id) : 0;
        for (i = 0; i < n; i++) {
            const char *pk = g_host->connection_get_auth_at(g_host->userdata, connection_id, i);
            if (pk && strcmp(pk, pubkey) == 0) return true;
        }
        return false;
    }
    first = g_host->connection_get_auth_pubkey(g_host->userdata, connection_id);
    return first && strcmp(first, pubkey) == 0;
}

size_t nhr_module_session_auth_count(uintptr_t connection_id) {
    const char *first;
    if (!g_host) return 0;
    if (g_host->connection_get_auth_count) {
        return g_host->connection_get_auth_count(g_host->userdata, connection_id);
    }
    if (!g_host->connection_get_auth_pubkey) return 0;
    first = g_host->connection_get_auth_pubkey(g_host->userdata, connection_id);
    return (first && first[0]) ? 1 : 0;
}

const char *nhr_module_session_auth_at(uintptr_t connection_id, size_t index) {
    if (!g_host) return NULL;
    if (g_host->connection_get_auth_at) {
        return g_host->connection_get_auth_at(g_host->userdata, connection_id, index);
    }
    if (index != 0 || !g_host->connection_get_auth_pubkey) return NULL;
    return g_host->connection_get_auth_pubkey(g_host->userdata, connection_id);
}

size_t nhr_module_session_snapshot(connection_snapshot_t *out, size_t capacity) {
    /* Enumerates the host-owned session list (live relay sessions). */
    if (!g_host || !out || !capacity) return 0;
    if (g_host->connection_snapshot) {
        return g_host->connection_snapshot(g_host->userdata, out, capacity);
    }
    return 0;
}

bool nhr_module_send_json(uintptr_t connection_id, const char *json, size_t length) {
    /* Resolve the opaque ID through the host session list. Grow-and-retry:
     * a full buffer may mean truncation (snapshot fills up to capacity),
     * so retry larger until the fill is partial. Bounded; fails closed. */
    size_t capacity = 64;
    void *connection = NULL;
    if (!g_host || !g_host->send_json || !g_host->connection_snapshot ||
        !g_host->alloc || !g_host->free || !json) return false;
    for (int attempt = 0; attempt < 5; attempt++) {
        connection_snapshot_t *snapshot = g_host->alloc(capacity * sizeof(*snapshot));
        size_t count, i;
        if (!snapshot) return false;
        count = g_host->connection_snapshot(g_host->userdata, snapshot, capacity);
        if (count < capacity) {
            for (i = 0; i < count; i++) {
                if (snapshot[i].id == connection_id) {
                    connection = snapshot[i].connection;
                    break;
                }
            }
            g_host->free(snapshot);
            break;
        }
        g_host->free(snapshot);
        if (capacity >= 16384) return false;
        capacity *= 4;
    }
    if (!connection) return false;
    g_host->send_json(g_host->userdata, connection, json, length);
    return true;
}

static event_t *module_storage_get_event(const char *id) {
    event_t *event = g_host && g_host->alloc ? g_host->alloc(sizeof(*event)) : malloc(sizeof(*event));
    char *tags = NULL, *content = NULL;
    if (!event || !g_host || !g_host->storage_get_event_copy) {
        if (event) { if (g_host && g_host->free) g_host->free(event); else free(event); }
        return NULL;
    }
    if (!g_host->storage_get_event_copy(g_host->userdata, id, event, &tags, &content)) {
        if (g_host && g_host->free) g_host->free(event); else free(event);
        return NULL;
    }
    if (tags) {
        event->tags_json = tags;
    }
    if (content) {
        event->content = content;
    }
    event->tags_json_len = event->tags_json ? strlen(event->tags_json) : 0;
    event->content_len = event->content ? strlen(event->content) : 0;
    return event;
}

static storage_insert_result_t module_storage_insert(const event_t *event,
                                                      const storage_tag_match_t *tags,
                                                      size_t count) {
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");

    if (g_host && g_host->storage_insert_record) {
        return g_host->storage_insert_record(g_host->userdata, event, tags, count);
    }
    return result;
}

static storage_delete_result_t module_storage_delete_id(const char *id, const char *pubkey) {
    storage_delete_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");

    if (g_host && g_host->storage_delete_by_id_and_pubkey) {
        int deleted = g_host->storage_delete_by_id_and_pubkey(g_host->userdata, id, pubkey);
        result.result = deleted >= 0 ? STORAGE_OK : STORAGE_ERROR;
        result.deleted_count = deleted >= 0 ? deleted : 0;
        if (deleted < 0) snprintf(result.error_message, sizeof(result.error_message), "delete failed");
        return result;
    }
    return result;
}

static storage_delete_result_t module_storage_delete_kind(int kind, const char *pubkey, time_t created_at) {
    storage_delete_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");

    if (g_host && g_host->storage_delete_by_kind_and_pubkey) {
        int deleted = g_host->storage_delete_by_kind_and_pubkey(g_host->userdata, kind, pubkey, created_at);
        result.result = deleted >= 0 ? STORAGE_OK : STORAGE_ERROR;
        result.deleted_count = deleted >= 0 ? deleted : 0;
        if (deleted < 0) snprintf(result.error_message, sizeof(result.error_message), "delete failed");
        return result;
    }
    return result;
}

/* New unified storage API - forwards to host NHR services */
static bool module_storage_find_events(const storage_event_scope_t *scope,
                                       event_t ***out_events,
                                       size_t *out_count) {
    return g_host && g_host->storage_find_events
        ? g_host->storage_find_events(g_host->userdata, scope, out_events, out_count)
        : false;
}

static bool module_storage_count_events(const storage_event_scope_t *scope,
                                        size_t *out_count) {
    return g_host && g_host->storage_count_events
        ? g_host->storage_count_events(g_host->userdata, scope, out_count)
        : false;
}

static bool module_storage_delete_events(const storage_event_scope_t *scope,
                                         size_t *out_deleted) {
    return g_host && g_host->storage_delete_events
        ? g_host->storage_delete_events(g_host->userdata, scope, out_deleted)
        : false;
}

static storage_transaction_t *module_storage_transaction_begin(void) {
    return g_host && g_host->storage_transaction_begin
        ? g_host->storage_transaction_begin(g_host->userdata)
        : NULL;
}

static bool module_storage_transaction_commit(storage_transaction_t *tx) {
    return g_host && g_host->storage_transaction_commit
        ? g_host->storage_transaction_commit(g_host->userdata, tx)
        : false;
}

static void module_storage_transaction_rollback(storage_transaction_t *tx) {
    if (g_host && g_host->storage_transaction_rollback) {
        g_host->storage_transaction_rollback(g_host->userdata, tx);
    }
}

static bool module_storage_delete_events_tx(const storage_event_scope_t *scope,
                                            storage_transaction_t *tx,
                                            size_t *out_deleted) {
    return g_host && g_host->storage_delete_events_tx
        ? g_host->storage_delete_events_tx(g_host->userdata, scope, tx, out_deleted)
        : false;
}

static bool module_storage_find_events_tx(const storage_event_scope_t *scope,
                                          storage_transaction_t *tx,
                                          event_t ***out_events,
                                          size_t *out_count) {
    return g_host && g_host->storage_find_events_tx
        ? g_host->storage_find_events_tx(g_host->userdata, scope, tx, out_events, out_count)
        : false;
}

static storage_insert_result_t module_storage_upsert_replaceable(const event_t *event,
                                                                  const storage_tag_match_t *indexed_tags,
                                                                  size_t indexed_tags_count) {
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    if (g_host && g_host->storage_upsert_replaceable) {
        return g_host->storage_upsert_replaceable(g_host->userdata, event, indexed_tags, indexed_tags_count);
    }
    return result;
}

static storage_insert_result_t module_storage_upsert_addressable(const event_t *event,
                                                                  const char *d_tag_value,
                                                                  const storage_tag_match_t *indexed_tags,
                                                                  size_t indexed_tags_count) {
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    if (g_host && g_host->storage_upsert_addressable) {
        return g_host->storage_upsert_addressable(g_host->userdata, event, d_tag_value, indexed_tags, indexed_tags_count);
    }
    return result;
}

static bool module_storage_find_ids_by_tags(const char *const *tag_names,
                                            const char *const *tag_values,
                                            size_t tag_count,
                                            char ***ids_out,
                                            size_t *count_out) {
    return g_host && g_host->storage_find_ids_by_tags
        ? g_host->storage_find_ids_by_tags(g_host->userdata, tag_names, tag_values, tag_count, ids_out, count_out)
        : false;
}

static void module_storage_free_id_list(char **ids, size_t count) {
    if (g_host && g_host->storage_free_id_list) {
        g_host->storage_free_id_list(g_host->userdata, ids, count);
    }
}

static bool module_check_event(const event_t *event) {
    if (!g_host || !g_host->crypto_check_event || !g_host->crypto_check_event(g_host->userdata, event)) return false;
    if (!event->tags_json) return true;
    tag_iter_t it;
    tag_iter_init(&it, event);
    struct mg_str key, tag;
    while (tag_iter_next(&it, &key, &tag)) {
        tag_iter_t sub;
        tag_iter_init_tag(&sub, tag);
        char *name = tag_iter_element(&sub, 0);
        if (name && strcmp(name, "delegation") == 0) {
            char *delegator = tag_iter_element(&sub, 1);
            char *conditions = tag_iter_element(&sub, 2);
            char *signature = tag_iter_element(&sub, 3);
            bool valid = delegator && conditions && signature &&
                         nip26_check_delegation(event, delegator, conditions, signature);
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

uint32_t NHR_CALL nhr_module_abi_version(void) {
    return NHR_ABI_VERSION;
}

/* Bridge used by in-module NIP policy code for event-ID and signature
 * verification (plus NIP-26 delegation, mirroring host check_event()).
 * Crypto state stays host-owned; this is a plain internal function, not an
 * ABI export. */
bool nhr_module_accepts_event(const event_t *event) {
    return module_check_event(event);
}

bool NHR_CALL nhr_module_init(const Nhr_Host *host, const relay_config_t *config, void *storage_handle) {
    if (!host || host->abi_version != NHR_ABI_VERSION || host->struct_size < sizeof(*host) || !config) return false;
    g_host = host;
    g_config = *config;
    (void)storage_handle;

    g_module_registry = nip_registry_create();
    if (!g_module_registry) return false;

    /* Register every capability provider in this module image
     * (constructors registered them at load time). */
    nip_registry_register_providers(g_module_registry);

    nip_composition_run_init(g_module_registry, config);
    return true;
}

void NHR_CALL nhr_module_shutdown(void) {
    if (g_module_registry) {
        nip_composition_run_shutdown(g_module_registry);
        /* Registry nodes are host- or module-owned heap copies; ctx blocks
         * are static or NULL (see nip_template.c), so there is nothing to
         * free here beyond the registry itself. */
        nip_registry_destroy(g_module_registry);
        g_module_registry = NULL;
    }
    g_host = NULL;
    g_config = (relay_config_t){0};
}

Nhr_State NHR_CALL nhr_module_pre_reload(void) {
    /* Stateless reload: every state that must survive (sockets, sessions
     * incl. NIP-42 challenge/pubkey, subscriptions, SQLite, config) is
     * host-owned and never crosses the unload boundary, so there is no
     * blob to build. The versioned empty state satisfies the host's shape
     * check in nhr_runtime_activate_candidate; post_reload just re-inits
     * the new generation, whose lifecycle init re-derives per-generation
     * ctx. Activation runs synchronously on the event-loop thread, so no
     * session can change mid-swap. */
    Nhr_State state = {0};
    state.version = NHR_STATE_VERSION;
    return state;
}

bool NHR_CALL nhr_module_post_reload(const Nhr_Host *host, const relay_config_t *config,
                                      void *storage_handle, Nhr_State state) {
    if (!host || host->abi_version != NHR_ABI_VERSION || host->struct_size < sizeof(*host) || !config) return false;
    /* state carries nothing (see pre_reload). A non-empty blob from an
     * older generation is tolerated and ignored: the host frees state.data
     * after we return, and live sessions already hold the auth state. */
    (void)state;
    return nhr_module_init(host, config, storage_handle);
}

void NHR_CALL nhr_module_register_capabilities(nip_registry_t *host_registry) {
    if (!host_registry || !g_module_registry) return;
    /* nip_registry_register() deep-copies each descriptor, so the module
     * keeps ownership of its own registry. The host owns its copies and can
     * clear them before the old module is unloaded without dangling. */
    for (nip_capability_t *cap = g_module_registry->capabilities; cap; cap = cap->next) {
        nip_registry_register(host_registry, cap);
    }
}

unsigned nhr_module_count_leading_zero_bits(const char *hex) {
    if (!g_host || !g_host->crypto_count_leading_zero_bits) return 0;
    return g_host->crypto_count_leading_zero_bits(g_host->userdata, hex);
}