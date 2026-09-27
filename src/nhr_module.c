#include "nhr_module.h"
#include "nip_capability.h" /* registry + nip26/nip42 shared decls (each NIP is one nipXX.c) */
#include "crypto.h"
#include "model/event_util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const Nhr_Host *g_host = NULL;
static relay_config_t g_config = {0};
static storage_context_t g_module_storage_adapter = {0};
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
        storage_tag_match_t *matches = NULL;
        size_t match_count = 0;
        if (!nip26_extract_index_tags(event, &matches, &match_count)) return result;
        storage_insert_result_t insert_result = g_host->storage_insert_record(g_host->userdata, event, matches, match_count);
        nip26_free_index_tags(matches, match_count);
        return insert_result;
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

static bool module_storage_delete_matching(const storage_event_scope_t *scope,
                                            storage_event_predicate_t predicate,
                                            void *userdata, size_t *deleted,
                                            char *next_id, size_t next_id_size,
                                            bool *more) {
    return g_host && g_host->storage_delete_matching &&
           g_host->storage_delete_matching(g_host->userdata, scope, predicate, userdata, deleted, next_id, next_id_size, more);
}

static bool module_storage_send_records(send_records_callback_t sender,
                                         const char *sub,
                                         const filter_t *filters,
                                         size_t filters_count, bool do_count,
                                         bool *has_more, int *out_count,
                                         const storage_tag_match_t *indexed_tags,
                                         size_t indexed_tags_count,
                                         void *userdata) {
    return g_host && g_host->storage_send_records &&
           g_host->storage_send_records(g_host->userdata, sender, sub, filters, filters_count, do_count, has_more, out_count, indexed_tags, indexed_tags_count, userdata);
}

static void module_storage_adapter_init(void) {
    memset(&g_module_storage_adapter, 0, sizeof(g_module_storage_adapter));
    g_module_storage_adapter.get_event_by_id = module_storage_get_event;
    g_module_storage_adapter.insert_record = module_storage_insert;
    g_module_storage_adapter.delete_record_by_id_and_pubkey = module_storage_delete_id;
    g_module_storage_adapter.delete_record_by_kind_and_pubkey = module_storage_delete_kind;
    g_module_storage_adapter.delete_matching = module_storage_delete_matching;
    g_module_storage_adapter.send_records = module_storage_send_records;
    g_module_storage_adapter.init = NULL;
    g_module_storage_adapter.deinit = NULL;
}

static bool module_check_event(const event_t *event) {
    if (!g_host || !g_host->crypto_check_event || !g_host->crypto_check_event(g_host->userdata, event)) return false;
    if (!event->tags_json) return true;
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = event_tag_element(event->tags_json, 0);
        if (name && strcmp(name, "delegation") == 0) {
            char *delegator = event_tag_element(event->tags_json, 1);
            char *conditions = event_tag_element(event->tags_json, 2);
            char *signature = event_tag_element(event->tags_json, 3);
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

/* Bridge used by in-module NIP policy code (nip01/nip42) for event-ID and
 * signature verification. Crypto state stays host-owned; this is a plain
 * internal function, not an ABI export. */
bool nhr_module_accepts_event(const event_t *event) {
    if (g_host && g_host->crypto_check_event) {
        return g_host->crypto_check_event(g_host->userdata, event);
    }
    return false;
}

bool NHR_CALL nhr_module_init(const Nhr_Host *host, const relay_config_t *config, void *storage_handle) {
    if (!host || host->abi_version != NHR_ABI_VERSION || host->struct_size < sizeof(*host) || !config) return false;
    g_host = host;
    g_config = *config;
    (void)storage_handle;
    module_storage_adapter_init();

    g_module_registry = nip_registry_create();
    if (!g_module_registry) return false;

    /* Register every capability provider in this module image
     * (constructors registered them at load time). */
    nip_registry_register_providers(g_module_registry);

    for (nip_capability_t *cap = g_module_registry->capabilities; cap; cap = cap->next) {
        if (cap->type == NIP_CAP_LIFECYCLE && cap->caps.lifecycle.init) {
            cap->caps.lifecycle.init(config, cap->ctx);
        }
    }
    return true;
}

void NHR_CALL nhr_module_shutdown(void) {
    if (g_module_registry) {
        for (nip_capability_t *cap = g_module_registry->capabilities; cap; cap = cap->next) {
            if (cap->type == NIP_CAP_LIFECYCLE && cap->caps.lifecycle.shutdown) {
                cap->caps.lifecycle.shutdown(cap->ctx);
            }
        }
        /* Registry nodes are host- or module-owned heap copies; ctx blocks
         * are static or NULL (see nip_template.c), so there is nothing to
         * free here beyond the registry itself. */
        nip_registry_destroy(g_module_registry);
        g_module_registry = NULL;
    }
    g_host = NULL;
    g_config = (relay_config_t){0};
    memset(&g_module_storage_adapter, 0, sizeof(g_module_storage_adapter));
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