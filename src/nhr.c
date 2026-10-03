#include "nhr.h"
#include "nhr_loader.h"
#include "crypto.h"
#include "relay/connection_session.h"
#include "log.h"
#include <mongoose.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "nostrogotho.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

static void NHR_CALL host_send_json(void *userdata, void *connection,
                                    const char *json, size_t length) {
    (void)userdata;
    if (connection && json) mg_ws_send((struct mg_connection *)connection,
                                       json, length, WEBSOCKET_OP_TEXT);
}

static void *NHR_CALL host_alloc(size_t size) { return malloc(size); }
static void NHR_CALL host_free(void *ptr) { free(ptr); }

static bool NHR_CALL host_storage_get_event(void *userdata, const char *id,
                                            event_t *out_event,
                                            char **owned_tags,
                                            char **owned_content) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    event_t *event;
    if (owned_tags) *owned_tags = NULL;
    if (owned_content) *owned_content = NULL;
    if (!runtime || !runtime->storage || !runtime->storage->get_event_by_id ||
        !out_event || !owned_tags || !owned_content) return false;
    event = runtime->storage->get_event_by_id(id);
    if (!event) return false;
    *out_event = *event;
    *owned_tags = event->tags_json;
    *owned_content = event->content;
    free(event);
    return true;
}

static storage_insert_result_t NHR_CALL host_storage_insert(void *userdata, const event_t *event,
                                                            const storage_tag_match_t *tags,
                                                            size_t tags_count) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    if (runtime && runtime->storage && runtime->storage->insert_record) {
        return runtime->storage->insert_record(event, tags, tags_count);
    }
    return result;
}

static int NHR_CALL host_storage_delete_id(void *userdata, const char *id,
                                          const char *pubkey) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    if (!runtime || !runtime->storage || !runtime->storage->delete_record_by_id_and_pubkey) return -1;
    storage_delete_result_t result = runtime->storage->delete_record_by_id_and_pubkey(id, pubkey);
    return result.result == STORAGE_OK ? result.deleted_count : -1;
}

static int NHR_CALL host_storage_delete_kind(void *userdata, int kind,
                                            const char *pubkey,
                                            time_t created_at) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    if (!runtime || !runtime->storage || !runtime->storage->delete_record_by_kind_and_pubkey) return -1;
    storage_delete_result_t result = runtime->storage->delete_record_by_kind_and_pubkey(kind, pubkey, created_at);
    return result.result == STORAGE_OK ? result.deleted_count : -1;
}

/* host_storage_delete_matching deleted with the legacy predicate API. */

static bool NHR_CALL host_storage_find_events(void *userdata,
                                              const storage_event_scope_t *scope,
                                              event_t ***out_events,
                                              size_t *out_count) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_find_events(scope, out_events, out_count)
        : false;
}

static bool NHR_CALL host_storage_count_events(void *userdata,
                                               const storage_event_scope_t *scope,
                                               size_t *out_count) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_count_events(scope, out_count)
        : false;
}

static bool NHR_CALL host_storage_delete_events(void *userdata,
                                                const storage_event_scope_t *scope,
                                                size_t *out_deleted) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_delete_events(scope, out_deleted)
        : false;
}

static storage_transaction_t *NHR_CALL host_storage_transaction_begin(void *userdata) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_transaction_begin()
        : NULL;
}

static bool NHR_CALL host_storage_transaction_commit(void *userdata, storage_transaction_t *tx) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_transaction_commit(tx)
        : false;
}

static void NHR_CALL host_storage_transaction_rollback(void *userdata, storage_transaction_t *tx) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    if (runtime && runtime->storage) {
        storage_transaction_rollback(tx);
    }
}

static bool NHR_CALL host_storage_delete_events_tx(void *userdata,
                                                   const storage_event_scope_t *scope,
                                                   storage_transaction_t *tx,
                                                   size_t *out_deleted) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_delete_events_tx(scope, tx, out_deleted)
        : false;
}

static bool NHR_CALL host_storage_find_events_tx(void *userdata,
                                                 const storage_event_scope_t *scope,
                                                 storage_transaction_t *tx,
                                                 event_t ***out_events,
                                                 size_t *out_count) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_find_events_tx(scope, tx, out_events, out_count)
        : false;
}

static storage_insert_result_t NHR_CALL host_storage_upsert_replaceable(void *userdata,
                                                                        const event_t *event,
                                                                        const storage_tag_match_t *indexed_tags,
                                                                        size_t indexed_tags_count) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    if (runtime && runtime->storage) {
        return storage_upsert_replaceable(event, indexed_tags, indexed_tags_count);
    }
    return result;
}

static storage_insert_result_t NHR_CALL host_storage_upsert_addressable(void *userdata,
                                                                        const event_t *event,
                                                                        const char *d_tag_value,
                                                                        const storage_tag_match_t *indexed_tags,
                                                                        size_t indexed_tags_count) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    storage_insert_result_t result = {0};
    result.result = STORAGE_ERROR;
    snprintf(result.error_message, sizeof(result.error_message), "not implemented");
    if (runtime && runtime->storage) {
        return storage_upsert_addressable(event, d_tag_value, indexed_tags, indexed_tags_count);
    }
    return result;
}

static bool NHR_CALL host_storage_find_ids_by_tags(void *userdata,
                                                   const char *const *tag_names,
                                                   const char *const *tag_values,
                                                   size_t tag_count,
                                                   char ***ids_out,
                                                   size_t *count_out) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    return runtime && runtime->storage
        ? storage_find_ids_by_tags(tag_names, tag_values, tag_count, ids_out, count_out)
        : false;
}

static void NHR_CALL host_storage_free_id_list(void *userdata, char **ids, size_t count) {
    Nhr_Runtime *runtime = (Nhr_Runtime *)userdata;
    if (runtime && runtime->storage) {
        storage_free_id_list(ids, count);
    }
}

static bool NHR_CALL host_crypto_check_event(void *userdata, const event_t *event) {
    (void)userdata;
    return check_event_core(event);
}

static void NHR_CALL host_crypto_sha256(void *userdata, const uint8_t *data,
                                        size_t length, uint8_t digest[32]) {
    (void)userdata;
    sha256(data, length, digest);
}

static bool NHR_CALL host_crypto_signature_verify(void *userdata,
                                                   const char *signature,
                                                   const char *pubkey,
                                                   const uint8_t digest[32]) {
    (void)userdata;
    return signature_verify(signature, pubkey, digest);
}

static unsigned NHR_CALL host_crypto_count_leading_zero_bits(void *userdata,
                                                             const char *hex) {
    (void)userdata;
    return (unsigned)count_leading_zero_bits(hex);
}

static uintptr_t NHR_CALL host_connection_id(void *userdata, void *connection) {
    (void)userdata;
    if (!connection) return 0;
    connection_session_t *session = connection_session_get_by_mg_connection((struct mg_connection *)connection);
    return session ? connection_session_get_id(session) : 0;
}

static size_t NHR_CALL host_connection_snapshot(void *userdata,
                                                connection_snapshot_t *connections,
                                                size_t capacity) {
    (void)userdata;
    /* Enumerate the relay's host-owned session list (populated by the live
     * relay path), not the legacy NHR connection list. Nhr_Connection and
     * connection_snapshot_t share the {id, connection} layout. */
    if (!connections || !capacity) return 0;
    return connection_session_snapshot(connections, capacity);
}

/* Session-auth services (ABI v2). Backed by the relay's host-owned
 * connection_session list — the same list the live relay path populates —
 * so NIP-42 challenge/pubkey state survives module reload with no copy. */
static const char *NHR_CALL host_connection_get_challenge(void *userdata,
                                                           uintptr_t connection_id) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_challenge(session) : NULL;
}

static bool NHR_CALL host_connection_set_challenge(void *userdata,
                                                    uintptr_t connection_id,
                                                    const char *challenge) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    if (!session) return false;
    connection_session_set_challenge(session, challenge);
    return true;
}

static const char *NHR_CALL host_connection_get_auth_pubkey(void *userdata,
                                                             uintptr_t connection_id) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_auth_pubkey(session) : NULL;
}

static bool NHR_CALL host_connection_set_auth(void *userdata,
                                               uintptr_t connection_id,
                                               const char *pubkey) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    if (!session) return false;
    connection_session_set_auth(session, pubkey);
    return true;
}

static void NHR_CALL host_connection_clear_auth(void *userdata,
                                                 uintptr_t connection_id) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    if (!session) return;
    connection_session_set_auth(session, NULL);
    connection_session_set_challenge(session, NULL);
}

/* Multi-pubkey session-auth services (ABI v3). Same host-owned list as the
 * v2 services above. */
static bool NHR_CALL host_connection_add_auth(void *userdata,
                                              uintptr_t connection_id,
                                              const char *pubkey) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    if (!session || !pubkey) return false;
    connection_session_add_auth_pubkey(session, pubkey);
    return true;
}

static bool NHR_CALL host_connection_has_auth(void *userdata,
                                              uintptr_t connection_id,
                                              const char *pubkey) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_has_auth_pubkey(session, pubkey) : false;
}

static size_t NHR_CALL host_connection_get_auth_count(void *userdata,
                                                      uintptr_t connection_id) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_auth_pubkey_count(session) : 0;
}

static const char *NHR_CALL host_connection_get_auth_at(void *userdata,
                                                        uintptr_t connection_id,
                                                        size_t index) {
    (void)userdata;
    connection_session_t *session = connection_session_get(connection_id);
    return session ? connection_session_get_auth_pubkey_at(session, index) : NULL;
}

void nhr_runtime_connection_closed(Nhr_Runtime *runtime, void *connection) {
    (void)runtime;
    (void)connection;
    /* Session cleanup is handled by the relay via connection_session_destroy().
     * The host-owned connection_session list is the single source of truth. */
}

static bool nhr_runtime_load_generation(Nhr_Runtime *runtime,
                                        const char *source_path,
                                        Nhr_Library *library) {
    char unique_path[1024];
    if (!runtime || !source_path || !library) return false;
    runtime->generation++;
    if (runtime->generation == 0) runtime->generation++;
#ifdef _WIN32
    snprintf(unique_path, sizeof(unique_path), "build/nhr_%lu_%u.dll",
             (unsigned long)GetCurrentProcessId(), runtime->generation);
#else
    snprintf(unique_path, sizeof(unique_path), "build/nhr_%lu_%u.so",
             (unsigned long)getpid(), runtime->generation);
#endif
    if (!nhr_platform_copy(source_path, unique_path)) {
        log_nhr_error("COPY", "could not copy candidate '%s' to '%s'", source_path, unique_path);
        return false;
    }
    if (!nhr_library_open(library, unique_path)) {
        remove(unique_path);
        return false;
    }
    snprintf(library->source_path, sizeof(library->source_path), "%s", source_path);
    return true;
}

bool nhr_library_open(Nhr_Library *out, const char *path) {
    char error[512] = {0};
    Nhr_Library candidate;
    memset(&candidate, 0, sizeof(candidate));
    if (!out || !path) return false;

    candidate.handle = nhr_platform_open(path, error, sizeof(error));
    if (!candidate.handle) {
        log_nhr_error("LOAD", "could not load '%s': %s", path,
                error[0] ? error : "unknown loader error");
        memset(out, 0, sizeof(*out));
        return false;
    }

#define NHR_RESOLVE(ret, name, args) \
    do { \
        error[0] = '\0'; \
        if (!nhr_platform_symbol(candidate.handle, "nhr_module_" #name, \
                                 &candidate.api.name, sizeof(candidate.api.name), \
                                 error, sizeof(error))) { \
            log_nhr_error("LOAD", "missing symbol nhr_module_%s in '%s': %s", \
                    #name, path, error[0] ? error : "not found"); \
            nhr_platform_close(candidate.handle); \
            memset(out, 0, sizeof(*out)); \
            return false; \
        } \
    } while (0);
    NHR_MODULE_FUNCTIONS(NHR_RESOLVE)
#undef NHR_RESOLVE

    if (candidate.api.abi_version() != NHR_ABI_VERSION) {
        log_nhr_error("LOAD", "ABI mismatch in '%s' (module=%u host=%u)",
                path, candidate.api.abi_version(), NHR_ABI_VERSION);
        nhr_platform_close(candidate.handle);
        memset(out, 0, sizeof(*out));
        return false;
    }
    snprintf(candidate.loaded_path, sizeof(candidate.loaded_path), "%s", path);
    *out = candidate;
    return true;
}

void nhr_library_close(Nhr_Library *library) {
    if (!library) return;
    if (library->handle) nhr_platform_close(library->handle);
    if (library->loaded_path[0]) remove(library->loaded_path);
    memset(library, 0, sizeof(*library));
}

bool nhr_runtime_init(Nhr_Runtime *runtime, storage_context_t *storage,
                      const relay_config_t *config,
                      const char *module_path) {
    Nhr_Library library;
    bool initialized = false;
    if (!runtime || !storage || !config || !module_path) return false;
    memset(runtime, 0, sizeof(*runtime));
    runtime->storage = storage;
    runtime->module_storage = *storage;
    runtime->config = *config;
    runtime->config.storage = &runtime->module_storage;
    runtime->services.abi_version = NHR_ABI_VERSION;
    runtime->services.struct_size = sizeof(runtime->services);
    runtime->services.userdata = runtime;
    runtime->services.send_json = host_send_json;
    runtime->services.storage_insert_record = host_storage_insert;
    runtime->services.storage_get_event_copy = host_storage_get_event;
    runtime->services.storage_delete_by_id_and_pubkey = host_storage_delete_id;
    runtime->services.storage_delete_by_kind_and_pubkey = host_storage_delete_kind;
    runtime->services.storage_find_events = host_storage_find_events;
    runtime->services.storage_count_events = host_storage_count_events;
    runtime->services.storage_delete_events = host_storage_delete_events;
    runtime->services.storage_transaction_begin = host_storage_transaction_begin;
    runtime->services.storage_transaction_commit = host_storage_transaction_commit;
    runtime->services.storage_transaction_rollback = host_storage_transaction_rollback;
    runtime->services.storage_delete_events_tx = host_storage_delete_events_tx;
    runtime->services.storage_find_events_tx = host_storage_find_events_tx;
    runtime->services.storage_upsert_replaceable = host_storage_upsert_replaceable;
    runtime->services.storage_upsert_addressable = host_storage_upsert_addressable;
    runtime->services.storage_find_ids_by_tags = host_storage_find_ids_by_tags;
    runtime->services.storage_free_id_list = host_storage_free_id_list;
    runtime->services.crypto_check_event = host_crypto_check_event;
    runtime->services.crypto_sha256 = host_crypto_sha256;
    runtime->services.crypto_signature_verify = host_crypto_signature_verify;
    runtime->services.crypto_count_leading_zero_bits = host_crypto_count_leading_zero_bits;
    runtime->services.connection_id = host_connection_id;
    runtime->services.connection_snapshot = host_connection_snapshot;
    runtime->services.connection_get_challenge = host_connection_get_challenge;
    runtime->services.connection_set_challenge = host_connection_set_challenge;
    runtime->services.connection_get_auth_pubkey = host_connection_get_auth_pubkey;
    runtime->services.connection_set_auth = host_connection_set_auth;
    runtime->services.connection_clear_auth = host_connection_clear_auth;
    runtime->services.connection_add_auth = host_connection_add_auth;
    runtime->services.connection_has_auth = host_connection_has_auth;
    runtime->services.connection_get_auth_count = host_connection_get_auth_count;
    runtime->services.connection_get_auth_at = host_connection_get_auth_at;
    runtime->services.alloc = host_alloc;
    runtime->services.free = host_free;
    /* Loader startup is LOAD -> ABI VALIDATION -> INIT -> RUN. */
    memset(&library, 0, sizeof(library));
    if (!nhr_runtime_load_generation(runtime, module_path, &library)) return false;
    initialized = library.api.init(&runtime->services, &runtime->config,
                                   &runtime->module_storage);
    if (!initialized) {
        library.api.shutdown();
        nhr_library_close(&library);
        return false;
    }
    runtime->library = library;
    runtime->active = library.api;
    snprintf(runtime->published_path, sizeof(runtime->published_path), "%s", module_path);
    snprintf(runtime->loaded_path, sizeof(runtime->loaded_path), "%s", library.loaded_path);
    return true;
}

bool nhr_runtime_build_candidate(Nhr_Runtime *runtime,
                                const char *candidate_path,
                                Nhr_Library *candidate) {
    if (!runtime || !candidate_path || !candidate) return false;
    memset(candidate, 0, sizeof(*candidate));
    /* PRE-FLIGHT only: LOAD + ABI VALIDATION. Do not call INIT while the
     * previous generation is still in RUN. Candidate constructors build only
     * image-local registry state and must not acquire host resources. */
    if (!nhr_runtime_load_generation(runtime, candidate_path, candidate)) return false;
    if (candidate->api.abi_version() != NHR_ABI_VERSION) {
        nhr_library_close(candidate);
        return false;
    }
    return true;
}

bool nhr_runtime_activate_candidate(Nhr_Runtime *runtime,
                                   Nhr_Library *candidate) {
    Nhr_Library old;
    Nhr_State state;
    char candidate_source_path[sizeof(candidate->loaded_path)];
    char old_published_path[sizeof(runtime->published_path)];
    if (!runtime || !candidate || !candidate->handle || !runtime->library.handle) return false;
    snprintf(candidate_source_path, sizeof(candidate_source_path), "%s",
             candidate->source_path);
    snprintf(old_published_path, sizeof(old_published_path), "%s", runtime->published_path);
    /* PRE_RELOAD -> SHUTDOWN -> UNLOAD -> fresh LOAD/ABI VALIDATION ->
     * POST_RELOAD -> RUN. No module callback can be running here: this is
     * invoked synchronously from the host event-loop timer. */
    state = runtime->library.api.pre_reload();
    if (state.version != NHR_STATE_VERSION ||
        (state.size != 0 && state.data == NULL) ||
        (state.size == 0 && state.data != NULL)) {
        if (state.data) host_free(state.data);
        nhr_library_close(candidate);
        return false;
    }
    /* SHUTDOWN, then UNLOAD old image before loading the candidate generation.
     * The preflight image is also unloaded so POST_RELOAD runs in a fresh image
     * whose constructors have rebuilt its private plugin registry. */
    old = runtime->library;
    runtime->library.handle = NULL;
    memset(&runtime->active, 0, sizeof(runtime->active));
    old.api.shutdown();
    nhr_library_close(&old);
    nhr_library_close(candidate); /* discard preflight image; next LOAD is fresh */
    Nhr_Library activated;
    memset(&activated, 0, sizeof(activated));
    if (!nhr_runtime_load_generation(runtime, candidate_source_path, &activated) ||
        !activated.api.post_reload(&runtime->services, &runtime->config,
                                   &runtime->module_storage, state)) {
        if (activated.handle) {
            activated.api.shutdown();
            nhr_library_close(&activated);
        }
        Nhr_Library fallback;
        memset(&fallback, 0, sizeof(fallback));
        if (nhr_runtime_load_generation(runtime, old_published_path, &fallback) &&
            fallback.api.post_reload(&runtime->services, &runtime->config,
                                     &runtime->module_storage, state)) {
            runtime->library = fallback;
            runtime->active = fallback.api;
            runtime->generation++;
            snprintf(runtime->published_path, sizeof(runtime->published_path), "%s", old_published_path);
            snprintf(runtime->loaded_path, sizeof(runtime->loaded_path), "%s", fallback.loaded_path);
        } else {
            if (fallback.handle) fallback.api.shutdown();
            nhr_library_close(&fallback);
            memset(&runtime->library, 0, sizeof(runtime->library));
            memset(&runtime->active, 0, sizeof(runtime->active));
        }
        if (state.data) host_free(state.data);
        return false;
    }
    runtime->library = activated;
    runtime->active = activated.api;
    snprintf(runtime->loaded_path, sizeof(runtime->loaded_path), "%s", activated.loaded_path);
    snprintf(runtime->published_path, sizeof(runtime->published_path), "%s",
             candidate_source_path);
    if (state.data) host_free(state.data);
    return true;
}

bool nhr_runtime_try_reload(Nhr_Runtime *runtime, const char *candidate_path) {
    Nhr_Library candidate;
    if (!runtime || !candidate_path || !runtime->library.handle) return false;
    if (!nhr_runtime_build_candidate(runtime, candidate_path, &candidate)) return false;
    /* Activation consumes the preflight image whether it succeeds or fails. */
    return nhr_runtime_activate_candidate(runtime, &candidate);
}

void nhr_runtime_shutdown(Nhr_Runtime *runtime) {
    if (!runtime) return;
    if (runtime->library.handle) {
        runtime->library.api.shutdown();
        nhr_library_close(&runtime->library);
    }
    memset(runtime, 0, sizeof(*runtime));
}
