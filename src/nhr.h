/**
 * \file            nhr.h
 * \brief           Nob hot-reload shared ABI
 */

#ifndef NHR_H_
#define NHR_H_

/* Shared Nob Hot Reload ABI. Bump NHR_ABI_VERSION on incompatible changes. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <mongoose.h>
#include "storage.h"
#include "relay/config.h"

/* Forward declarations to avoid circular dependencies */
typedef struct nip_registry nip_registry_t;
typedef struct connection_snapshot connection_snapshot_t;

#ifdef _WIN32
#define NHR_CALL __cdecl
#ifdef NHR_BUILD_MODULE
#define NHR_EXPORT __declspec(dllexport)
#else
#define NHR_EXPORT
#endif
#else
#define NHR_CALL
#define NHR_EXPORT __attribute__((visibility("default")))
#endif

/* v7 removed modify_results from nip_query_policy_capability_t (never dispatched).
 * v6 removed composition.* and nip42.* toggles from relay_config_t
 * (auth is always required; combinators are hardcoded). v5 removed
 * storage_delete_matching (predicate callback across the hot reload
 * boundary). v4 changed relay_config_t layout (owned string buffers,
 * verbosity enum replacing bool debug_logging, nip42/hot_reload sections).
 * v3 added the multi-pubkey session services. Rebuild host and module
 * together on version change. */
#define NHR_ABI_VERSION 7u
#define NHR_STATE_VERSION 1u

typedef struct {
    uint32_t version;
    void *data;
    size_t size;
} Nhr_State;

/* Resident process services. Storage callbacks are synchronous; buffers
 * returned by storage_get_event_copy are host-owned and must be freed through
 * `free`. Module callbacks passed into a service are never retained. */
typedef struct Nhr_Host {
    uint32_t abi_version;
    uint32_t struct_size;
    void *userdata;
    void (NHR_CALL *send_json)(void *userdata, void *connection,
                               const char *json, size_t length);
    storage_insert_result_t (NHR_CALL *storage_insert_record)(void *userdata, const event_t *event,
                                                              const storage_tag_match_t *tags,
                                                              size_t tags_count);
    bool (NHR_CALL *storage_get_event_copy)(void *userdata, const char *id,
                                            event_t *out_event,
                                            char **owned_tags,
                                            char **owned_content);
    int (NHR_CALL *storage_delete_by_id_and_pubkey)(void *userdata,
                                                    const char *id,
                                                    const char *pubkey);
    int (NHR_CALL *storage_delete_by_kind_and_pubkey)(void *userdata, int kind,
                                                      const char *pubkey,
                                                      time_t created_at);
    /* Legacy storage_delete_matching (predicate callback across the hot
     * reload boundary) deleted. Modules use find/delete_events. */
    /* New unified storage API (per NOSTR_EVENT_STORAGE_SPEC.md) -
     * exposed for module builds; host calls global functions directly. */
    bool (NHR_CALL *storage_find_events)(void *userdata,
                                         const storage_event_scope_t *scope,
                                         event_t ***out_events,
                                         size_t *out_count);
    bool (NHR_CALL *storage_count_events)(void *userdata,
                                          const storage_event_scope_t *scope,
                                          size_t *out_count);
    bool (NHR_CALL *storage_delete_events)(void *userdata,
                                           const storage_event_scope_t *scope,
                                           size_t *out_deleted);
    storage_transaction_t *(NHR_CALL *storage_transaction_begin)(void *userdata);
    bool (NHR_CALL *storage_transaction_commit)(void *userdata, storage_transaction_t *tx);
    void (NHR_CALL *storage_transaction_rollback)(void *userdata, storage_transaction_t *tx);
    bool (NHR_CALL *storage_delete_events_tx)(void *userdata,
                                              const storage_event_scope_t *scope,
                                              storage_transaction_t *tx,
                                              size_t *out_deleted);
    bool (NHR_CALL *storage_find_events_tx)(void *userdata,
                                            const storage_event_scope_t *scope,
                                            storage_transaction_t *tx,
                                            event_t ***out_events,
                                            size_t *out_count);
    storage_insert_result_t (NHR_CALL *storage_upsert_replaceable)(void *userdata,
                                                                   const event_t *event,
                                                                   const storage_tag_match_t *indexed_tags,
                                                                   size_t indexed_tags_count);
    storage_insert_result_t (NHR_CALL *storage_upsert_addressable)(void *userdata,
                                                                   const event_t *event,
                                                                   const char *d_tag_value,
                                                                   const storage_tag_match_t *indexed_tags,
                                                                   size_t indexed_tags_count);
    bool (NHR_CALL *storage_find_ids_by_tags)(void *userdata,
                                              const char *const *tag_names,
                                              const char *const *tag_values,
                                              size_t tag_count,
                                              char ***ids_out,
                                              size_t *count_out);
    void (NHR_CALL *storage_free_id_list)(void *userdata, char **ids, size_t count);
    bool (NHR_CALL *crypto_check_event)(void *userdata, const event_t *event);
    void (NHR_CALL *crypto_sha256)(void *userdata, const uint8_t *data,
                                   size_t length, uint8_t digest[32]);
    bool (NHR_CALL *crypto_signature_verify)(void *userdata,
                                             const char *signature,
                                             const char *pubkey,
                                             const uint8_t digest[32]);
    unsigned (NHR_CALL *crypto_count_leading_zero_bits)(void *userdata,
                                                        const char *hex);
    size_t (NHR_CALL *connection_snapshot)(void *userdata,
                                            connection_snapshot_t *connections,
                                            size_t capacity);
    uintptr_t (NHR_CALL *connection_id)(void *userdata, void *connection);
    /* NIP-42 session-auth state (host-owned connection_session_t). All
     * synchronous. Borrowed strings are valid until the next session
     * mutation; copy them if retained. set_* with NULL clears the field.
     * Added in ABI v2; check for non-NULL before calling when talking to
     * an older host. */
    const char *(NHR_CALL *connection_get_challenge)(void *userdata,
                                                     uintptr_t connection_id);
    bool (NHR_CALL *connection_set_challenge)(void *userdata,
                                              uintptr_t connection_id,
                                              const char *challenge);
    const char *(NHR_CALL *connection_get_auth_pubkey)(void *userdata,
                                                       uintptr_t connection_id);
    bool (NHR_CALL *connection_set_auth)(void *userdata,
                                         uintptr_t connection_id,
                                         const char *pubkey);
    void (NHR_CALL *connection_clear_auth)(void *userdata,
                                           uintptr_t connection_id);
    /* Multi-pubkey session-auth services (ABI v3). add_auth appends without
     * clearing existing pubkeys; has_auth tests membership; count/at
     * enumerate. Added in ABI v3; check for non-NULL before calling when
     * talking to an older host. */
    bool (NHR_CALL *connection_add_auth)(void *userdata,
                                         uintptr_t connection_id,
                                         const char *pubkey);
    bool (NHR_CALL *connection_has_auth)(void *userdata,
                                         uintptr_t connection_id,
                                         const char *pubkey);
    size_t (NHR_CALL *connection_get_auth_count)(void *userdata,
                                                 uintptr_t connection_id);
    const char *(NHR_CALL *connection_get_auth_at)(void *userdata,
                                                   uintptr_t connection_id,
                                                   size_t index);
    void *(NHR_CALL *alloc)(size_t size);
    void (NHR_CALL *free)(void *ptr);
} Nhr_Host;

/* Module lifecycle: `init` is called after LOAD+ABI validation at startup;
 * reload uses old `pre_reload`, old `shutdown`/UNLOAD, fresh LOAD+validation,
 * then new `post_reload`. `post_reload` performs new-generation INIT and
 * state restoration. No dispatch occurs until that returns true. */

/* One symbol list produces module declarations and the host function table. */
#define NHR_MODULE_FUNCTIONS(X) \
    X(uint32_t, abi_version, (void)) \
    X(bool, init, (const Nhr_Host *host, const relay_config_t *config, void *storage_handle)) \
    X(void, shutdown, (void)) \
    X(Nhr_State, pre_reload, (void)) \
    X(bool, post_reload, (const Nhr_Host *host, const relay_config_t *config, void *storage_handle, Nhr_State state)) \
    X(void, register_capabilities, (nip_registry_t *registry))

#define NHR_DECLARE_EXPORT(ret, name, args) NHR_EXPORT ret NHR_CALL nhr_module_##name args;
NHR_MODULE_FUNCTIONS(NHR_DECLARE_EXPORT)
#undef NHR_DECLARE_EXPORT

/* Host-side function pointers - only the 6 lifecycle functions */
typedef struct {
#define NHR_DECLARE_POINTER(ret, name, args) ret (NHR_CALL *name) args;
    NHR_MODULE_FUNCTIONS(NHR_DECLARE_POINTER)
#undef NHR_DECLARE_POINTER
} Nhr_Module;

typedef struct {
    void *handle;
    Nhr_Module api;
    char source_path[1024];
    char loaded_path[1024];
} Nhr_Library;

typedef struct {
    storage_context_t *storage;
    storage_context_t module_storage;
    Nhr_Host services;
    Nhr_Library library;
    Nhr_Module active;
    relay_config_t config;
    unsigned generation;
    char published_path[1024];
    char loaded_path[1024];
} Nhr_Runtime;

bool nhr_library_open(Nhr_Library *out, const char *path);
void nhr_library_close(Nhr_Library *library);
bool nhr_runtime_init(Nhr_Runtime *runtime, storage_context_t *storage,
                      const relay_config_t *config, const char *module_path);
bool nhr_runtime_build_candidate(Nhr_Runtime *runtime,
                                 const char *candidate_path,
                                 Nhr_Library *candidate);
bool nhr_runtime_activate_candidate(Nhr_Runtime *runtime,
                                    Nhr_Library *candidate);
bool nhr_runtime_try_reload(Nhr_Runtime *runtime, const char *candidate_path);
void nhr_runtime_shutdown(Nhr_Runtime *runtime);
void nhr_runtime_connection_closed(Nhr_Runtime *runtime, void *connection);

#endif /* NHR_H_ */
