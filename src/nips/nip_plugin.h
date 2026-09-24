#ifndef NIP_PLUGIN_H_
#define NIP_PLUGIN_H_

#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <mongoose.h>
#include "nostrogotho.h"
#include "nip01.h"
#include "../storage.h"
#include "../json_util.h"

/* ============================================================================
 * NIP Plugin Interface
 *
 * Every NIP module in src/nips/ is a self-contained plugin. A plugin links
 * itself into the relay purely by being compiled: each nipXX.c registers a
 * nip_plugin_t via nip_plugin_register() from an __attribute__((constructor))
 * function. server.c knows nothing about individual NIPs — it only walks the
 * registry and invokes whichever hooks a plugin provides (NULL = not used).
 *
 * Kind listening is part of the plugin itself: declare the kinds you handle
 * in kinds[] and provide on_event. nip_plugin_register() wires those kinds
 * into the NIP-01 dispatcher automatically — there is no separate listener
 * registry or second registration call.
 *
 * Adding a NIP  = drop nipXX.c into src/nips/ (the build tool globs it).
 * Removing one  = delete the file; the relay degrades to plain NIP-01.
 * ============================================================================
 */

/* Runtime relay configuration handed to every plugin's init() hook. */
typedef struct {
    const char *service_url;
    storage_context_t *storage;
    int max_message_length;
    int max_subscriptions;
    int max_filters;
    int max_subid_length;
    int max_event_tags;
    int max_content_length;
    int min_pow_difficulty;
    int max_limit;
    int default_limit;
    time_t created_at_lower_limit;
    time_t created_at_upper_limit;
    bool auth_required;
} relay_config_t;

/* Maximum number of event-kind ranges a single plugin may listen for. */
#define NIP_PLUGIN_MAX_KIND_RANGES 4

/* Inclusive kind range a plugin listens for. Use {k, k} for a single kind;
 * the NIP_PLUGIN_KIND(k) macro is shorthand for that. */
typedef struct {
    int kind_min;
    int kind_max;
} nip_plugin_kind_range_t;

#define NIP_PLUGIN_KIND(k) { (k), (k) }

typedef struct nip_plugin {
    const char *name;

    /* Per-plugin state. Allocated by the plugin (typically in a constructor
     * or lazily in init()) and threaded back into every hook call, so a
     * plugin never needs file-scope static globals. */
    void *ctx;

    /* Event-kind ranges this plugin listens for. When an event's kind falls
     * inside one of them, on_event is invoked by the NIP-01 dispatcher.
     * kinds_count of 0 means the plugin has no kind listener. */
    nip_plugin_kind_range_t kinds[NIP_PLUGIN_MAX_KIND_RANGES];
    size_t kinds_count;

    /* Kind listener. Called by the NIP-01 dispatcher when an event's kind
     * matches one of the ranges in kinds[]. The first listener to accept
     * wins; if every matching listener rejects, the event is rejected. */
    nip01_event_listener_t on_event;

    /* Called once during server_configure() with the relay's runtime config. */
    void (*init)(const relay_config_t *config, void *ctx);

    /* Connection lifecycle (e.g. NIP-42 sends its AUTH challenge here). */
    void (*on_connect)(struct mg_connection *connection, void *ctx);
    void (*on_disconnect)(struct mg_connection *connection, void *ctx);

    /* Return true if the plugin consumed the message (e.g. NIP-42 "AUTH"). */
    bool (*on_message)(struct mg_connection *connection,
                       json_value_t *values, size_t count, void *ctx);

    /* Publish policy. Return false and fill `reason` to reject an EVENT
     * before kind dispatch (e.g. NIP-40 expiry, NIP-42 restricted tags). */
    bool (*accept_publish)(struct mg_connection *connection,
                           const event_t *event,
                           char *reason, size_t reason_size, void *ctx);

    /* Delivery policy. Return false to suppress an event for this
     * connection on both stored queries and broadcasts (NIP-40, NIP-17). */
    bool (*can_deliver)(const event_t *event, struct mg_connection *connection,
                        void *ctx);

    /* Called when a REQ finishes. May emit its own protocol traffic (e.g.
     * NIP-17 sends a fresh AUTH challenge for gift-wrap subscriptions) and
     * returns true to make the EOSE carry the "auth" completeness hint. */
    bool (*eose_auth_hint)(struct mg_connection *connection,
                           const filter_t *filters, size_t count, void *ctx);

    /* Build the ["EOSE", ...] / ["COUNT", ...] response (malloc'd, caller
     * frees). The first plugin providing the hook wins; otherwise the
     * server falls back to a bare protocol-default response. */
    char *(*build_eose)(const char *sub, bool has_more, bool auth_hint, void *ctx);
    char *(*build_count)(const char *sub, unsigned long count, void *ctx);

    /* Periodic maintenance, driven every timer_interval_ms inside the
     * event loop (e.g. NIP-40 expired-event GC). */
    void (*timer)(storage_context_t *storage, void *ctx);
    unsigned timer_interval_ms;

    /* NIP-11 relay information document (HTTP, Accept: application/nostr+json). */
    const char *(*info_document)(void *ctx);

    struct nip_plugin *next;
} nip_plugin_t;

typedef void (*nip_plugin_send_json_fn)(struct mg_connection *connection,
                                        const char *json, size_t length);

/* Register a plugin. Call from __attribute__((constructor)) in the NIP's
 * own .c file so inclusion in the build is the only opt-in required. */
void nip_plugin_register(nip_plugin_t *plugin);
/* Clear host-service callback slots only; do not unlink constructor-registered
 * plugins from this image's registry. */
void nip_plugin_reset_registry(void);

/* Install an optional host transport bridge. Monolithic builds leave this
 * unset and use Mongoose directly; reloadable builds install the resident
 * host bridge during module initialization. */
void nip_plugin_set_send_json(nip_plugin_send_json_fn send_json);

/* Head of the registration list (in registration order). */
nip_plugin_t *nip_plugins(void);

/* Invoke every plugin's init() hook. Called by server_configure(). */
void nip_plugins_init(const relay_config_t *config);

/* Convenience senders plugins may use instead of hand-rolling JSON. */
void nip_plugin_send_json(struct mg_connection *connection, const char *json);
void nip_plugin_send_status(struct mg_connection *connection, const char *type,
                            const char *id, bool ok, const char *message);

/* ============================================================================
 * Ergonomic result / storage helpers
 *
 * Kind listeners return a nip01_process_result_t. These constructors cover
 * the common outcomes so a listener body is a few lines instead of a
 * hand-rolled struct + snprintf dance.
 * ============================================================================
 */

/* Accepted, broadcast to subscribers, no response message. */
nip01_process_result_t nip_plugin_accept(void);

/* Rejected with a human-readable reason (sent as the OK message). */
nip01_process_result_t nip_plugin_reject(const char *message);

/* Store the event and accept it for broadcast. Returns a duplicate result
 * when the event already exists (storage->insert_record returned false). */
nip01_process_result_t nip_plugin_store_and_broadcast(storage_context_t *storage,
                                                      const event_t *event);

/* Store the event without broadcasting (e.g. NIP-09 deletions). Returns a
 * duplicate result when the event already exists. */
nip01_process_result_t nip_plugin_store_only(storage_context_t *storage,
                                             const event_t *event);

/* Thin wrapper over storage->insert_record. */
bool nip_plugin_store(storage_context_t *storage, const event_t *event);

/* Configure the generic tag-index extractor used by plugin store helpers.
 * The hook is synchronous and the returned keys are freed before returning. */
typedef bool (*nip_plugin_tag_index_fn)(const event_t *event,
                                        storage_tag_match_t **matches,
                                        size_t *count);
typedef bool (*nip_plugin_query_index_fn)(const filter_t *filters,
                                          size_t filters_count,
                                          storage_tag_match_t **matches,
                                          size_t *count);
void nip_plugin_set_tag_indexer(nip_plugin_tag_index_fn indexer);
void nip_plugin_set_query_indexer(nip_plugin_query_index_fn indexer);
bool nip_plugin_extract_index_tags(const event_t *event,
                                   storage_tag_match_t **matches,
                                   size_t *count);
bool nip_plugin_query_index_tags(const filter_t *filters,
                                 size_t filters_count,
                                 storage_tag_match_t **matches,
                                 size_t *count);

#endif /* NIP_PLUGIN_H_ */
