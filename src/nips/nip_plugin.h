#ifndef NIP_PLUGIN_H_
#define NIP_PLUGIN_H_

#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <mongoose.h>
#include "nostrogotho.h"
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

typedef struct nip_plugin {
    const char *name;

    /* Called once during server_configure() with the relay's runtime config. */
    void (*init)(const relay_config_t *config);

    /* Connection lifecycle (e.g. NIP-42 sends its AUTH challenge here). */
    void (*on_connect)(struct mg_connection *connection);
    void (*on_disconnect)(struct mg_connection *connection);

    /* Return true if the plugin consumed the message (e.g. NIP-42 "AUTH"). */
    bool (*on_message)(struct mg_connection *connection,
                       json_value_t *values, size_t count);

    /* Publish policy. Return false and fill `reason` to reject an EVENT
     * before kind dispatch (e.g. NIP-40 expiry, NIP-42 restricted tags). */
    bool (*accept_publish)(struct mg_connection *connection,
                           const event_t *event,
                           char *reason, size_t reason_size);

    /* Delivery policy. Return false to suppress an event for this
     * connection on both stored queries and broadcasts (NIP-40, NIP-17). */
    bool (*can_deliver)(const event_t *event, struct mg_connection *connection);

    /* Called when a REQ finishes. May emit its own protocol traffic (e.g.
     * NIP-17 sends a fresh AUTH challenge for gift-wrap subscriptions) and
     * returns true to make the EOSE carry the "auth" completeness hint. */
    bool (*eose_auth_hint)(struct mg_connection *connection,
                           const filter_t *filters, size_t count);

    /* Build the ["EOSE", ...] / ["COUNT", ...] response (malloc'd, caller
     * frees). The first plugin providing the hook wins; otherwise the
     * server falls back to a bare protocol-default response. */
    char *(*build_eose)(const char *sub, bool has_more, bool auth_hint);
    char *(*build_count)(const char *sub, unsigned long count);

    /* Periodic maintenance, driven every timer_interval_ms inside the
     * event loop (e.g. NIP-40 expired-event GC). */
    void (*timer)(storage_context_t *storage);
    unsigned timer_interval_ms;

    /* NIP-11 relay information document (HTTP, Accept: application/nostr+json). */
    const char *(*info_document)(void);

    struct nip_plugin *next;
} nip_plugin_t;

/* Register a plugin. Call from __attribute__((constructor)) in the NIP's
 * own .c file so inclusion in the build is the only opt-in required. */
void nip_plugin_register(nip_plugin_t *plugin);

/* Head of the registration list (in registration order). */
nip_plugin_t *nip_plugins(void);

/* Invoke every plugin's init() hook. Called by server_configure(). */
void nip_plugins_init(const relay_config_t *config);

/* Convenience senders plugins may use instead of hand-rolling JSON. */
void nip_plugin_send_json(struct mg_connection *connection, const char *json);
void nip_plugin_send_status(struct mg_connection *connection, const char *type,
                            const char *id, bool ok, const char *message);

#endif /* NIP_PLUGIN_H_ */
