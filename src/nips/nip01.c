#include "nip01.h"
#include "../crypto.h"
#include "../storage.h"
#include "nip_event.h"
#include "nip_plugin.h"
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * NIP-01: Basic Protocol Flow, Events and Signatures
 * 
 * Implementation of core event validation and the event dispatch system.
 * Each NIP is a plugin that declares the event kinds it cares about; when
 * an event arrives, the dispatcher calls every plugin whose declared kind
 * ranges cover it, in registration order.
 *
 * Consolidated here per the reference specs:
 *   - NIP-16 (Event Treatment) is `final mandatory` and "Moved to NIP-01":
 *     replaceable-event handling for kinds 0, 3, 10000-19999 lives here.
 *   - NIP-33 (Parameterized Replaceable Events) is `final mandatory` and
 *     "Moved to NIP-01": addressable-event handling for kinds 30000-39999
 *     (with the "d" tag) lives here.
 * ============================================================================ */

bool nip01_validate_event(const event_t *ev) {
    if (!ev) return false;
    
    /* Delegate to crypto layer for full validation
     * (ID verification, signature verification, delegation checking) */
#ifdef NHR_BUILD_MODULE
    extern bool nhr_module_accepts_event(const event_t *event);
    return nhr_module_accepts_event(ev);
#else
    return check_event(ev);
#endif
}

/* ============================================================================
 * Event Dispatcher
 *
 * The dispatcher walks the plugin registry (nip_plugins()) and invokes each
 * plugin's on_event hook when the event's kind falls inside one of the
 * plugin's declared kind ranges. There is no separate listener registry:
 * a plugin declares its kinds in its nip_plugin_t and nip_plugin_register()
 * is the only registration call.
 * ============================================================================ */

/* Return true if `kind` falls inside any of the plugin's declared ranges. */
static bool plugin_listens_for(const nip_plugin_t *plugin, int kind) {
    for (size_t i = 0; i < plugin->kinds_count; i++) {
        if (kind >= plugin->kinds[i].kind_min && kind <= plugin->kinds[i].kind_max) {
            return true;
        }
    }
    return false;
}

nip01_process_result_t nip01_process_event(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url,
    size_t max_content_length,
    time_t created_at_lower_limit,
    time_t created_at_upper_limit,
    int min_pow_difficulty) {

    (void) min_pow_difficulty; /* PoW is enforced by the nip13 plugin hook. */
    nip01_process_result_t result = {0};
    
    if (!event) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "error: invalid event");
        return result;
    }
    
    /* Step 1: Validate event (ID, signature, delegation) */
    if (!nip01_validate_event(event)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "invalid: event id, signature or delegation is invalid");
        return result;
    }
    
    /* Step 2: Check content size */
    if (max_content_length > 0 && event->content_len > max_content_length) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "invalid: content too large");
        return result;
    }

    /* Step 2b: Reject events whose serialization can never fit the fixed
     * 64 KiB response buffer. Without this, such events are accepted and
     * stored but are truncated mid-JSON (i.e. delivered as garbage) on
     * every later query or broadcast. The 160-byte margin covers the
     * ["EVENT","<sub id up to 100 chars>",...] wrapper. */
    if (json_serialized_event_size(event) + 160 > JSON_BUILDER_BUFFER_SIZE) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "invalid: event serialization too large");
        return result;
    }
    
    /* Step 3: Check timestamp limits */
    time_t now = time(NULL);
    if ((created_at_lower_limit && event->created_at < now - created_at_lower_limit) ||
        (created_at_upper_limit && event->created_at > now + created_at_upper_limit)) {
        result.accepted = false;
        snprintf(result.response_msg, sizeof(result.response_msg),
                "invalid: created_at is out of the acceptable range");
        return result;
    }
    
    /* Step 4: Proof-of-work (NIP-13) is enforced by the nip13 plugin's
     * accept_publish hook, which the server runs before dispatching here. */

    /* Step 4b: NIP-module publish policies (e.g. NIP-40 expiry, NIP-42
     * auth-required tags) are enforced by the server before dispatch via
     * plugin accept_publish() hooks, so this dispatcher stays NIP-agnostic. */

    /* Step 5: Call every plugin whose declared kind ranges cover this kind,
     * in registration order. The first listener to accept wins. */
    bool any_listener_matched = false;
    for (nip_plugin_t *plugin = nip_plugins(); plugin; plugin = plugin->next) {
        if (!plugin->on_event || !plugin_listens_for(plugin, event->kind)) {
            continue;
        }
        any_listener_matched = true;
        result = plugin->on_event(connection, event, storage, relay_url);
        if (result.accepted) {
            return result;
        }
    }
    if (any_listener_matched) {
        /* All matching listeners rejected this event */
        if (result.response_msg[0] == '\0') {
            snprintf(result.response_msg, sizeof(result.response_msg),
                    "invalid: event rejected by all handlers");
        }
        return result;
    }
    
    /* Step 6: No listener claimed this kind - fall back to default NIP-01
     * behavior. Ephemeral events (kinds 20000-29999) are broadcast without
     * storage; everything else is stored and broadcast. */
    if (event->kind >= 20000 && event->kind < 30000) {
        return nip_plugin_accept();
    }
    
    return nip_plugin_store_and_broadcast(storage, event);
}

/* ============================================================================
 * NIP-16 (moved to NIP-01): Replaceable Events
 *
 * Kinds 0, 3 and 10000-19999 are replaceable: for each (kind, pubkey) only
 * the latest event is retained. When a newer event arrives, the previous
 * record is deleted before the new one is stored. On equal created_at the
 * storage layer performs the lexical id tie-break (lowest id wins).
 * ============================================================================ */

static bool nip01_replace_event(const event_t *event, storage_context_t *storage) {
    return storage->delete_record_by_kind_and_pubkey(event->kind, event->pubkey,
                                                     event->created_at) >= 0;
}

typedef struct {
    const char *identifier;
} nip01_dtag_match_t;

static bool nip01_matches_dtag(const event_t *event, void *userdata) {
    const nip01_dtag_match_t *match = (const nip01_dtag_match_t *)userdata;
    struct mg_str key, tag, tags = mg_str(event->tags_json ? event->tags_json : "[]");
    size_t offset = 0;
    bool found_d = false;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "d") == 0) {
            char *value = nip_tag_element(tag, 1);
            found_d = true;
            bool matched = strcmp(value ? value : "", match->identifier) == 0;
            free(value);
            free(name);
            return matched;
        }
        free(name);
    }
    /* NIP-01/33: absence of a d tag is equivalent to d="". */
    return !found_d && match->identifier[0] == '\0';
}

static bool nip01_delete_addressable(const event_t *event,
                                     storage_context_t *storage,
                                     const char *identifier) {
    storage_event_scope_t scope = {0};
    nip01_dtag_match_t match;
    char cursor[MAX_ID_SIZE + 1] = "";
    bool more;

    if (!storage || !storage->delete_matching) return false;
    scope.pubkey = event->pubkey;
    scope.has_kind = true;
    scope.kind = event->kind;
    scope.has_created_at_before = true;
    scope.created_at_before = event->created_at;
    match.identifier = identifier ? identifier : "";

    do {
        size_t deleted = 0;
        char next_id[MAX_ID_SIZE + 1] = "";
        scope.after_id = cursor[0] ? cursor : NULL;
        if (!storage->delete_matching(&scope, nip01_matches_dtag, &match,
                                      &deleted, next_id, sizeof(next_id), &more)) return false;
        (void)deleted;
        snprintf(cursor, sizeof(cursor), "%s", next_id);
    } while (more);
    return true;
}

static nip01_process_result_t nip01_replaceable_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;
    (void)relay_url;

    if (!storage) {
        return nip_plugin_reject("error: storage unavailable");
    }

    if (!nip01_replace_event(event, storage)) {
        return nip_plugin_reject("error: failed to replace event");
    }

    return nip_plugin_store_and_broadcast(storage, event);
}

/* ============================================================================
 * NIP-33 (moved to NIP-01): Addressable (Parameterized Replaceable) Events
 *
 * Kinds 30000-39999 are addressable: for each (kind, pubkey, "d" tag value)
 * only the latest event is stored. The "d" tag value is the addressable
 * identifier; an event without a "d" tag is treated as having an empty one.
 * ============================================================================ */

static bool nip01_replace_addressable_event(const event_t *event,
                                            storage_context_t *storage) {
    struct mg_str key, tag, tags = mg_str(event->tags_json);
    size_t offset = 0;
    char *dvalue = NULL;
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        bool is_d = name && strcmp(name, "d") == 0;
        free(name);
        if (is_d) {
            dvalue = nip_tag_element(tag, 1);
            break;
        }
    }
    /* NIP-01: an event without a "d" tag is treated as having an empty one. */
    bool replaced = nip01_delete_addressable(event, storage, dvalue);
    free(dvalue);
    return replaced;
}

static nip01_process_result_t nip01_addressable_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    (void)connection;
    (void)relay_url;

    if (!storage) {
        return nip_plugin_reject("error: storage unavailable");
    }

    if (!nip01_replace_addressable_event(event, storage)) {
        return nip_plugin_reject("error: failed to replace event");
    }

    return nip_plugin_store_and_broadcast(storage, event);
}

/* ============================================================================
 * Built-in plugin registration (NIP-16 / NIP-33 consolidated into NIP-01)
 *
 * The replaceable/addressable semantics are themselves a plugin: it listens
 * for the NIP-16 / NIP-33 kind ranges and handles storage replacement. This
 * keeps the dispatcher purely mechanical — it never special-cases kinds.
 * ============================================================================ */

/* Single on_event entry that routes to the replaceable or addressable
 * handler based on the kind range (NIP-33 kinds are 30000-39999). */
static nip01_process_result_t nip01_builtin_listener(
    struct mg_connection *connection,
    const event_t *event,
    storage_context_t *storage,
    const char *relay_url) {

    if (event->kind >= 30000 && event->kind < 40000) {
        return nip01_addressable_listener(connection, event, storage, relay_url);
    }
    return nip01_replaceable_listener(connection, event, storage, relay_url);
}

static nip_plugin_t nip01_plugin = {
    .name = "nip01",
    .kinds = {
        NIP_PLUGIN_KIND(0),            /* NIP-16 replaceable: metadata */
        NIP_PLUGIN_KIND(3),            /* NIP-16 replaceable: contacts */
        { 10000, 19999 },              /* NIP-16 replaceable: app data */
        { 30000, 39999 },              /* NIP-33 addressable */
    },
    .kinds_count = 4,
    .on_event = nip01_builtin_listener,
};

/* Auto-register the built-in NIP-16 / NIP-33 plugin at program startup,
 * matching the self-registration pattern used by every other NIP module. */
__attribute__((constructor)) static void nip01_register_at_startup(void) {
    nip_plugin_register(&nip01_plugin);
}

