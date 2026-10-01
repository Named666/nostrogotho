#include "subscription_manager.h"
#include "nostrogotho.h"
#include "storage.h"
#include "json_util.h"
#include "protocol/tag_iter.h"
#include "protocol/event_tags.h"
#include "nips/nip_capability.h"
#include "protocol/protocol.h"
#include "log.h"
#include <mongoose.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* mg_str_contains() is shared from json_util.h. */

/* ============================================================================
 * Single stored-query path using the unified storage API
 * (NOSTR_EVENT_STORAGE_SPEC.md). All REQ/COUNT history queries go through
 * query_with_new_api below via filter_to_scope. There is no legacy SQL
 * LIKE filter path: the old query_context/query_sender frame-reparse
 * pipeline was deleted. Live broadcasts use matches_filter (same OR/AND
 * tag semantics as build_where_clause) in match_and_deliver.
 * ============================================================================ */

/* Convert filter_t to storage_event_scope_t.
 * Single translation for the unified query path. Tag values for one name
 * are stored flat; build_where_clause groups them by name (OR within a
 * name, AND across names) to match matches_filter semantics. */
static void filter_to_scope(const filter_t *filter, storage_event_scope_t *scope) {
    memset(scope, 0, sizeof(*scope));
    
    if (filter->ids_count > 0) {
        scope->ids = (const char **)filter->ids;
        scope->ids_count = filter->ids_count;
    }
    if (filter->authors_count > 0) {
        scope->pubkeys = (const char **)filter->authors;
        scope->pubkeys_count = filter->authors_count;
    }
    if (filter->kinds_count > 0) {
        scope->kinds = filter->kinds;
        scope->kinds_count = filter->kinds_count;
    }
    
    /* Tag filters: convert #e, #p, #a tags to tag_names/tag_values arrays */
    if (filter->tags_count > 0) {
        /* Count total tag values across all tags */
        size_t total_values = 0;
        for (size_t i = 0; i < filter->tags_count; i++) {
            total_values += filter->tags[i].count - 1;  /* -1 for tag name */
        }
        
        if (total_values > 0) {
            scope->tag_names = (const char **)malloc(total_values * sizeof(char *));
            scope->tag_values = (const char **)malloc(total_values * sizeof(char *));
            if (scope->tag_names && scope->tag_values) {
                size_t idx = 0;
                for (size_t i = 0; i < filter->tags_count; i++) {
                    const tag_t *tag = &filter->tags[i];
                    for (size_t v = 1; v < tag->count; v++) {
                        scope->tag_names[idx] = tag->elements[0];
                        scope->tag_values[idx] = tag->elements[v];
                        idx++;
                    }
                }
                scope->tag_count = total_values;
            }
        }
    }
    
    if (filter->since > 0) {
        scope->has_created_at_at_or_after = true;
        scope->created_at_at_or_after = filter->since;
    }
    if (filter->until > 0) {
        scope->has_created_at_at_or_before = true;
        scope->created_at_at_or_before = filter->until;
    }
    
    if (filter->limit > 0) {
        scope->limit = filter->limit;
    }
    
    /* Note: search filter not yet supported in new scope API */
}

static void free_scope_tags(storage_event_scope_t *scope) {
    if (scope->tag_names) {
        free((void *)scope->tag_names);
        scope->tag_names = NULL;
    }
    if (scope->tag_values) {
        free((void *)scope->tag_values);
        scope->tag_values = NULL;
    }
    scope->tag_count = 0;
}

/* Query context removed: legacy frame-reparse pipeline deleted. */

/* Single in-memory matcher shared by live delivery and stored-query
 * verification. OR within each field (ids/authors/kinds/tag values for one
 * name), AND across fields and across distinct tag names. */
static bool matches_filter(const filter_t *filter, const event_t *event);

/* Query using new unified storage API */
/* BORROWS filters - does NOT take ownership. Filters owned by caller (subscription_manager or protocol_message). */
static bool query_with_new_api(subscription_manager_t *manager,
                               storage_context_t *storage,
                               connection_id_t connection_id,
                               const char *sub,
                               filter_t *filters,  /* BORROWED */
                               size_t filters_count,
                               bool do_count,
                               void (*send_json)(connection_id_t connection_id, const char *),
                               bool (*can_deliver)(const event_t *, connection_id_t, void *),
                               void *can_deliver_ctx,
                               char *(*build_eose)(const char *sub, bool has_more, bool auth_hint, void *ctx),
                               char *(*build_count)(const char *sub, unsigned long count, void *ctx),
                               bool (*needs_auth_hint)(const filter_t *filters,
                                                       size_t filters_count,
                                                       connection_id_t connection_id,
                                                       void *ctx),
                               void (*send_auth_challenge)(connection_id_t connection_id,
                                                           void *ctx),
                               void *protocol_response_ctx) {
    if (!manager || !storage || !connection_id || !sub || !filters || filters_count == 0 || !send_json) return false;

    log_debug("SUBSCRIPTION", "QUERY", "ENTRY sub=%s filters=%zu do_count=%d filters_ptr=%p (BORROWED)", 
              sub, filters_count, do_count, (void*)filters);

    /* connection_id is already resolved by caller */
    connection_id_t conn_id = connection_id;

    bool success = true;
    size_t total_count = 0;
    bool has_more = false;

    if (do_count) {
        /* COUNT: union count across filters (OR semantics). Storage scopes
         * cannot express cross-filter OR, so materialize IDs per filter and
         * deduplicate. Sums would double-count events matching 2+ filters. */
        char **seen_ids = NULL;
        size_t seen_count = 0;
        size_t seen_cap = 0;
        for (size_t f = 0; f < filters_count; f++) {
            storage_event_scope_t scope = {0};
            filter_to_scope(&filters[f], &scope);

            event_t **events = NULL;
            size_t count = 0;
            /* COUNT via find + in-memory verify so search/tag semantics
             * match REQ exactly (single matcher: matches_filter). */
            if (storage->find_events(&scope, &events, &count)) {
                for (size_t i = 0; i < count; i++) {
                    bool ok_filter = matches_filter(&filters[f], events[i]);
                    bool allowed = true;
                    if (ok_filter && can_deliver) {
                        allowed = can_deliver(events[i], conn_id, can_deliver_ctx);
                    }
                    if (ok_filter && allowed) {
                        bool dup = false;
                        for (size_t s = 0; s < seen_count; s++) {
                            if (strcmp(seen_ids[s], events[i]->id) == 0) {
                                dup = true;
                                break;
                            }
                        }
                        if (!dup) {
                            if (seen_count >= seen_cap) {
                                size_t ncap = seen_cap ? seen_cap * 2 : 32;
                                char **grown = (char **)realloc(seen_ids, ncap * sizeof(char *));
                                if (!grown) { event_free(events[i]); continue; }
                                seen_ids = grown;
                                seen_cap = ncap;
                            }
                            seen_ids[seen_count] = strdup(events[i]->id);
                            if (seen_ids[seen_count]) seen_count++;
                        }
                    }
                    event_free(events[i]);
                }
                free(events);
            }
            free_scope_tags(&scope);
        }
        total_count = seen_count;
        for (size_t s = 0; s < seen_count; s++) free(seen_ids[s]);
        free(seen_ids);
    } else {
        /* REQ: find events for each filter (OR semantics), deduplicated.
         * Storage is the single query path; matches_filter re-verifies each
         * row so `search` (not in scope) and any scope gap use the same
         * semantics as live delivery. */
        int limit = 500;
        if (filters[0].limit > 0 && filters[0].limit < limit) limit = filters[0].limit;

        int sent_count = 0;
        char **seen_ids = NULL;
        size_t seen_count = 0;
        size_t seen_cap = 0;

        for (size_t f = 0; f < filters_count && !has_more; f++) {
            storage_event_scope_t scope = {0};
            filter_to_scope(&filters[f], &scope);

            /* Fetch limit+1 to detect has_more */
            scope.limit = (size_t)limit + 1;

            event_t **events = NULL;
            size_t count = 0;
            if (storage->find_events(&scope, &events, &count)) {
                log_debug("SUBSCRIPTION", "QUERY", "filter[%zu] found %zu events", f, count);
                for (size_t i = 0; i < count && !has_more; i++) {
                    event_t *ev = events[i];
                    bool dup = false;
                    for (size_t s = 0; s < seen_count; s++) {
                        if (strcmp(seen_ids[s], ev->id) == 0) { dup = true; break; }
                    }
                    if (dup) { event_free(ev); continue; }
                    if (!matches_filter(&filters[f], ev)) { event_free(ev); continue; }
                    if (sent_count >= limit) {
                        has_more = true;
                        event_free(ev);
                        break;
                    }

                    /* Check delivery policy */
                    bool allowed = true;
                    if (can_deliver) {
                        allowed = can_deliver(ev, conn_id, can_deliver_ctx);
                    }

                    if (allowed) {
                        if (seen_count >= seen_cap) {
                            size_t ncap = seen_cap ? seen_cap * 2 : 32;
                            char **grown = (char **)realloc(seen_ids, ncap * sizeof(char *));
                            if (grown) { seen_ids = grown; seen_cap = ncap; }
                        }
                        if (seen_count < seen_cap || seen_cap == 0) {
                            /* Best-effort dedup record; send even if OOM. */
                            if (seen_ids && seen_count < seen_cap) {
                                seen_ids[seen_count] = strdup(ev->id);
                                if (seen_ids[seen_count]) seen_count++;
                            }
                        }
                        /* Build JSON event and send */
                        json_builder_t builder;
                        json_builder_start(&builder);
                        json_builder_append_string(&builder, "EVENT");
                        json_builder_append_string(&builder, sub);
                        json_serialize_event(ev, &builder);
                        send_json(conn_id, json_builder_finish(&builder));
                        sent_count++;
                    }
                    /* event_free() - storage_find_events TRANSFERS ownership of returned events to caller */
                    event_free(ev);
                }
                free(events);
            }
            free_scope_tags(&scope);
        }
        for (size_t s = 0; s < seen_count; s++) free(seen_ids[s]);
        free(seen_ids);
        has_more = has_more;
        total_count = (size_t)sent_count;
    }

    if (!success) {
        log_debug("SUBSCRIPTION", "QUERY", "FAILED");
        return false;
    }

    /* Send EOSE for REQ or COUNT response for COUNT */
    if (!do_count) {
        bool auth_hint = false;
        if (needs_auth_hint) {
            auth_hint = needs_auth_hint(filters, filters_count,
                                        conn_id,
                                        protocol_response_ctx);
            if (auth_hint && send_auth_challenge) {
                send_auth_challenge(conn_id,
                                    protocol_response_ctx);
            }
        }
        if (build_eose) {
            char *eose = build_eose(sub, has_more, auth_hint, protocol_response_ctx);
            if (eose) {
                send_json(conn_id, eose);
                free(eose);
            }
        } else {
            char *eose = protocol_serialize_eose(sub, has_more, auth_hint);
            if (eose) {
                send_json(conn_id, eose);
                free(eose);
            }
        }
    } else {
        if (build_count) {
            char *count_resp = build_count(sub, (unsigned long)total_count, protocol_response_ctx);
            if (count_resp) {
                send_json(conn_id, count_resp);
                free(count_resp);
            }
        } else {
            char *count_resp = protocol_serialize_count(sub, (unsigned long)total_count);
            if (count_resp) {
                send_json(conn_id, count_resp);
                free(count_resp);
            }
        }
    }

    log_debug("SUBSCRIPTION", "QUERY", "END sub=%s sent=%zu has_more=%d", sub, total_count, has_more);

    return true;
}

/* ============================================================================
 * SUBSCRIPTION_MANAGER.C - Subscription Lifecycle Implementation
 * ============================================================================ */

typedef struct subscription {
    connection_id_t connection_id;
    char *id;
    filter_t *filters;
    size_t filters_count;
    struct subscription *next;
} subscription_t;

struct subscription_manager {
    subscription_t *subscriptions;
    size_t max_subscriptions_per_connection;
    size_t max_filters_per_subscription;
    size_t max_subscription_id_length;
};

subscription_manager_t *subscription_manager_create(size_t max_subscriptions_per_connection,
                                                    size_t max_filters_per_subscription,
                                                    size_t max_subscription_id_length) {
    subscription_manager_t *manager = calloc(1, sizeof(*manager));
    if (!manager) return NULL;

    manager->subscriptions = NULL;
    manager->max_subscriptions_per_connection =
        max_subscriptions_per_connection ? max_subscriptions_per_connection : 20;
    manager->max_filters_per_subscription =
        max_filters_per_subscription ? max_filters_per_subscription : 10;
    manager->max_subscription_id_length =
        max_subscription_id_length ? max_subscription_id_length : 100;

    return manager;
}

void subscription_manager_destroy(subscription_manager_t *manager) {
    if (!manager) return;
    
    subscription_t *sub = manager->subscriptions;
    while (sub) {
        subscription_t *next = sub->next;
        for (size_t i = 0; i < sub->filters_count; i++) filter_release(&sub->filters[i]);
        free(sub->filters);
        free(sub->id);
        free(sub);
        sub = next;
    }
    
    free(manager);
}

bool subscription_manager_create_subscription(subscription_manager_t *manager,
                                              connection_id_t connection_id,
                                              const char *id,
                                              filter_t *filters,  /* TAKES OWNERSHIP on success */
                                              size_t filters_count) {
    if (!manager || !connection_id || !id || !filters || filters_count == 0) return false;
    if (strlen(id) > manager->max_subscription_id_length) return false;
    if (filters_count > manager->max_filters_per_subscription) return false;
    
    log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "ENTRY conn_id=%u sub=%s filters=%zu filters_ptr=%p (caller owns)", 
            (unsigned)connection_id, id, filters_count, (void*)filters);
    
    /* Count existing subscriptions for this connection */
    size_t count = 0;
    for (subscription_t *s = manager->subscriptions; s; s = s->next) {
        if (s->connection_id == connection_id) count++;
    }
    log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "existing subscriptions for conn_id=%u: %zu", 
            (unsigned)connection_id, count);
    if (count >= manager->max_subscriptions_per_connection) {
        log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "EXIT early (too many), caller retains ownership of filters");
        return false;
    }
    
    /* Remove any existing subscription with same ID for this connection */
    subscription_t **link = &manager->subscriptions;
    while (*link) {
        subscription_t *sub = *link;
        if (sub->connection_id == connection_id && strcmp(sub->id, id) == 0) {
            log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "removing existing sub=%s for conn_id=%u", 
                    id, (unsigned)connection_id);
            *link = sub->next;
            for (size_t i = 0; i < sub->filters_count; i++) filter_release(&sub->filters[i]);
            free(sub->filters);
            free(sub->id);
            free(sub);
            break;
        } else {
            link = &sub->next;
        }
    }
    
    subscription_t *subscription = calloc(1, sizeof(*subscription));
    if (!subscription) {
        log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "EXIT (OOM), caller retains ownership of filters");
        return false;
    }
    
    subscription->id = strdup(id);
    if (!subscription->id) {
        free(subscription);
        log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "EXIT (strdup failed), caller retains ownership of filters");
        return false;
    }
    
    /* TRANSFER OWNERSHIP: subscription now owns filters */
    subscription->connection_id = connection_id;
    subscription->filters = filters;
    subscription->filters_count = filters_count;
    subscription->next = manager->subscriptions;
    manager->subscriptions = subscription;
    
    log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "SUCCESS - ownership TRANSFERRED to subscription_manager, filters_ptr=%p", (void*)filters);
    log_debug("SUBSCRIPTION", "CREATE_SUBSCRIPTION", "created sub=%s for conn_id=%u (total now %zu)", 
            id, (unsigned)connection_id, count + 1);
    
    return true;
}

void subscription_manager_close_subscription(subscription_manager_t *manager,
                                             connection_id_t connection_id,
                                             const char *id) {
    if (!manager || !connection_id || !id) return;
    
    log_sub_debug(connection_id, id, "CLOSE_SUBSCRIPTION", "ENTRY");
    
    subscription_t **link = &manager->subscriptions;
    while (*link) {
        subscription_t *sub = *link;
        if (sub->connection_id == connection_id && strcmp(sub->id, id) == 0) {
            *link = sub->next;
            log_sub_debug(connection_id, id, "CLOSE_SUBSCRIPTION", "FREEING filters (subscription_manager owned them)");
            for (size_t i = 0; i < sub->filters_count; i++) filter_release(&sub->filters[i]);
            free(sub->filters);
            free(sub->id);
            free(sub);
            log_sub_debug(connection_id, id, "CLOSE_SUBSCRIPTION", "removed sub=%s", id);
            break;
        } else {
            link = &sub->next;
        }
    }
}

void subscription_manager_remove_connection(subscription_manager_t *manager,
                                            connection_id_t connection_id) {
    if (!manager || !connection_id) return;
    
    log_debug("SUBSCRIPTION", "REMOVE_CONNECTION", "ENTRY conn_id=%u", (unsigned)connection_id);
    
    subscription_t **link = &manager->subscriptions;
    size_t removed = 0;
    while (*link) {
        subscription_t *sub = *link;
        if (sub->connection_id == connection_id) {
            *link = sub->next;
            log_sub_debug(connection_id, sub->id, "REMOVE_CONNECTION", "FREEING filters (subscription_manager owned them)");
            for (size_t i = 0; i < sub->filters_count; i++) filter_release(&sub->filters[i]);
            free(sub->filters);
            free(sub->id);
            free(sub);
            removed++;
        } else {
            link = &sub->next;
        }
    }
    
    log_debug("SUBSCRIPTION", "REMOVE_CONNECTION", "removed %zu subscriptions for conn_id=%u", removed, (unsigned)connection_id);
}

static bool matches_filter(const filter_t *filter, const event_t *event) {
    if (filter->since && event->created_at < filter->since) return false;
    if (filter->until && event->created_at > filter->until) return false;
    if (filter->ids_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->ids_count; i++) {
            if (strncmp(event->id, filter->ids[i], strlen(filter->ids[i])) == 0) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    if (filter->authors_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->authors_count; i++) {
            if (strncmp(event->pubkey, filter->authors[i], strlen(filter->authors[i])) == 0) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    if (filter->kinds_count) {
        bool matched = false;
        for (size_t i = 0; i < filter->kinds_count; i++) {
            if (event->kind == filter->kinds[i]) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    for (size_t i = 0; i < filter->tags_count; i++) {
        bool matched = false;
        tag_t *tag = &filter->tags[i];
        for (size_t j = 1; j < tag->count; j++) {
            if (event_tag_has_value(event, tag->elements[0], tag->elements[j])) {
                matched = true;
                break;
            }
        }
        if (!matched) return false;
    }
    if (filter->search && *filter->search &&
        !mg_str_contains(mg_str(event->content ? event->content : ""), filter->search)) return false;
    return true;
}

void subscription_manager_match_and_deliver(subscription_manager_t *manager,
                                            const event_t *event,
                                            bool (*can_deliver)(const event_t *, connection_id_t, void *),
                                            void *can_deliver_ctx,
                                            void (*send_event)(connection_id_t connection_id, const char *, const event_t *)) {
    if (!manager || !event || !send_event) return;
    
    log_event_debug(0, event->id, event->kind, "MATCH_AND_DELIVER", "event kind=%d id=%.16s...", 
            event->kind, event->id);
    
    size_t delivered = 0;
    for (subscription_t *sub = manager->subscriptions; sub; sub = sub->next) {
        bool matched = false;
        for (size_t i = 0; i < sub->filters_count; i++) {
            if (matches_filter(&sub->filters[i], event)) {
                matched = true;
                break;
            }
        }
        if (matched) {
            bool can_deliver_result = true;
            if (can_deliver) {
                can_deliver_result = can_deliver(event, sub->connection_id, can_deliver_ctx);
            }
            if (can_deliver_result) {
                /* Verify the connection still exists */
                connection_session_t *session = connection_session_get(sub->connection_id);
                if (session) {
                    log_sub_debug(sub->connection_id, sub->id, "MATCH_AND_DELIVER", "delivering to conn_id=%u sub=%s", 
                            (unsigned)sub->connection_id, sub->id);
                    send_event(sub->connection_id, sub->id, event);
                    delivered++;
                }
            }
        }
    }
    
    log_debug("SUBSCRIPTION", "MATCH_AND_DELIVER", "delivered to %zu connections", delivered);
}

/* NOTE: legacy query_sender/query_frame_passes_delivery pipeline deleted.
 * Stored results are materialized by query_with_new_api and verified with
 * matches_filter (same matcher as live delivery), not by re-parsing
 * ["EVENT", ...] frames. */

bool subscription_manager_query(subscription_manager_t *manager,
                                storage_context_t *storage,
                                connection_id_t connection_id,
                                const char *sub,
                                filter_t *filters,  /* BORROWED - caller retains ownership */
                                size_t filters_count,
                                bool do_count,
                                void (*send_json)(connection_id_t connection_id, const char *),
                                bool (*can_deliver)(const event_t *, connection_id_t, void *),
                                void *can_deliver_ctx,
                                char *(*build_eose)(const char *sub, bool has_more, bool auth_hint, void *ctx),
                                char *(*build_count)(const char *sub, unsigned long count, void *ctx),
                                bool (*needs_auth_hint)(const filter_t *filters,
                                                        size_t filters_count,
                                                        connection_id_t connection_id,
                                                        void *ctx),
                                void (*send_auth_challenge)(connection_id_t connection_id,
                                                            void *ctx),
                                bool (*authorize_query)(connection_id_t connection_id, filter_t *filters,
                                                        size_t filters_count, char *reason, size_t reason_size,
                                                        void *ctx),
                                void *authorize_query_ctx,
                                void *protocol_response_ctx,
                                char *out_reason, size_t out_reason_size) {
    log_debug("SUBSCRIPTION", "QUERY", "ENTRY sub=%s filters=%zu do_count=%d filters_ptr=%p (BORROWED)", 
              sub, filters_count, do_count, (void*)filters);
    
    /* Check query authorization before execution. Reason is propagated to
     * the caller so it can send CLOSED with the specific NIP-42 prefix
     * (auth-required: vs restricted:) instead of a generic message. */
    char reject_reason[256] = {0};
    if (authorize_query && !authorize_query(connection_id, filters, filters_count,
                                            reject_reason, sizeof(reject_reason),
                                            authorize_query_ctx)) {
        log_debug("SUBSCRIPTION", "QUERY", "REJECTED: %s", reject_reason);
        if (out_reason && out_reason_size > 0) {
            snprintf(out_reason, out_reason_size, "%s", reject_reason);
        }
        return false; /* Caller should send CLOSED with reject_reason */
    }
    
    return query_with_new_api(manager, storage, connection_id, sub, filters, filters_count,
                              do_count, send_json, can_deliver, can_deliver_ctx,
                              build_eose, build_count, needs_auth_hint,
                              send_auth_challenge, protocol_response_ctx);
}

size_t subscription_manager_count_for_connection(subscription_manager_t *manager,
                                                 connection_id_t connection_id) {
    if (!manager || !connection_id) return 0;
    
    size_t count = 0;
    for (subscription_t *s = manager->subscriptions; s; s = s->next) {
        if (s->connection_id == connection_id) count++;
    }
    return count;
}