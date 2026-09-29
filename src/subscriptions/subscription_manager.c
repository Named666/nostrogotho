#include "subscription_manager.h"
#include "nostrogotho.h"
#include "storage.h"
#include "json_util.h"
#include "model/tag_iter.h"
#include "model/event_tags.h"
#include "nips/nip_capability.h"
#include "protocol/protocol.h"
#include <mongoose.h>
#include <stdlib.h>
#include <string.h>

/* mg_str_contains() is shared from json_util.h. */

/* Forward declaration */
struct query_context;

/* ============================================================================
 * New Query Implementation using Unified Storage API (NOSTR_EVENT_STORAGE_SPEC.md)
 * ============================================================================ */

/* Convert filter_t to storage_event_scope_t */
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

/* Query context structure - forward declared above */
struct query_context {
    struct mg_connection *connection;
    const char *sub;
    const filter_t *query_filters;
    size_t query_filters_count;
    bool do_count;
    void (*send_json)(struct mg_connection *, const char *);
    bool (*can_deliver)(const event_t *, connection_id_t, void *);
    void *can_deliver_ctx;
    char *(*build_eose)(const char *sub, bool has_more, bool auth_hint, void *ctx);
    char *(*build_count)(const char *sub, unsigned long count, void *ctx);
    bool (*needs_auth_hint)(const filter_t *, size_t, connection_id_t, void *);
    void (*send_auth_challenge)(connection_id_t, void *);
    void *protocol_response_ctx;
    bool has_more;
    int total_count;
    connection_id_t connection_id;
};

/* Query using new unified storage API */
static bool query_with_new_api(subscription_manager_t *manager,
                               storage_context_t *storage,
                               struct mg_connection *connection,
                               const char *sub,
                               filter_t *filters,
                               size_t filters_count,
                               bool do_count,
                               void (*send_json)(struct mg_connection *, const char *),
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
    if (!manager || !storage || !connection || !sub || !filters || filters_count == 0 || !send_json) return false;

    /* Resolve the connection ID from the live session */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;

    bool success = true;
    size_t total_count = 0;
    bool has_more = false;

    if (do_count) {
        /* COUNT: sum counts from each filter (OR semantics) */
        for (size_t f = 0; f < filters_count; f++) {
            storage_event_scope_t scope = {0};
            filter_to_scope(&filters[f], &scope);
            
            size_t count = 0;
            if (storage_count_events(&scope, &count)) {
                total_count += count;
            }
            free_scope_tags(&scope);
        }
    } else {
        /* REQ: find events for each filter (OR semantics) */
        int limit = 500;
        if (filters[0].limit > 0 && filters[0].limit < limit) limit = filters[0].limit;
        
        int sent_count = 0;
        
        for (size_t f = 0; f < filters_count && !has_more; f++) {
            storage_event_scope_t scope = {0};
            filter_to_scope(&filters[f], &scope);
            
            /* Fetch limit+1 to detect has_more */
            scope.limit = limit + 1;
            
            event_t **events = NULL;
            size_t count = 0;
            if (storage_find_events(&scope, &events, &count)) {
                for (size_t i = 0; i < count && !has_more; i++) {
                    if (sent_count >= limit) {
                        has_more = true;
                        break;
                    }
                    
                    /* Check delivery policy */
                    bool allowed = true;
                    if (can_deliver) {
                        allowed = can_deliver(events[i], conn_id, can_deliver_ctx);
                    }
                    
                    if (allowed) {
                        /* Build JSON event and send */
                        json_builder_t builder;
                        json_builder_start(&builder);
                        json_builder_append_string(&builder, "EVENT");
                        json_builder_append_string(&builder, sub);
                        json_serialize_event(events[i], &builder);
                        send_json(connection, json_builder_finish(&builder));
                        sent_count++;
                    }
                    event_free(events[i]);
                }
                free(events);
            }
            free_scope_tags(&scope);
        }
        has_more = has_more;
        total_count = sent_count;
    }

    if (!success) {
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
                send_json(connection, eose);
                free(eose);
            }
        } else {
            char *eose = protocol_serialize_eose(sub, has_more, auth_hint);
            if (eose) {
                send_json(connection, eose);
                free(eose);
            }
        }
    } else {
        if (build_count) {
            char *count_resp = build_count(sub, (unsigned long)total_count, protocol_response_ctx);
            if (count_resp) {
                send_json(connection, count_resp);
                free(count_resp);
            }
        } else {
            char *count_resp = protocol_serialize_count(sub, (unsigned long)total_count);
            if (count_resp) {
                send_json(connection, count_resp);
                free(count_resp);
            }
        }
    }

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
                                              filter_t *filters,
                                              size_t filters_count) {
    if (!manager || !connection_id || !id || !filters || filters_count == 0) return false;
    if (strlen(id) > manager->max_subscription_id_length) return false;
    if (filters_count > manager->max_filters_per_subscription) return false;
    
    /* Count existing subscriptions for this connection */
    size_t count = 0;
    for (subscription_t *s = manager->subscriptions; s; s = s->next) {
        if (s->connection_id == connection_id) count++;
    }
    if (count >= manager->max_subscriptions_per_connection) return false;
    
    /* Remove any existing subscription with same ID for this connection */
    subscription_t **link = &manager->subscriptions;
    while (*link) {
        subscription_t *sub = *link;
        if (sub->connection_id == connection_id && strcmp(sub->id, id) == 0) {
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
    if (!subscription) return false;
    
    subscription->id = strdup(id);
    if (!subscription->id) {
        free(subscription);
        return false;
    }
    
    subscription->connection_id = connection_id;
    subscription->filters = filters;
    subscription->filters_count = filters_count;
    subscription->next = manager->subscriptions;
    manager->subscriptions = subscription;
    
    return true;
}

void subscription_manager_close_subscription(subscription_manager_t *manager,
                                             connection_id_t connection_id,
                                             const char *id) {
    if (!manager || !connection_id || !id) return;
    
    subscription_t **link = &manager->subscriptions;
    while (*link) {
        subscription_t *sub = *link;
        if (sub->connection_id == connection_id && strcmp(sub->id, id) == 0) {
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
}

void subscription_manager_remove_connection(subscription_manager_t *manager,
                                            connection_id_t connection_id) {
    if (!manager || !connection_id) return;
    
    subscription_t **link = &manager->subscriptions;
    while (*link) {
        subscription_t *sub = *link;
        if (sub->connection_id == connection_id) {
            *link = sub->next;
            for (size_t i = 0; i < sub->filters_count; i++) filter_release(&sub->filters[i]);
            free(sub->filters);
            free(sub->id);
            free(sub);
        } else {
            link = &sub->next;
        }
    }
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
                                            void (*send_event)(struct mg_connection *, const char *, const event_t *)) {
    if (!manager || !event || !send_event) return;
    
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
                /* Get the Mongoose connection from the connection session */
                connection_session_t *session = connection_session_get(sub->connection_id);
                struct mg_connection *conn = session ? connection_session_get_mg_connection(session) : NULL;
                if (conn) {
                    send_event(conn, sub->id, event);
                }
            }
        }
    }
}

/* Shared delivery pipeline for stored results: parse the stored
 * ["EVENT", sub, {...}] frame once, apply the same matcher and the same
 * composed delivery policy used for live broadcasts, and forward only
 * events that survive both. Non-EVENT frames (e.g. COUNT) pass through. */
static bool query_frame_passes_delivery(struct query_context *ctx,
                                        const char *json_event) {
    json_value_t values[4] = {{0}};
    size_t count = json_array_parse(json_event, values, 4);
    const char *method = json_array_get_string(values, count, 0);
    bool deliver = true;

    if (method && strcmp(method, "EVENT") == 0 && count == 3 &&
        values[2].type == JSON_TYPE_OBJECT && values[2].value.string_val) {
        event_t event;
        if (json_parse_event(values[2].value.string_val, &event)) {
            bool matched = (ctx->query_filters_count == 0);
            for (size_t i = 0; !matched && i < ctx->query_filters_count; i++) {
                matched = matches_filter(&ctx->query_filters[i], &event);
            }
            bool allowed = true;
            if (ctx->can_deliver) {
                allowed = ctx->can_deliver(&event, ctx->connection_id,
                                           ctx->can_deliver_ctx);
            }
            deliver = matched && allowed;
            event_release(&event);
        }
    }
    json_array_free(values, count);
    return deliver;
}

static void query_sender(const char *json_event, void *userdata) {
    struct query_context *ctx = (struct query_context *)userdata;
    if (!ctx || !ctx->send_json || !ctx->connection) return;

    if (!query_frame_passes_delivery(ctx, json_event)) return;
    ctx->send_json(ctx->connection, json_event);
}

bool subscription_manager_query(subscription_manager_t *manager,
                                storage_context_t *storage,
                                struct mg_connection *connection,
                                const char *sub,
                                filter_t *filters,
                                size_t filters_count,
                                bool do_count,
                                void (*send_json)(struct mg_connection *, const char *),
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
    return query_with_new_api(manager, storage, connection, sub, filters, filters_count,
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