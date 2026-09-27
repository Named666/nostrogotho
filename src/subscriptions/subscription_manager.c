#include "subscription_manager.h"
#include "nostrogotho.h"
#include "storage.h"
#include "json_util.h"
#include "model/event_util.h"
#include "nips/nip_capability.h"
#include "protocol/protocol.h"
#include <mongoose.h>
#include <stdlib.h>
#include <string.h>

/* mg_str_contains() is shared from json_util.h. */

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
            if (event_has_tag(event, tag->elements[0], tag->elements[j])) {
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
                                            void (*send_event)(struct mg_connection *, const char *, const event_t *),
                                            void *send_ctx) {
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

struct query_context {
    struct mg_connection *connection;
    const char *sub;
    const filter_t *query_filters;
    size_t query_filters_count;
    bool do_count;
    void (*send_json)(struct mg_connection *, const char *);
    void *send_ctx;
    bool (*can_deliver)(const event_t *, connection_id_t, void *);
    void *can_deliver_ctx;
    char *(*build_eose)(const char *sub, bool has_more, bool auth_hint);
    char *(*build_count)(const char *sub, unsigned long count);
    bool (*needs_auth_hint)(const filter_t *, size_t, connection_id_t, void *);
    void (*send_auth_challenge)(connection_id_t, void *);
    void *protocol_response_ctx;
    bool has_more;
    int total_count;
    connection_id_t connection_id;
};

/* Global context for query callback (single-threaded) */
static struct query_context *g_query_context = NULL;

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
                                void *send_ctx,
                                bool (*can_deliver)(const event_t *, connection_id_t, void *),
                                void *can_deliver_ctx,
                                char *(*build_eose)(const char *sub, bool has_more, bool auth_hint),
                                char *(*build_count)(const char *sub, unsigned long count),
                                bool (*needs_auth_hint)(const filter_t *filters,
                                                        size_t filters_count,
                                                        connection_id_t connection_id,
                                                        void *ctx),
                                void (*send_auth_challenge)(connection_id_t connection_id,
                                                            void *ctx),
                                void *protocol_response_ctx) {
    if (!manager || !storage || !connection || !sub || !filters || filters_count == 0 || !send_json) return false;

    /* Resolve the connection ID from the live session (works for REQ and
     * for COUNT, which owns no subscription). */
    connection_session_t *session = connection_session_get_by_mg_connection(connection);
    connection_id_t conn_id = session ? connection_session_get_id(session) : 0;

    struct query_context ctx = {
        .connection = connection,
        .sub = sub,
        .query_filters = filters,
        .query_filters_count = filters_count,
        .do_count = do_count,
        .send_json = send_json,
        .send_ctx = send_ctx,
        .can_deliver = can_deliver,
        .can_deliver_ctx = can_deliver_ctx,
        .build_eose = build_eose,
        .build_count = build_count,
        .needs_auth_hint = needs_auth_hint,
        .send_auth_challenge = send_auth_challenge,
        .protocol_response_ctx = protocol_response_ctx,
        .has_more = false,
        .total_count = 0,
        .connection_id = conn_id
    };
    
    /* Use storage to query events */
    bool success = storage->send_records(query_sender, sub, filters, filters_count,
                                         do_count, &ctx.has_more, &ctx.total_count,
                                         NULL, 0, &ctx);
    
    if (!success) {
        return false;
    }
    
    /* Send EOSE for REQ or COUNT response for COUNT */
    if (!do_count) {
        /* For REQ, send EOSE with completeness/auth hints. A fresh AUTH
         * challenge goes out before EOSE when a provider requests it. */
        bool auth_hint = false;
        if (ctx.needs_auth_hint) {
            auth_hint = ctx.needs_auth_hint(filters, filters_count,
                                            ctx.connection_id,
                                            ctx.protocol_response_ctx);
            if (auth_hint && ctx.send_auth_challenge) {
                ctx.send_auth_challenge(ctx.connection_id,
                                        ctx.protocol_response_ctx);
            }
        }
        if (ctx.build_eose) {
            char *eose = ctx.build_eose(sub, ctx.has_more, auth_hint);
            if (eose) {
                ctx.send_json(connection, eose);
                free(eose);
            }
        } else {
            /* Fallback to default EOSE */
            char *eose = protocol_serialize_eose(sub, ctx.has_more, auth_hint);
            if (eose) {
                ctx.send_json(connection, eose);
                free(eose);
            }
        }
    } else {
        /* For COUNT, send COUNT response */
        if (ctx.build_count) {
            char *count_resp = ctx.build_count(sub, (unsigned long)ctx.total_count);
            if (count_resp) {
                ctx.send_json(connection, count_resp);
                free(count_resp);
            }
        } else {
            /* Fallback to default COUNT */
            char *count_resp = protocol_serialize_count(sub, (unsigned long)ctx.total_count);
            if (count_resp) {
                ctx.send_json(connection, count_resp);
                free(count_resp);
            }
        }
    }
    
    return true;
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