#ifndef SUBSCRIPTION_MANAGER_H_
#define SUBSCRIPTION_MANAGER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "nostrogotho.h"
#include "relay/connection_session.h"
#include "storage.h"

/* ============================================================================
 * SUBSCRIPTION_MANAGER.H - Subscription Lifecycle Management
 * 
 * Extracts subscription management from server.c into a dedicated module.
 * Handles connection association, subscription lifecycle, filter matching,
 * and delivery coordination.
 * 
 * OWNERSHIP MODEL:
 * - subscription_manager_t owns all subscription_t and their filters
 * - subscription_manager_create_subscription() TAKES ownership of filters on success
 *   (caller must NULL its pointer after successful call)
 * - subscription_manager_create_subscription() does NOT take ownership on failure
 * - subscription_manager_query() BORROWS filters (caller retains ownership)
 * - subscription_manager_match_and_deliver() BORROWS event (caller retains ownership)
 * - subscription_manager_destroy() frees all owned subscriptions and filters
 * ============================================================================ */

typedef struct subscription_manager subscription_manager_t;

/* Create and initialize a new subscription manager. Limits come from
 * relay_config_t (single source of truth); 0 keeps the built-in default. */
subscription_manager_t *subscription_manager_create(size_t max_subscriptions_per_connection,
                                                    size_t max_filters_per_subscription,
                                                    size_t max_subscription_id_length);

/* Destroy and free subscription manager and all owned subscriptions/filters */
void subscription_manager_destroy(subscription_manager_t *manager);

/* Create a new subscription for a connection
 * TAKES OWNERSHIP of filters array and all filter contents on success
 * Returns false if ownership NOT taken (caller must free filters)
 * On success, caller MUST NULL its filters pointer to prevent double-free */
bool subscription_manager_create_subscription(subscription_manager_t *manager,
                                              connection_id_t connection_id,
                                              const char *id,
                                              filter_t *filters,  /* TAKES OWNERSHIP on success */
                                              size_t filters_count);

/* Close a specific subscription by ID - frees owned filters */
void subscription_manager_close_subscription(subscription_manager_t *manager,
                                             connection_id_t connection_id,
                                             const char *id);

/* Remove all subscriptions for a connection (on disconnect) - frees owned filters */
void subscription_manager_remove_connection(subscription_manager_t *manager,
                                            connection_id_t connection_id);

/* Check if an event matches any subscription filters and deliver if so
 * BORROWS event - does NOT take ownership */
void subscription_manager_match_and_deliver(subscription_manager_t *manager,
                                            const event_t *event,  /* BORROWED */
                                            bool (*can_deliver)(const event_t *, connection_id_t, void *),
                                            void *can_deliver_ctx,
                                            void (*send_event)(connection_id_t connection_id, const char *, const event_t *));

/* Execute a stored query for a subscription.
 * BORROWS filters - caller retains ownership.
 * Stored results pass through the SAME pipeline as live broadcasts: the
 * shared filter matcher decides candidacy and the composed NIP delivery
 * policy may veto each event. needs_auth_hint/send_auth_challenge (with
 * protocol_response_ctx) implement the NIP-17/NIP-67 "auth" EOSE hint for
 * gift-wrap queries on unauthenticated connections.
 * 
 * authorize_query: called before query execution. If returns false, the query
 * is rejected. The reason buffer will be filled with the rejection message
 * (e.g., "auth-required: ..." or "restricted: ...") for sending a CLOSED message.
 * Returns true to proceed, false to reject (caller should send CLOSED). */
bool subscription_manager_query(subscription_manager_t *manager,
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
                                bool (*authorize_query)(connection_id_t connection_id, filter_t *filters,
                                                        size_t filters_count, char *reason, size_t reason_size,
                                                        void *ctx),
                                void *authorize_query_ctx,
                                void *protocol_response_ctx,
                                char *out_reason, size_t out_reason_size);

/* Get subscription count for a connection */
size_t subscription_manager_count_for_connection(subscription_manager_t *manager,
                                                 connection_id_t connection_id);

#endif /* SUBSCRIPTION_MANAGER_H_ */