#include "connection_session.h"
#include <mongoose.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * CONNECTION_SESSION.C - Connection/Session Implementation
 * ============================================================================ */

struct connection_session {
    uintptr_t connection_id;
    struct mg_connection *mg_connection;
    auth_state_t auth_state;
    char **auth_pubkeys;
    size_t auth_pubkeys_count;
    char *challenge;
    void *protocol_state;
    struct connection_session *next;
};

static connection_session_t *sessions = NULL;

connection_id_t connection_session_create(uintptr_t connection_id,
                                          struct mg_connection *connection) {
    connection_session_t *session = calloc(1, sizeof(*session));
    if (!session) return 0;
    
    session->connection_id = connection_id;
    session->mg_connection = connection;
    session->auth_state = AUTH_STATE_NONE;
    session->auth_pubkeys = NULL;
    session->auth_pubkeys_count = 0;
    session->challenge = NULL;
    session->protocol_state = NULL;
    session->next = sessions;
    sessions = session;
    
    return connection_id;
}

void connection_session_destroy(connection_session_t *session) {
    if (!session) return;
    
    /* Remove from list */
    connection_session_t **link = &sessions;
    while (*link) {
        if (*link == session) {
            *link = session->next;
            break;
        }
        link = &(*link)->next;
    }
    
    for (size_t i = 0; i < session->auth_pubkeys_count; i++) {
        free(session->auth_pubkeys[i]);
    }
    free(session->auth_pubkeys);
    free(session->challenge);
    free(session);
}

connection_session_t *connection_session_get(uintptr_t connection_id) {
    for (connection_session_t *s = sessions; s; s = s->next) {
        if (s->connection_id == connection_id) return s;
    }
    return NULL;
}

connection_session_t *connection_session_get_by_mg_connection(struct mg_connection *connection) {
    for (connection_session_t *s = sessions; s; s = s->next) {
        if (s->mg_connection == connection) return s;
    }
    return NULL;
}

void connection_session_set_auth(connection_session_t *session, const char *pubkey) {
    if (!session) return;
    
    /* Clear existing pubkeys */
    for (size_t i = 0; i < session->auth_pubkeys_count; i++) {
        free(session->auth_pubkeys[i]);
    }
    free(session->auth_pubkeys);
    
    if (pubkey) {
        session->auth_pubkeys = malloc(sizeof(char *));
        if (session->auth_pubkeys) {
            session->auth_pubkeys[0] = strdup(pubkey);
            session->auth_pubkeys_count = 1;
        }
        session->auth_state = AUTH_STATE_AUTHENTICATED;
    } else {
        session->auth_pubkeys = NULL;
        session->auth_pubkeys_count = 0;
        session->auth_state = AUTH_STATE_NONE;
    }
}

const char *connection_session_get_auth_pubkey(connection_session_t *session) {
    return (session && session->auth_pubkeys_count > 0) ? session->auth_pubkeys[0] : NULL;
}

/* Add an authenticated pubkey (supports multiple per NIP-42) */
void connection_session_add_auth_pubkey(connection_session_t *session, const char *pubkey) {
    if (!session || !pubkey) return;
    
    /* Dedupe: repeated AUTH from the same pubkey must not grow the list
     * unbounded (resource exhaustion via AUTH replay). */
    for (size_t i = 0; i < session->auth_pubkeys_count; i++) {
        if (session->auth_pubkeys[i] && strcmp(session->auth_pubkeys[i], pubkey) == 0) {
            session->auth_state = AUTH_STATE_AUTHENTICATED;
            return;
        }
    }

    char **new_pubkeys = realloc(session->auth_pubkeys,
                                  (session->auth_pubkeys_count + 1) * sizeof(char *));
    if (!new_pubkeys) return;
    
    session->auth_pubkeys = new_pubkeys;
    session->auth_pubkeys[session->auth_pubkeys_count] = strdup(pubkey);
    session->auth_pubkeys_count++;
    session->auth_state = AUTH_STATE_AUTHENTICATED;
}

/* Check if a pubkey is authenticated for this session */
bool connection_session_has_auth_pubkey(connection_session_t *session, const char *pubkey) {
    if (!session || !pubkey) return false;
    
    for (size_t i = 0; i < session->auth_pubkeys_count; i++) {
        if (session->auth_pubkeys[i] && strcmp(session->auth_pubkeys[i], pubkey) == 0) {
            return true;
        }
    }
    return false;
}

/* Get number of authenticated pubkeys */
size_t connection_session_get_auth_pubkey_count(connection_session_t *session) {
    return session ? session->auth_pubkeys_count : 0;
}

/* Get authenticated pubkey by index */
const char *connection_session_get_auth_pubkey_at(connection_session_t *session, size_t index) {
    if (!session || index >= session->auth_pubkeys_count) return NULL;
    return session->auth_pubkeys[index];
}

void connection_session_set_challenge(connection_session_t *session, const char *challenge) {
    if (!session) return;
    free(session->challenge);
    session->challenge = challenge ? strdup(challenge) : NULL;
    if (challenge) session->auth_state = AUTH_STATE_CHALLENGED;
}

const char *connection_session_get_challenge(connection_session_t *session) {
    return session ? session->challenge : NULL;
}

void connection_session_set_auth_state(connection_session_t *session, auth_state_t state) {
    if (session) session->auth_state = state;
}

auth_state_t connection_session_get_auth_state(connection_session_t *session) {
    return session ? session->auth_state : AUTH_STATE_NONE;
}

void connection_session_set_protocol_state(connection_session_t *session, void *state) {
    if (session) session->protocol_state = state;
}

void *connection_session_get_protocol_state(connection_session_t *session) {
    return session ? session->protocol_state : NULL;
}

uintptr_t connection_session_get_id(connection_session_t *session) {
    return session ? session->connection_id : 0;
}

struct mg_connection *connection_session_get_mg_connection(connection_session_t *session) {
    return session ? session->mg_connection : NULL;
}

void connection_session_iterate(connection_session_iter_fn fn, void *userdata) {
    if (!fn) return;
    for (connection_session_t *s = sessions; s; s = s->next) {
        fn(s, userdata);
    }
}

void connection_session_cleanup_all(void) {
    while (sessions) {
        connection_session_t *next = sessions->next;
        for (size_t i = 0; i < sessions->auth_pubkeys_count; i++) {
            free(sessions->auth_pubkeys[i]);
        }
        free(sessions->auth_pubkeys);
        free(sessions->challenge);
        free(sessions);
        sessions = next;
    }
}

size_t connection_session_snapshot(connection_snapshot_t *connections, size_t capacity) {
    size_t count = 0;
    for (connection_session_t *s = sessions; s && count < capacity; s = s->next) {
        connections[count].id = s->connection_id;
        connections[count].connection = s->mg_connection;
        count++;
    }
    return count;
}

bool connection_session_restore(const connection_snapshot_t *connections, size_t count) {
    for (size_t i = 0; i < count; i++) {
        struct mg_connection *conn = (struct mg_connection *)connections[i].connection;
        connection_session_t *existing = connection_session_get_by_mg_connection(conn);
        if (!existing) {
            connection_id_t id = connection_session_create(connections[i].id, conn);
            if (!id) return false;
        }
    }
    return true;
}