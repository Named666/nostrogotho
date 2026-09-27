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
    char *auth_pubkey;
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
    session->auth_pubkey = NULL;
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
    
    free(session->auth_pubkey);
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
    free(session->auth_pubkey);
    session->auth_pubkey = pubkey ? strdup(pubkey) : NULL;
    if (pubkey) session->auth_state = AUTH_STATE_AUTHENTICATED;
}

const char *connection_session_get_auth_pubkey(connection_session_t *session) {
    return session ? session->auth_pubkey : NULL;
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
        free(sessions->auth_pubkey);
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