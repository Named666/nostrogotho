#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "nip42.h"
#include "nip_event.h"

typedef struct nip42_client {
    struct mg_connection *connection;
    char challenge[17];
    char pubkey[MAX_PUBKEY_SIZE + 1];
    struct nip42_client *next;
} nip42_client_t;

static nip42_client_t *clients;

static nip42_client_t *find_client(struct mg_connection *connection) {
    for (nip42_client_t *client = clients; client; client = client->next) {
        if (client->connection == connection) return client;
    }
    return NULL;
}

bool nip42_open(struct mg_connection *connection, char challenge[17]) {
    unsigned char random[8];
    nip42_client_t *client = calloc(1, sizeof(*client));
    if (!client || BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        free(client);
        return false;
    }
    client->connection = connection;
    for (size_t index = 0; index < sizeof(random); index++) {
        snprintf(client->challenge + index * 2, 3, "%02x", random[index]);
    }
    memcpy(challenge, client->challenge, sizeof(client->challenge));
    client->next = clients;
    clients = client;
    return true;
}

void nip42_close(struct mg_connection *connection) {
    nip42_client_t **link = &clients;
    while (*link) {
        if ((*link)->connection == connection) {
            nip42_client_t *client = *link;
            *link = client->next;
            free(client);
            return;
        }
        link = &(*link)->next;
    }
}

const char *nip42_authenticated_pubkey(struct mg_connection *connection) {
    nip42_client_t *client = find_client(connection);
    return client && client->pubkey[0] ? client->pubkey : NULL;
}

bool nip42_authenticate(struct mg_connection *connection, const event_t *event,
                        const char *service_url, time_t now) {
    nip42_client_t *client = find_client(connection);
    if (!client || event->kind != 22242 || !check_event(event) ||
        llabs((long long) now - (long long) event->created_at) > 600 ||
        !nip_event_has_tag(event, "challenge", client->challenge) ||
        !nip_event_has_relay_tag(event, service_url)) return false;
    strcpy(client->pubkey, event->pubkey);
    return true;
}