/*
 * Example: Using the cagliostr library to create and validate Nostr events
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cagliostr.h"
#include "storage.h"
#include "crypto.h"

/* Forward declaration */
static void record_sender_cb(const char *json_event);

/* Example: Create and store a simple event */
void example_create_event(storage_context_t *storage) {
    printf("=== Example: Create Event ===\n");
    
    event_t *event = event_alloc();
    if (!event) {
        fprintf(stderr, "Failed to allocate event\n");
        return;
    }
    
    /* Set event fields */
    strncpy(event->id, "abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234", MAX_ID_SIZE);
    strncpy(event->pubkey, "1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234abcd", MAX_PUBKEY_SIZE);
    event->created_at = time(NULL);
    event->kind = 1;  /* Short text note */
    
    /* Set tags (as JSON) */
    event->tags_json = string_dup("[[\"t\",\"nostr\"],[\"t\",\"relay\"]]");
    event->tags_json_len = strlen(event->tags_json);
    
    /* Set content */
    event->content = string_dup("Hello from cagliostr!");
    event->content_len = strlen(event->content);
    
    /* Set signature */
    strncpy(event->sig, "1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd", MAX_SIG_SIZE);
    
    /* Store the event */
    if (storage->insert_record(event)) {
        printf("✓ Event stored successfully\n");
    } else {
        fprintf(stderr, "✗ Failed to store event\n");
    }
    
    event_free(event);
}

/* Example: Query events with filter */
void example_query_events(storage_context_t *storage) {
    printf("\n=== Example: Query Events ===\n");
    
    filter_t *filter = filter_alloc();
    if (!filter) {
        fprintf(stderr, "Failed to allocate filter\n");
        return;
    }
    
    /* Set filter criteria */
    filter->kinds = (int *)malloc(sizeof(int));
    filter->kinds[0] = 1;
    filter->kinds_count = 1;
    
    filter->limit = 10;
    filter->since = time(NULL) - 86400;  /* Last 24 hours */
    
    /* Query events */
    bool has_more = false;
    printf("Querying for kind 1 events...\n");
    if (storage->send_records(record_sender_cb, "sub1", filter, 1, false, &has_more)) {
        printf("✓ Query executed\n");
        if (has_more) {
            printf("  Note: More events available than returned\n");
        }
    } else {
        fprintf(stderr, "✗ Query failed\n");
    }
    
    filter_free(filter);
}

/* Callback for send_records */
static void record_sender_cb(const char *json_event) {
    if (json_event) {
        printf("Event: %s\n", json_event);
    }
}

/* Example: Verify cryptographic operations */
void example_crypto(void) {
    printf("\n=== Example: Cryptographic Operations ===\n");
    
    if (!crypto_init()) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return;
    }
    
    /* Example hex-to-bytes conversion */
    const char *hex_str = "abcd1234";
    uint8_t bytes[4];
    size_t out_len = 0;
    
    if (hex_to_bytes(hex_str, strlen(hex_str), bytes, sizeof(bytes), &out_len)) {
        printf("✓ Hex to bytes conversion successful: %zu bytes\n", out_len);
    } else {
        fprintf(stderr, "✗ Hex to bytes conversion failed\n");
    }
    
    /* Example bytes-to-hex conversion */
    uint8_t test_bytes[] = {0xAB, 0xCD, 0x12, 0x34};
    char *hex_result = bytes_to_hex(test_bytes, sizeof(test_bytes));
    if (hex_result) {
        printf("✓ Bytes to hex conversion: %s\n", hex_result);
        free(hex_result);
    }
    
    /* Example SHA256 */
    const char *msg = "hello world";
    uint8_t digest[32];
    sha256((const uint8_t *)msg, strlen(msg), digest);
    
    char *hash_hex = bytes_to_hex(digest, 32);
    if (hash_hex) {
        printf("✓ SHA256('hello world'): %s\n", hash_hex);
        free(hash_hex);
    }
    
    crypto_deinit();
}

/* Example: Database initialization */
void example_database_init(void) {
    printf("\n=== Example: Database Initialization ===\n");
    
    storage_context_t storage = {0};
    storage_context_init_sqlite3(&storage);
    
    if (!storage.init) {
        fprintf(stderr, "Failed to initialize storage context\n");
        return;
    }
    
    /* Initialize in-memory database */
    if (storage.init("file::memory:?cache=shared")) {
        printf("✓ Database initialized in memory\n");
    } else {
        fprintf(stderr, "✗ Database initialization failed\n");
        return;
    }
    
    /* Now use the storage context */
    example_create_event(&storage);
    example_query_events(&storage);
    
    if (storage.deinit) {
        storage.deinit();
        printf("✓ Database closed\n");
    }
}

/* Main example runner */
int main(int argc, char **argv) {
    printf("Cagliostr C99 Library Examples\n");
    printf("================================\n\n");
    
    /* Run examples */
    example_database_init();
    example_crypto();
    
    printf("\n================================\n");
    printf("Examples completed successfully!\n");
    
    return 0;
}
