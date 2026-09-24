#include "nip26.h"
#include "../storage.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <mongoose.h>
#include "nip_event.h"
#include "nip_plugin.h"
#ifndef NHR_DYNAMIC_MODULE
#include "../crypto.h"
#endif

static void (*nip26_hash_fn)(const uint8_t *, size_t, uint8_t[32]);
static bool (*nip26_verify_fn)(const char *, const char *, const uint8_t[32]);

void nip26_set_crypto_services(
    void (*hash_fn)(const uint8_t *, size_t, uint8_t[32]),
    bool (*verify_fn)(const char *, const char *, const uint8_t[32])) {
    nip26_hash_fn = hash_fn;
    nip26_verify_fn = verify_fn;
}
/* ============================================================================
 * NIP-26: Delegated Event Signing
 * 
 * Implementation of delegation verification. This module separates the
 * delegation-specific logic from general cryptographic operations.
 * ============================================================================ */

bool nip26_check_delegation(const event_t *ev, const char *delegator_pubkey,
                            const char *conditions, const char *delegation_sig) {
    if (!ev || !delegator_pubkey) return false;
    
    /* Check delegation conditions */
    if (conditions && strlen(conditions) > 0) {
        bool has_kind_condition = false;
        bool kind_matched = false;
        
        char cond_copy[512];
        strncpy(cond_copy, conditions, sizeof(cond_copy) - 1);
        cond_copy[sizeof(cond_copy) - 1] = '\0';
        
        char *saveptr = NULL;
        char *condition = strtok_r(cond_copy, "&", &saveptr);
        
        while (condition) {
            char *eq_pos = strchr(condition, '=');
            char *lt_pos = strchr(condition, '<');
            char *gt_pos = strchr(condition, '>');
            
            const char *op_str = NULL;
            char op_char = '\0';
            
            if (eq_pos) {
                op_char = '=';
                op_str = eq_pos + 1;
            } else if (lt_pos) {
                op_char = '<';
                op_str = lt_pos + 1;
            } else if (gt_pos) {
                op_char = '>';
                op_str = gt_pos + 1;
            }
            
            if (op_char) {
                size_t key_len = (op_char == '=') ? (eq_pos - condition) :
                                 (op_char == '<') ? (lt_pos - condition) :
                                 (gt_pos - condition);
                
                if (key_len == 4 && strncmp(condition, "kind", 4) == 0 && op_char == '=') {
                    has_kind_condition = true;
                    char kind_str[16];
                    snprintf(kind_str, sizeof(kind_str), "%d", ev->kind);
                    
                    if (strcmp(kind_str, op_str) == 0) {
                        kind_matched = true;
                    }
                } else if (key_len == 10 && strncmp(condition, "created_at", 10) == 0) {
                    time_t timestamp = (time_t)strtol(op_str, NULL, 10);
                    
                    if (op_char == '<' && ev->created_at >= timestamp) {
                        return false;
                    } else if (op_char == '>' && ev->created_at <= timestamp) {
                        return false;
                    }
                }
            }
            
            condition = strtok_r(NULL, "&", &saveptr);
        }
        
        if (has_kind_condition && !kind_matched) {
            return false;
        }
    }
    
    /* Verify delegation signature */
    char delegation_str[512];
    int written = snprintf(delegation_str, sizeof(delegation_str),
                          "nostr:delegation:%s:%s",
                          ev->pubkey, conditions ? conditions : "");
    
    if (written < 0 || written >= (int)sizeof(delegation_str)) {
        return false;
    }
    
    uint8_t delegation_digest[32];
    if (nip26_hash_fn && nip26_verify_fn) {
        nip26_hash_fn((const uint8_t *)delegation_str, strlen(delegation_str),
                      delegation_digest);
        return nip26_verify_fn(delegation_sig, delegator_pubkey,
                               delegation_digest);
    }
#ifndef NHR_DYNAMIC_MODULE
    sha256((const uint8_t *)delegation_str, strlen(delegation_str), delegation_digest);
    return signature_verify(delegation_sig, delegator_pubkey, delegation_digest);
#else
    return false;
#endif
}

bool nip26_extract_index_tags(const event_t *event,
                              storage_tag_match_t **matches, size_t *count) {
    struct mg_str key, tag, tags;
    size_t offset = 0;
    if (!event || !matches || !count) return false;
    *matches = NULL;
    *count = 0;
    tags = mg_str(event->tags_json ? event->tags_json : "[]");
    while ((offset = mg_json_next(tags, offset, &key, &tag)) != 0) {
        char *name = nip_tag_element(tag, 0);
        if (name && strcmp(name, "delegation") == 0) {
            char *delegator = nip_tag_element(tag, 1);
            if (delegator) {
                storage_tag_match_t *grown = (storage_tag_match_t *)realloc(
                    *matches, (*count + 1) * sizeof(**matches));
                if (!grown) {
                    free(name);
                    free(delegator);
                    nip26_free_index_tags(*matches, *count);
                    *matches = NULL;
                    *count = 0;
                    return false;
                }
                *matches = grown;
                (*matches)[*count].tag_name = name;
                (*matches)[*count].tag_value = delegator;
                (*count)++;
                name = NULL;
            }
        }
        free(name);
    }
    return true;
}


void nip26_free_index_tags(storage_tag_match_t *matches, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free((void *)matches[i].tag_name);
        free((void *)matches[i].tag_value);
    }
    free(matches);
}

bool nip26_query_index_tags(const filter_t *filters, size_t filters_count,
                            storage_tag_match_t **matches, size_t *count) {
    if (!matches || !count) return false;
    *matches = NULL;
    *count = 0;
    for (size_t f = 0; filters && f < filters_count; f++) {
        for (size_t a = 0; a < filters[f].authors_count; a++) {
            const char *author = filters[f].authors[a];
            if (!author || strlen(author) != MAX_PUBKEY_SIZE) continue;
            storage_tag_match_t *grown = (storage_tag_match_t *)realloc(
                *matches, (*count + 1) * sizeof(**matches));
            if (!grown) {
                nip26_free_index_tags(*matches, *count);
                *matches = NULL;
                *count = 0;
                return false;
            }
            *matches = grown;
            (*matches)[*count].tag_name = string_dup("delegation");
            (*matches)[*count].tag_value = string_dup(author);
            (*matches)[*count].filter_index = f;
            if (!(*matches)[*count].tag_name || !(*matches)[*count].tag_value) {
                free((void *)(*matches)[*count].tag_name);
                free((void *)(*matches)[*count].tag_value);
                nip26_free_index_tags(*matches, *count);
                *matches = NULL;
                *count = 0;
                return false;
            }
            (*count)++;
        }
    }
    return true;
}

