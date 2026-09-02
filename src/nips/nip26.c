#include "nip26.h"
#include "../crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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
    sha256((const uint8_t *)delegation_str, strlen(delegation_str), delegation_digest);
    
    return signature_verify(delegation_sig, delegator_pubkey, delegation_digest);
}


