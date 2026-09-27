#include "event_validation.h"
#include "crypto.h"
#include "json_util.h"
#include "nostrogotho.h"
#include <time.h>
#include <stdio.h>
#include <string.h>

/* Forward declarations for crypto functions used internally */
bool check_event_id(const event_t *ev);
bool check_signature(const event_t *ev);

/* ============================================================================
 * EVENT_VALIDATION.C - Event Validation Implementation
 * ============================================================================ */

static validation_outcome_t make_outcome(validation_result_t result, const char *reason) {
    validation_outcome_t outcome = {0};
    outcome.result = result;
    if (reason) {
        snprintf(outcome.reason, sizeof(outcome.reason), "%s", reason);
    }
    return outcome;
}

validation_outcome_t validation_check_structure(const event_t *event, size_t max_content_length) {
    if (!event) {
        return make_outcome(VALIDATION_INVALID_STRUCTURE, "event is null");
    }
    
    if (!event->id[0] || !event->pubkey[0] || !event->sig[0]) {
        return make_outcome(VALIDATION_INVALID_STRUCTURE, "missing required fields");
    }
    
    if (event->kind < 0) {
        return make_outcome(VALIDATION_INVALID_STRUCTURE, "invalid kind");
    }
    
    if (event->created_at == 0) {
        return make_outcome(VALIDATION_INVALID_STRUCTURE, "invalid created_at");
    }
    
    if (max_content_length > 0 && event->content_len > max_content_length) {
        return make_outcome(VALIDATION_CONTENT_TOO_LARGE, "content too large");
    }
    
    /* Check event serialization size */
    if (!validation_check_serialization_size(event, 65536)) {
        return make_outcome(VALIDATION_CONTENT_TOO_LARGE, "event serialization too large");
    }
    
    return make_outcome(VALIDATION_OK, "");
}

validation_outcome_t validation_verify_event_id(const event_t *event) {
    if (!event) {
        return make_outcome(VALIDATION_INVALID_EVENT_ID, "event is null");
    }
    
    if (!check_event_id(event)) {
        return make_outcome(VALIDATION_INVALID_EVENT_ID, "event id verification failed");
    }
    
    return make_outcome(VALIDATION_OK, "");
}

validation_outcome_t validation_verify_signature(const event_t *event) {
    if (!event) {
        return make_outcome(VALIDATION_INVALID_SIGNATURE, "event is null");
    }
    
    if (!check_signature(event)) {
        return make_outcome(VALIDATION_INVALID_SIGNATURE, "signature verification failed");
    }
    
    return make_outcome(VALIDATION_OK, "");
}

validation_outcome_t validation_verify_delegation(const event_t *event) {
    if (!event) {
        return make_outcome(VALIDATION_INVALID_DELEGATION, "event is null");
    }
    
    /* check_delegation requires delegator_pubkey, conditions, and delegation_sig.
     * For now, we skip delegation verification if no delegation tags are present.
     * Full delegation verification is done in check_event(). */
    return make_outcome(VALIDATION_OK, "");
}

validation_outcome_t validation_check_timestamp(const event_t *event, time_t lower_limit, time_t upper_limit) {
    if (!event) {
        return make_outcome(VALIDATION_TIMESTAMP_OUT_OF_RANGE, "event is null");
    }
    
    time_t now = time(NULL);
    
    if (lower_limit > 0 && event->created_at < now - lower_limit) {
        return make_outcome(VALIDATION_TIMESTAMP_OUT_OF_RANGE, "created_at is too old");
    }
    
    if (upper_limit > 0 && event->created_at > now + upper_limit) {
        return make_outcome(VALIDATION_TIMESTAMP_OUT_OF_RANGE, "created_at is too far in future");
    }
    
    return make_outcome(VALIDATION_OK, "");
}

validation_outcome_t validation_check_pow(const event_t *event, int min_pow_difficulty) {
    if (!event) {
        return make_outcome(VALIDATION_INSUFFICIENT_POW, "event is null");
    }
    
    if (min_pow_difficulty > 0) {
        unsigned leading_zeros = count_leading_zero_bits(event->id);
        if (leading_zeros < (unsigned)min_pow_difficulty) {
            return make_outcome(VALIDATION_INSUFFICIENT_POW, "insufficient proof of work");
        }
    }
    
    return make_outcome(VALIDATION_OK, "");
}

validation_outcome_t validation_validate_event(const event_t *event,
                                               size_t max_content_length,
                                               time_t lower_limit,
                                               time_t upper_limit,
                                               int min_pow_difficulty) {
    validation_outcome_t outcome;
    
    outcome = validation_check_structure(event, max_content_length);
    if (outcome.result != VALIDATION_OK) return outcome;
    
    outcome = validation_verify_event_id(event);
    if (outcome.result != VALIDATION_OK) return outcome;
    
    outcome = validation_verify_signature(event);
    if (outcome.result != VALIDATION_OK) return outcome;
    
    outcome = validation_verify_delegation(event);
    if (outcome.result != VALIDATION_OK) return outcome;
    
    outcome = validation_check_timestamp(event, lower_limit, upper_limit);
    if (outcome.result != VALIDATION_OK) return outcome;
    
    outcome = validation_check_pow(event, min_pow_difficulty);
    if (outcome.result != VALIDATION_OK) return outcome;
    
    return make_outcome(VALIDATION_OK, "");
}

bool validation_check_serialization_size(const event_t *event, size_t max_response_size) {
    if (!event) return false;
    
    size_t serialized_size = json_serialized_event_size(event);
    /* Add margin for ["EVENT","<sub id up to 100 chars>",...] wrapper */
    return serialized_size + 160 <= max_response_size;
}