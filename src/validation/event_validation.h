#ifndef EVENT_VALIDATION_H_
#define EVENT_VALIDATION_H_

#include <stdbool.h>
#include <time.h>
#include "nostrogotho.h"
#include "crypto.h"

/* ============================================================================
 * EVENT_VALIDATION.H - Event Validation Boundary
 * 
 * Separates event validation logic from cryptographic primitives.
 * Orchestrates validation steps: structure, ID, signature, delegation.
 * ============================================================================ */

typedef enum {
    VALIDATION_OK = 0,
    VALIDATION_INVALID_STRUCTURE,
    VALIDATION_INVALID_EVENT_ID,
    VALIDATION_INVALID_SIGNATURE,
    VALIDATION_INVALID_DELEGATION,
    VALIDATION_CONTENT_TOO_LARGE,
    VALIDATION_TIMESTAMP_OUT_OF_RANGE,
    VALIDATION_INSUFFICIENT_POW,
    VALIDATION_POLICY_REJECTED
} validation_result_t;

typedef struct {
    validation_result_t result;
    char reason[256];
} validation_outcome_t;

/* Validate event structure (required fields, field sizes) */
validation_outcome_t validation_check_structure(const event_t *event, size_t max_content_length);

/* Verify event ID matches computed hash */
validation_outcome_t validation_verify_event_id(const event_t *event);

/* Verify Schnorr signature */
validation_outcome_t validation_verify_signature(const event_t *event);

/* Verify NIP-26 delegation */
validation_outcome_t validation_verify_delegation(const event_t *event);

/* Check timestamp bounds */
validation_outcome_t validation_check_timestamp(const event_t *event, time_t lower_limit, time_t upper_limit);

/* Check proof of work (NIP-13) */
validation_outcome_t validation_check_pow(const event_t *event, int min_pow_difficulty);

/* Full validation pipeline */
validation_outcome_t validation_validate_event(const event_t *event,
                                               size_t max_content_length,
                                               time_t lower_limit,
                                               time_t upper_limit,
                                               int min_pow_difficulty);

/* Check if event serialization fits in response buffer */
bool validation_check_serialization_size(const event_t *event, size_t max_response_size);

#endif /* EVENT_VALIDATION_H_ */