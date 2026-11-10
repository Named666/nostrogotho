/* ng_status.h - the one error-code type for modules that report more than
 * success/failure.
 *
 * Error semantics across nostrogotho (see REFACTOR.md):
 *   - bool:        true = done, false = failed; used when the caller has a
 *                  single failure path (most of the code).
 *   - pointer:     NULL = failed (allocation or invalid input).
 *   - ng_status_t: NG_OK (0) or a negative NG_E_* code when callers act on
 *                  the reason (config errors, ws_parse_header's
 *                  NG_E_AGAIN / NG_E_INVALID, json_builder overflow).
 *   - a named enum when the outcome is not an error but one of several
 *     normal results (storage_put_t, storage_admit_t).
 *   - counts are returned through a size_t out-parameter next to a bool,
 *     never as "count or -1".
 * Functions never return a mix of these, and failures never leave a
 * half-updated output: outputs are written only on NG_OK / true.
 */
#ifndef NG_STATUS_H_
#define NG_STATUS_H_

typedef enum {
    NG_OK          = 0,
    NG_E_INVALID   = -1,   /* malformed input (syntax) */
    NG_E_RANGE     = -2,   /* well-formed but out of the accepted range */
    NG_E_UNKNOWN   = -3,   /* unknown key / name */
    NG_E_NOMEM     = -4,   /* allocation failed or size overflow */
    NG_E_IO        = -5,   /* OS-level I/O error (errno is set) */
    NG_E_AGAIN     = -6,   /* incomplete input: call again with more bytes */
    NG_E_TOOBIG    = -7    /* output would exceed a hard size policy */
} ng_status_t;

/* Static English description; never NULL. Thread-safe. */
static inline const char *ng_status_str(ng_status_t s) {
    switch (s) {
    case NG_OK: return "ok";
    case NG_E_INVALID: return "invalid syntax";
    case NG_E_RANGE: return "value out of range";
    case NG_E_UNKNOWN: return "unknown key";
    case NG_E_NOMEM: return "out of memory";
    case NG_E_IO: return "I/O error";
    case NG_E_AGAIN: return "incomplete";
    case NG_E_TOOBIG: return "too large";
    }
    return "error";
}

#endif /* NG_STATUS_H_ */
