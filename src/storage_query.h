/* storage_query - compile one NIP-01 filter into an SQL statement plus its
 * bind parameters (the query planner/builder of the SQLite backend).
 *
 * Pure: no SQLite calls, no globals; unit-tested in tests/test_storage_query.c.
 * Buffers grow as needed with checked sizes up to the policy caps below;
 * past them (or on OOM) building fails with an explicit status and the
 * caller rejects the query. The output is NUL-terminated SQL using `?`
 * placeholders numbered 1..n in params order.
 *
 * Ownership: SQ_TEXT params either borrow a string from the filter (valid
 * while the filter is) or own a heap pattern (owned = true); sq_free
 * releases the SQL, the param table and every owned pattern.
 */
#ifndef STORAGE_QUERY_H_
#define STORAGE_QUERY_H_

#include <stdbool.h>
#include <stddef.h>
#include "nostrogotho.h"
#include "ng_status.h"

/* Policy caps for one compiled filter. SQ_MAX_PARAMS stays well below
 * SQLite's SQLITE_MAX_VARIABLE_NUMBER (32766 in the vendored build). */
#define SQ_MAX_SQL    (256u * 1024u)
#define SQ_MAX_PARAMS 4096u

typedef enum { SQ_INT, SQ_TEXT } sq_type_t;

typedef struct {
    sq_type_t type;
    long long num;          /* SQ_INT */
    char *text;             /* SQ_TEXT */
    bool owned;             /* text is heap-owned by the query */
} sq_param_t;

typedef struct {
    char *sql;
    size_t len, cap;
    sq_param_t *params;
    size_t n, pcap;
    ng_status_t status;     /* first error, sticky */
} sq_query_t;

/* Compile `filter` into q (q must be zeroed or sq_free'd). do_count selects
 * SELECT COUNT(id) (no ORDER BY / LIMIT); otherwise the 7 event columns,
 * ORDER BY created_at DESC LIMIT ? bound to `limit`.
 * Returns NG_OK, NG_E_TOOBIG (past SQ_MAX_SQL / SQ_MAX_PARAMS),
 * NG_E_INVALID (a tag condition without values) or NG_E_NOMEM. q must be sq_free'd in every case. */
ng_status_t sq_build(sq_query_t *q, const filter_t *filter, bool do_count, int limit);

void sq_free(sq_query_t *q);

#endif /* STORAGE_QUERY_H_ */
