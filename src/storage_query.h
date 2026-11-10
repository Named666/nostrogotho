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
#define SQ_MAX_SQL    (1024u * 1024u)
#define SQ_MAX_PARAMS 30000u   /* below SQLite's 32766 host parameters */

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

/* The 7 event columns every stored-event query returns, in this order. */
#define SQ_EVENT_COLUMNS "lower(hex(e.id)), lower(hex(e.pubkey)), e.created_at, e.kind, e.tags, " \
                         "e.content, lower(hex(e.sig))"

/* NIP-01 indexes tags whose name is a single letter (a-z, A-Z): only those
 * are stored in the tag table and only those may appear as #<name> filters. */
bool sq_tag_name_indexable(const char *name);
/* s[0..len) is exactly 64 lowercase hex digits (stored as a 32-byte blob). */
bool sq_is_hex64(const char *s, size_t len);

/* Compile `filter` into q (q must be zeroed or sq_free'd). do_count selects
 * a COUNT (no ORDER BY / LIMIT); otherwise SQ_EVENT_COLUMNS,
 * ORDER BY created_at DESC, id ASC LIMIT ? bound to `limit`. Tag conditions
 * use the tag table (see storage_sqlite.c); a multi-value tag condition
 * adds DISTINCT (one event may carry several of the values).
 * Returns NG_OK, NG_E_TOOBIG (past SQ_MAX_SQL / SQ_MAX_PARAMS),
 * NG_E_INVALID (a tag condition without values or with a name that is not
 * a single letter) or NG_E_NOMEM. q must be sq_free'd in every case. */
ng_status_t sq_build(sq_query_t *q, const filter_t *filter, bool do_count, int limit);

/* SQ_MODE_ROWS / SQ_MODE_COUNT are sq_build(.., false / true, ..);
 * SQ_MODE_PUBKEYS selects (seq, pubkey blob) of every matching event, no
 * ORDER BY / LIMIT (NIP-45 HyperLogLog). */
typedef enum { SQ_MODE_ROWS, SQ_MODE_COUNT, SQ_MODE_PUBKEYS } sq_mode_t;
ng_status_t sq_build_mode(sq_query_t *q, const filter_t *filter, sq_mode_t mode, int limit);

void sq_free(sq_query_t *q);

#endif /* STORAGE_QUERY_H_ */
