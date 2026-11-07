/* dedupe - concurrent event-id set guarding the single writer.
 *
 * Layer 2/3 of the duplicate guards (layer 1 is the per-batch check in the
 * writer, layer 4 the UNIQUE index on event.id):
 *   - in-flight: a worker claims an id after verifying the event and before
 *     queueing it to the writer; a second copy arriving on any connection or
 *     worker while the first is queued is answered "duplicate" at once.
 *   - recent:    after the writer resolves an id (stored, or already in the
 *     DB) it stays in the set as "known" in a bounded FIFO, so recent
 *     duplicates never reach SQLite (and skip signature verification).
 * Lock-striped open addressing; ids are 64-hex strings stored as 32 bytes. */
#ifndef NG_DEDUPE_H
#define NG_DEDUPE_H
#include <stdbool.h>
#include <stddef.h>

enum { DEDUPE_ABSENT = 0, DEDUPE_INFLIGHT = 1, DEDUPE_KNOWN = 2 };

void dedupe_init(size_t recent_capacity);   /* 0 disables the set */
int  dedupe_lookup(const char *hex_id);     /* DEDUPE_* */
bool dedupe_claim(const char *hex_id);      /* true: absent -> in-flight (caller owns it) */
void dedupe_resolve(const char *hex_id);    /* in-flight -> known (recent FIFO) */
void dedupe_release(const char *hex_id);    /* in-flight -> absent (not stored) */
void dedupe_forget(const char *hex_id);     /* known -> absent (e.g. NIP-09 deleted it) */
void dedupe_free(void);
#endif
