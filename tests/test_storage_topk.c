/* test_storage_topk - many-author REQs (storage_read.c topk_since: the
 * (limit+1)-th newest created_at from (pubkey, kind, created_at) probes,
 * then the same SQL bounded by it) return exactly the rows, in exactly the
 * order (created_at DESC, id ASC), of a brute-force query: random author /
 * kind subsets, since / until, limits, and heavy created_at ties. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include "storage.h"
#include "storage_internal.h"
#include "json_util.h"

static int failures, checks;
static uint64_t rs = 88172645463325252ull;
static unsigned rnd(unsigned n) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (unsigned) (rs % n); }

#define NA 24
static char PKS[NA][65];
static const int KINDS[] = { 1, 6, 7, 1111, 9735 };

static char got[600][65];
static int ngot;
static void collect(const char *json, const event_t *ev) {
    (void) json;
    if (ev && ngot < 600) snprintf(got[ngot++], 65, "%s", ev->id);
}

int main(void) {
    char path[] = "/tmp/ng_topk_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 1;
    close(fd); unlink(path);
    char dsn[64]; snprintf(dsn, sizeof(dsn), "file:%s", path);
    storage_context_t s; memset(&s, 0, sizeof(s));
    storage_context_init_sqlite3(&s);
    if (!s.init(dsn)) { printf("FAIL: init\n"); return 1; }
    for (int a = 0; a < NA; a++) snprintf(PKS[a], 65, "%02x%062x", a * 7 + 1, a);
    for (int i = 0; i < 4000; i++) {
        event_t e; memset(&e, 0, sizeof(e));
        snprintf(e.id, sizeof(e.id), "%08x%056x", (unsigned) rnd(0x7fffffff), i);
        /* zipf-ish authors, few distinct created_at values (ties) */
        int a = (int) (rnd(NA) * rnd(NA) / NA);
        snprintf(e.pubkey, sizeof(e.pubkey), "%s", PKS[a]);
        memset(e.sig, 'b', MAX_SIG_SIZE); e.sig[MAX_SIG_SIZE] = '\0';
        e.created_at = (time_t) (1700000000 + rnd(300));
        e.kind = KINDS[rnd(5)];
        e.tags_json = (char *) "[]"; e.tags_json_len = 2;
        e.content = (char *) "c"; e.content_len = 1;
        if (s.insert_event(&e) != STORAGE_PUT_INSERTED) { printf("FAIL: insert %d\n", i); failures++; }
    }
    char fj[4096], sql[4096];
    for (int t = 0; t < 400; t++) {
        int na = 2 + (int) rnd(NA - 1), nk = (int) rnd(4), lim = 1 + (int) rnd(80);
        long since = rnd(3) ? 0 : 1700000000 + (long) rnd(200), until = rnd(3) ? 0 : 1700000100 + (long) rnd(200);
        size_t fo = 0, so = 0;
        fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, "{\"limit\":%d,\"authors\":[", lim);
        so += (size_t) snprintf(sql + so, sizeof(sql) - so, "SELECT lower(hex(id)) FROM event WHERE pubkey IN (");
        int start = (int) rnd(NA);
        for (int i = 0; i < na; i++) {
            const char *pk = PKS[(start + i) % NA];
            fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, "%s\"%s\"", i ? "," : "", pk);
            so += (size_t) snprintf(sql + so, sizeof(sql) - so, "%sunhex('%s')", i ? "," : "", pk);
        }
        fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, "]");
        so += (size_t) snprintf(sql + so, sizeof(sql) - so, ")");
        if (nk) {
            fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, ",\"kinds\":[");
            so += (size_t) snprintf(sql + so, sizeof(sql) - so, " AND kind IN (");
            for (int i = 0; i < nk; i++) {
                fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, "%s%d", i ? "," : "", KINDS[(t + i) % 5]);
                so += (size_t) snprintf(sql + so, sizeof(sql) - so, "%s%d", i ? "," : "", KINDS[(t + i) % 5]);
            }
            fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, "]");
            so += (size_t) snprintf(sql + so, sizeof(sql) - so, ")");
        }
        if (since) { fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, ",\"since\":%ld", since); so += (size_t) snprintf(sql + so, sizeof(sql) - so, " AND created_at >= %ld", since); }
        if (until) { fo += (size_t) snprintf(fj + fo, sizeof(fj) - fo, ",\"until\":%ld", until); so += (size_t) snprintf(sql + so, sizeof(sql) - so, " AND created_at <= %ld", until); }
        snprintf(fj + fo, sizeof(fj) - fo, "}");
        snprintf(sql + so, sizeof(sql) - so, " ORDER BY created_at DESC, id ASC LIMIT %d", lim);
        filter_t f;
        if (!json_parse_filter(fj, &f)) { printf("FAIL: parse %s\n", fj); failures++; continue; }
        ngot = 0;
        bool more = false;
        bool ok = s.send_records(collect, "s", &f, 1, false, NULL, &more) == NG_OK;
        filter_release(&f);
        sqlite3_stmt *st = NULL;
        int n = 0, bad = !ok;
        if (sqlite3_prepare_v2(ngdb_conn, sql, -1, &st, NULL) != SQLITE_OK) bad = 1;
        while (!bad && sqlite3_step(st) == SQLITE_ROW) {
            if (n >= ngot || strcmp(got[n], (const char *) sqlite3_column_text(st, 0)) != 0) bad = 1;
            n++;
        }
        sqlite3_finalize(st);
        if (n != ngot) bad = 1;
        checks++;
        if (bad) { printf("FAIL: %s (got %d, want %d)\n", fj, ngot, n); failures++; }
    }
    s.deinit();
    char side[96];
    unlink(path);
    snprintf(side, sizeof(side), "%s-wal", path); unlink(side);
    snprintf(side, sizeof(side), "%s-shm", path); unlink(side);
    snprintf(side, sizeof(side), "%s-tagidx", path); unlink(side);
    printf("%s: %d/%d many-author filters identical to brute force\n", failures ? "FAIL" : "PASS", checks - failures, checks);
    return failures ? 1 : 0;
}
