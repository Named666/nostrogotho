/* Integration tests for the NIP-01 tag index (storage_write.c store_tags,
 * the event_tag_delete trigger, storage_query.c tag joins) on a real
 * SQLite database in a temp file. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include "storage.h"
#include "storage_internal.h"
#include "json_util.h"

static int failures;
static void check(const char *name, int ok, const char *detail) {
    printf("%s: %s%s%s\n", ok ? "PASS" : "FAIL", name, detail ? " -- " : "", detail ? detail : "");
    if (!ok) failures++;
}

static char H1[] = "1111111111111111111111111111111111111111111111111111111111111111";
static char H2[] = "2222222222222222222222222222222222222222222222222222222222222222";
static char PK[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static event_t mk(int n, int kind, long long at, const char *tags) {
    event_t e; memset(&e, 0, sizeof(e));
    snprintf(e.id, sizeof(e.id), "%064x", n);
    snprintf(e.pubkey, sizeof(e.pubkey), "%s", PK);
    memset(e.sig, 'b', MAX_SIG_SIZE); e.sig[MAX_SIG_SIZE] = '\0';
    e.created_at = (time_t) at; e.kind = kind;
    e.tags_json = (char *) tags; e.tags_json_len = strlen(tags);
    e.content = (char *) "c"; e.content_len = 1;
    return e;
}

static int rows;
static void count_rows(const char *json, const event_t *ev) { (void) ev; if (json) rows++; }

static int query(storage_context_t *s, const char *filter_json, bool do_count) {
    filter_t f;
    if (!json_parse_filter(filter_json, &f)) return -2;
    rows = 0;
    int n = 0;
    bool ok = s->send_records(count_rows, "s", &f, 1, do_count, &n) == NG_OK;
    filter_release(&f);
    return ok ? (do_count ? n : rows) : -1;
}

static int tag_rows(void) {
    sqlite3_stmt *st; int n = -1;
    if (sqlite3_prepare_v2(ngdb_conn, "SELECT COUNT(*) FROM tag", -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

int main(void) {
    char path[] = "/tmp/ng_tagtest_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { printf("FAIL: mkstemp\n"); return 1; }
    close(fd); unlink(path);
    char dsn[64]; snprintf(dsn, sizeof(dsn), "file:%s", path);
    storage_context_t s; memset(&s, 0, sizeof(s));
    storage_context_init_sqlite3(&s);
    if (!s.init(dsn)) { printf("FAIL: init\n"); return 1; }

    char t1[512];
    snprintf(t1, sizeof(t1), "[[\"p\",\"%s\",\"wss://relay.example\"],[\"e\",\"%s\",\"\",\"reply\"],"
             "[\"t\",\"Nostr\"],[\"title\",\"long name not indexed\"],[\"q\"],[\"t\",\"Nostr\"]]", H1, H2);
    event_t e1 = mk(1, 1, 1000, t1);
    check("insert tagged event", s.insert_event(&e1) == STORAGE_PUT_INSERTED, NULL);
    check("3 tag rows (single-letter, valued, duplicate collapsed)", tag_rows() == 3, NULL);

    char fq[256];
    snprintf(fq, sizeof(fq), "{\"#p\":[\"%s\"]}", H1);
    check("#p matches a tag with a relay hint", query(&s, fq, false) == 1, NULL);
    snprintf(fq, sizeof(fq), "{\"#e\":[\"%s\"],\"kinds\":[1]}", H2);
    check("#e matches a tag with a marker", query(&s, fq, false) == 1, NULL);
    snprintf(fq, sizeof(fq), "{\"#e\":[\"%s\"],\"kinds\":[7]}", H2);
    check("#e + other kind: no match", query(&s, fq, false) == 0, NULL);
    check("#t exact (case-sensitive)", query(&s, "{\"#t\":[\"Nostr\"]}", false) == 1 &&
          query(&s, "{\"#t\":[\"nostr\"]}", false) == 0, NULL);
    snprintf(fq, sizeof(fq), "{\"#t\":[\"Nostr\"],\"#p\":[\"%s\"]}", H1);
    check("two tag names AND", query(&s, fq, false) == 1, NULL);
    snprintf(fq, sizeof(fq), "{\"#t\":[\"Nostr\"],\"#p\":[\"%s\"]}", H2);
    check("two tag names AND (miss)", query(&s, fq, false) == 0, NULL);

    char t2[256];
    snprintf(t2, sizeof(t2), "[[\"p\",\"%s\"],[\"p\",\"%s\"]]", H1, H2);
    event_t e2 = mk(2, 1, 1001, t2);
    s.insert_event(&e2);
    snprintf(fq, sizeof(fq), "{\"#p\":[\"%s\",\"%s\"]}", H1, H2);
    check("multi-value: each event once", query(&s, fq, false) == 2, NULL);
    check("multi-value COUNT distinct", query(&s, fq, true) == 2, NULL);
    check("multi-letter tag filter rejected by the parser", query(&s, "{\"#title\":[\"x\"]}", false) == -2, NULL);

    size_t d = 0;
    check("delete event 1", s.delete_record_by_id_and_pubkey(e1.id, e1.pubkey, &d) && d == 1, NULL);
    check("its tag rows are gone (trigger)", tag_rows() == 2, NULL);
    snprintf(fq, sizeof(fq), "{\"#e\":[\"%s\"]}", H2);
    check("deleted event no longer matches", query(&s, fq, false) == 0, NULL);

    /* Replaceable overwrite: the old version's tag rows go with it. */
    char t3[256];
    snprintf(t3, sizeof(t3), "[[\"p\",\"%s\"]]", H2);
    event_t k3a = mk(3, 3, 2000, t3), k3b = mk(4, 3, 2001, "[]");
    s.insert_event(&k3a);
    check("kind 3 v1 indexed", tag_rows() == 3, NULL);
    check("kind 3 v2 admitted", s.replaceable_admit(&k3b, NULL) == STORAGE_ADMIT_NEWEST, NULL);
    s.insert_event(&k3b);
    check("kind 3 v1 tag rows removed", tag_rows() == 2, NULL);

    /* Mass delete (NIP-62 path) clears all tag rows. */
    check("delete all by pubkey", s.delete_all_events_by_pubkey(PK, 999999, 0, &d), NULL);
    check("tag table empty", tag_rows() == 0, NULL);

    s.deinit();
    char side[96];
    unlink(path);
    snprintf(side, sizeof(side), "%s-wal", path); unlink(side);
    snprintf(side, sizeof(side), "%s-shm", path); unlink(side);
    return failures ? 1 : 0;
}
