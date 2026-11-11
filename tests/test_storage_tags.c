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
#include "storage_query.h"

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
    bool ok = s->send_records(count_rows, "s", &f, 1, do_count, &n, NULL) == NG_OK;
    filter_release(&f);
    return ok ? (do_count ? n : rows) : -1;
}

static int scanned;
static void count_scan(const event_t *ev, void *arg) { (void) arg; if (ev && ev->kind == 9) scanned++; }

static int count_sql(const char *sql) {
    sqlite3_stmt *st; int n = -1;
    if (sqlite3_prepare_v2(ngdb_conn, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* FTS5 structure is sound and the indexed documents are exactly the
 * searchable rows (content != '', kind not excluded). */
static bool fts_ok(void) {
    if (sqlite3_exec(ngdb_conn, "INSERT INTO event_fts(event_fts) VALUES('integrity-check')", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    return count_sql("SELECT COUNT(*) FROM (SELECT seq FROM event WHERE content != '' AND " NG_SEARCH_KIND_SQL("kind")
                     " EXCEPT SELECT id FROM event_fts_docsize)") == 0 &&
           count_sql("SELECT COUNT(*) FROM (SELECT id FROM event_fts_docsize EXCEPT SELECT seq FROM event WHERE content != ''"
                     " AND " NG_SEARCH_KIND_SQL("kind") ")") == 0;
}

static event_t mkc(int n, int kind, long long at, const char *tags, const char *content) {
    event_t e = mk(n, kind, at, tags);
    e.content = (char *) content; e.content_len = strlen(content);
    return e;
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

    /* NIP-62: durable vanish. */
    event_t v1 = mk(20, 1, 3000, "[]"), v2 = mk(21, 1, 5000, "[]"), req = mk(22, 62, 4000, "[]");
    char wt[128]; snprintf(wt, sizeof(wt), "[[\"p\",\"%s\"]]", PK);
    event_t wrap = mk(23, 1059, 9000, wt);
    memset(wrap.pubkey, 'c', 64);
    check("vanish: setup", s.insert_event(&v1) == STORAGE_PUT_INSERTED &&
          s.insert_event(&wrap) == STORAGE_PUT_INSERTED, NULL);
    check("vanish", s.vanish(PK, 4000, NULL, &d) && d == 2, NULL);
    check("vanish request stored", s.insert_event(&req) == STORAGE_PUT_INSERTED, NULL);
    check("older event refused", s.insert_event(&v1) == STORAGE_PUT_VANISHED, NULL);
    check("newer event accepted", s.insert_event(&v2) == STORAGE_PUT_INSERTED, NULL);
    check("vanish until never shrinks", s.vanish(PK, 100, NULL, &d), NULL);
    s.deinit();
    memset(&s, 0, sizeof(s));
    storage_context_init_sqlite3(&s);
    check("reopen", s.init(dsn), NULL);
    check("vanish survives restart", s.insert_event(&v1) == STORAGE_PUT_VANISHED, NULL);
    event_t v3 = mk(24, 7, 3999, "[]");
    check("... any kind but 62", s.insert_event(&v3) == STORAGE_PUT_VANISHED, NULL);
    memset(v3.pubkey, 'c', 64);
    check("other pubkeys unaffected", s.insert_event(&v3) == STORAGE_PUT_INSERTED, NULL);

    /* NIP-29 moderation ops. */
    event_t g1 = mk(30, 9, 6000, "[[\"h\",\"pizza\"]]"), g2 = mk(31, 9, 6001, "[[\"h\",\"pizza\"]]"),
            g3 = mk(32, 9, 6002, "[[\"h\",\"other\"]]");
    memset(g1.pubkey, 'c', 64); memset(g2.pubkey, 'c', 64); memset(g3.pubkey, 'c', 64);
    check("groups: setup", s.insert_event(&g1) == STORAGE_PUT_INSERTED && s.insert_event(&g2) == STORAGE_PUT_INSERTED &&
          s.insert_event(&g3) == STORAGE_PUT_INSERTED, NULL);
    check("has_id_prefix hit", s.has_id_prefix("00000000"), NULL);   /* ids are %064x of small n */
    check("has_id_prefix miss", !s.has_id_prefix("ffffffff") && !s.has_id_prefix("12345678"), NULL);
    check("has_id_prefix rejects bad hex", !s.has_id_prefix("zz") && !s.has_id_prefix("0000000g"), NULL);
    int k9 = 9; scanned = 0;
    check("scan_kinds", s.scan_kinds(&k9, 1, count_scan, NULL) && scanned == 3, NULL);
    d = 0;
    check("delete_by_id", s.delete_by_id(g1.id, &d) && d == 1, NULL);
    d = 0;
    check("delete_by_tag h", s.delete_by_tag('h', "pizza", NULL, &d) && d == 1, NULL);
    check("... other groups untouched", query(&s, "{\"#h\":[\"other\"]}", false) == 1 &&
          query(&s, "{\"#h\":[\"pizza\"]}", false) == 0, NULL);

    /* NIP-50 bulk feed: deletes and replacements inside the batch that
     * inserted the rows, then search and an FTS5 integrity check. */
    {
        event_t a = mkc(40, 1, 7000, "[]", "zebra alpha"), b = mkc(41, 0, 7001, "[]", "zebra profile one"),
                b2 = mkc(42, 0, 7002, "[]", "zebra profile two"), c = mkc(43, 1, 7003, "[[\"t\",\"gone\"]]", "zebra gamma"),
                d4 = mkc(44, 1, 7004, "[]", "zebra delta"), e4 = mkc(45, 4, 7005, "[]", "zebra secret dm");
        memset(b.pubkey, 'd', 64); memset(b2.pubkey, 'd', 64);
        event_t x = mkc(46, 1, 7006, "[[\"expiration\",\"1\"]]", "zebra expired");
        check("fts: integrity before the batch", fts_ok(), NULL);
        check("fts batch: begin", s.begin_batch(), NULL);
        check("fts batch: inserts", s.insert_event(&a) == STORAGE_PUT_INSERTED && s.insert_event(&b) == STORAGE_PUT_INSERTED &&
              s.insert_event(&c) == STORAGE_PUT_INSERTED && s.insert_event(&e4) == STORAGE_PUT_INSERTED &&
              s.insert_event(&x) == STORAGE_PUT_INSERTED, NULL);
        check("fts batch: kind 0 replaced in the same batch", s.replaceable_admit(&b2, NULL) == STORAGE_ADMIT_NEWEST &&
              s.insert_event(&b2) == STORAGE_PUT_INSERTED, NULL);
        check("fts batch: delete_by_tag in the same batch", s.delete_by_tag('t', "gone", NULL, &d) && d == 1, NULL);
        check("fts batch: insert then delete_by_id", s.insert_event(&d4) == STORAGE_PUT_INSERTED && s.delete_by_id(d4.id, &d) && d == 1, NULL);
        check("fts batch: NIP-40 purge in the same batch", s.purge_expired(999999, &d) && d == 1, NULL);
        check("fts batch: commit", s.commit_batch(), NULL);
        check("fts: integrity-check", fts_ok(), NULL);
        check("fts: survivors searchable", query(&s, "{\"search\":\"zebra\"}", false) == 2 &&
              query(&s, "{\"search\":\"profile two\"}", false) == 1, NULL);
        check("fts: replaced / deleted / purged / kind 4 not found",
              query(&s, "{\"search\":\"one\"}", false) == 0 && query(&s, "{\"search\":\"gamma\"}", false) == 0 &&
              query(&s, "{\"search\":\"delta\"}", false) == 0 && query(&s, "{\"search\":\"expired\"}", false) == 0 &&
              query(&s, "{\"search\":\"secret\"}", false) == 0, NULL);
        event_t r = mkc(47, 1, 7007, "[]", "zebra rolled");
        check("fts: rolled back batch", s.begin_batch() && s.insert_event(&r) == STORAGE_PUT_INSERTED && s.rollback_batch() &&
              fts_ok() && query(&s, "{\"search\":\"rolled\"}", false) == 0, NULL);
        event_t vz = mkc(48, 1, 7008, "[]", "zebra vanishing");
        memset(vz.pubkey, 'e', 64);
        char vpk[65]; memset(vpk, 'e', 64); vpk[64] = 0;
        check("fts: vanish in the inserting batch", s.begin_batch() && s.insert_event(&vz) == STORAGE_PUT_INSERTED &&
              s.vanish(vpk, 9000, NULL, &d) && d == 1 && s.commit_batch() && fts_ok() &&
              query(&s, "{\"search\":\"vanishing\"}", false) == 0, NULL);
        event_t w1 = mkc(49, 1, 7009, "[]", "zebra omega"), w2 = mkc(50, 30023, 7010, "[[\"d\",\"post\"]]", "zebra article");
        check("fts: batch of inserts only, fed at commit", s.begin_batch() && s.insert_event(&w1) == STORAGE_PUT_INSERTED &&
              s.insert_event(&w2) == STORAGE_PUT_INSERTED && s.commit_batch() && fts_ok() &&
              query(&s, "{\"search\":\"omega\"}", false) == 1 && query(&s, "{\"search\":\"article\"}", false) == 1, NULL);
    }

    /* Tag index scope: letters outside tag_index_letters and tags past
     * tag_index_max_per_event are answered from the tags JSON. */
    {
        s.deinit();
        unlink(path);
        char side0[96];
        snprintf(side0, sizeof(side0), "%s-wal", path); unlink(side0);
        snprintf(side0, sizeof(side0), "%s-shm", path); unlink(side0);
        check("tag index: bad letters rejected", !storage_set_tag_index("e,p,1", 3) && ngdb_tag_cap() == NG_TAG_CAP_DEFAULT, NULL);
        check("tag index: letters e,p,t cap 3", storage_set_tag_index("e, p,t", 3) && strcmp(sq_tag_letters(), "ept") == 0, NULL);
        check("tag index: reopen", s.init(dsn), NULL);
        char tx[1024];
        snprintf(tx, sizeof(tx), "[[\"x\",\"foo\"],[\"E\",\"%s\"],[\"t\",\"a\"],[\"p\",\"%s\"],"
                 "[\"x\",\"bar\"]]", H1, H2);
        event_t a = mk(60, 1, 8000, tx), b = mk(61, 7, 8001, "[[\"x\",\"foo\"],[\"k\",\"1\"]]");
        check("non-indexed letters store no rows", s.insert_event(&a) == STORAGE_PUT_INSERTED &&
              s.insert_event(&b) == STORAGE_PUT_INSERTED && tag_rows() == 2, NULL);
        check("#x fallback", query(&s, "{\"#x\":[\"foo\"]}", false) == 2 &&
              query(&s, "{\"#x\":[\"bar\"]}", false) == 1 && query(&s, "{\"#x\":[\"baz\"]}", false) == 0, NULL);
        check("#x fallback multi-value + COUNT", query(&s, "{\"#x\":[\"foo\",\"bar\"]}", false) == 2 &&
              query(&s, "{\"#x\":[\"foo\",\"bar\"]}", true) == 2, NULL);
        check("#x fallback + kinds", query(&s, "{\"#x\":[\"foo\"],\"kinds\":[7]}", false) == 1, NULL);
        check("#k (not indexed here) fallback", query(&s, "{\"#k\":[\"1\"]}", false) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#E\":[\"%s\"]}", H1);
        check("#E hex value via fallback (text compare)", query(&s, fq, false) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#x\":[\"bar\"],\"#p\":[\"%s\"]}", H2);
        check("indexed driver + fallback condition", query(&s, fq, false) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#x\":[\"foo\"],\"#p\":[\"%s\"]}", H1);
        check("indexed driver + fallback condition (miss)", query(&s, fq, false) == 0, NULL);

        /* Cap 3: five p tags, the last two only in the JSON. */
        char tc[2048]; size_t o = 0;
        o += (size_t) snprintf(tc + o, sizeof(tc) - o, "[");
        for (int i = 0; i < 5; i++)
            o += (size_t) snprintf(tc + o, sizeof(tc) - o, "%s[\"p\",\"%064x\"]", i ? "," : "", 0x100 + i);
        snprintf(tc + o, sizeof(tc) - o, ",[\"t\",\"late\"]]");
        event_t c = mk(62, 3, 8002, tc);
        check("capped event: 3 rows + overflow", s.insert_event(&c) == STORAGE_PUT_INSERTED && tag_rows() == 5 &&
              count_sql("SELECT COUNT(*) FROM tag_overflow") == 1, NULL);
        char p0[65], p4[65]; snprintf(p0, sizeof(p0), "%064x", 0x100); snprintf(p4, sizeof(p4), "%064x", 0x104);
        snprintf(fq, sizeof(fq), "{\"#p\":[\"%s\"]}", p0);
        check("capped: indexed tag found", query(&s, fq, false) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#p\":[\"%s\"]}", p4);
        check("capped: tag past the cap found (driver)", query(&s, fq, false) == 1 && query(&s, fq, true) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#p\":[\"%s\",\"%s\"],\"kinds\":[3]}", p0, p4);
        check("capped: both values, one event", query(&s, fq, false) == 1 && query(&s, fq, true) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#t\":[\"late\"],\"#p\":[\"%s\"]}", p4);
        check("capped: past-cap tags in driver and EXISTS", query(&s, fq, false) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#t\":[\"a\"],\"#p\":[\"%s\"]}", H2);
        check("overflow present: ordinary indexed query", query(&s, fq, false) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#p\":[\"%s\"],\"kinds\":[1]}", p4);
        check("capped: kinds still applied", query(&s, fq, false) == 0, NULL);

        /* Reopen with other settings: the index is rebuilt to match. */
        s.deinit();
        check("rebuild: letters p,x cap 2", storage_set_tag_index("px", 2) && s.init(dsn), NULL);
        /* a: x,p,x -> 2 rows (x foo, p) + overflow; b: x -> 1; c: 5 p -> 2 + overflow */
        check("rebuild: rows and overflow match the new settings", tag_rows() == 5 &&
              count_sql("SELECT COUNT(*) FROM tag_overflow") == 2 &&
              count_sql("SELECT COUNT(*) FROM tag WHERE name = 'x'") == 2, NULL);
        check("rebuild: queries agree", query(&s, "{\"#x\":[\"bar\"]}", false) == 1 &&
              query(&s, "{\"#t\":[\"late\"]}", false) == 1, NULL);
        snprintf(fq, sizeof(fq), "{\"#p\":[\"%s\"]}", p4);
        check("rebuild: past-cap tag found", query(&s, fq, false) == 1, NULL);
        size_t dd = 0;
        check("delete drops the overflow row", s.delete_record_by_id_and_pubkey(c.id, c.pubkey, &dd) && dd == 1 &&
              count_sql("SELECT COUNT(*) FROM tag_overflow") == 1 && query(&s, fq, false) == 0, NULL);
        s.deinit();
        check("reopen with same settings: no rebuild needed", s.init(dsn) && tag_rows() == 3, NULL);
        storage_set_tag_index(SQ_TAG_LETTERS_DEFAULT, NG_TAG_CAP_DEFAULT);
    }

    s.deinit();
    char side[96];
    unlink(path);
    snprintf(side, sizeof(side), "%s-wal", path); unlink(side);
    snprintf(side, sizeof(side), "%s-shm", path); unlink(side);
    return failures ? 1 : 0;
}
