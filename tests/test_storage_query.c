/* Unit tests for the filter -> SQL compiler (src/storage_query.c). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "storage_query.h"

static int failures;
static void check(const char *name, int ok, const char *detail) {
    printf("%s: %s%s%s\n", ok ? "PASS" : "FAIL", name, detail ? " -- " : "", detail ? detail : "");
    if (!ok) failures++;
}

static char H1[] = "1111111111111111111111111111111111111111111111111111111111111111";
static char H2[] = "2222222222222222222222222222222222222222222222222222222222222222";

static void test_simple_req(void) {
    filter_t f; memset(&f, 0, sizeof(f));
    int kinds[] = {1};
    f.kinds = kinds; f.kinds_count = 1; f.since = 100;
    sq_query_t q = {0};
    ng_status_t st = sq_build(&q, &f, false, 20);
    const char *want = "SELECT " SQ_EVENT_COLUMNS " FROM event e WHERE e.kind = ? AND e.created_at >= 100 "
                       "ORDER BY e.created_at DESC, e.id ASC LIMIT ?";
    check("kinds+since SQL", st == NG_OK && q.sql && strcmp(q.sql, want) == 0 && q.len == strlen(want), q.sql);
    check("kinds+since params", q.n == 2 && q.params[0].type == SQ_INT && q.params[0].num == 1 &&
          q.params[1].type == SQ_INT && q.params[1].num == 20, NULL);
    sq_free(&q);
}

static void test_count_authors_ids(void) {
    filter_t f; memset(&f, 0, sizeof(f));
    char *ids[] = {H1, H2}, *authors[] = {H2};
    f.ids = ids; f.ids_count = 2; f.authors = authors; f.authors_count = 1; f.until = 5;
    sq_query_t q = {0};
    ng_status_t st = sq_build(&q, &f, true, 500);
    const char *want = "SELECT COUNT(*) FROM event e WHERE e.id IN (unhex(?),unhex(?)) AND "
                       "(e.pubkey IN (unhex(?)) OR e.id IN (SELECT event_id FROM delegation WHERE delegator IN (unhex(?)))) "
                       "AND e.created_at <= 5";
    check("COUNT ids+authors SQL", st == NG_OK && strcmp(q.sql, want) == 0, q.sql);
    check("COUNT ids+authors params (no LIMIT)", q.n == 4 && q.params[0].text == H1 && q.params[1].text == H2 &&
          q.params[2].text == H2 && q.params[3].text == H2 && !q.params[0].owned, NULL);
    sq_free(&q);
}

static void test_tags_and_search_escaped(void) {
    filter_t f; memset(&f, 0, sizeof(f));
    char *el[] = {(char *) "t", (char *) "a%b", (char *) "c_d"};
    tag_t tag = { el, 3, 3 };
    f.tags = &tag; f.tags_count = 1;
    f.search = (char *) "50%_off\\";
    sq_query_t q = {0};
    ng_status_t st = sq_build(&q, &f, false, 10);
    const char *want = "SELECT DISTINCT " SQ_EVENT_COLUMNS " FROM tag t JOIN event e ON e.seq = t.ev "
                       "WHERE t.name = ? AND t.value IN (?,?) AND e.content LIKE ? ESCAPE '\\' "
                       "ORDER BY e.created_at DESC, e.id ASC LIMIT ?";
    check("multi-value tag + search SQL", st == NG_OK && strcmp(q.sql, want) == 0, q.sql);
    int ok = q.n == 5 && !q.params[0].owned && strcmp(q.params[0].text, "t") == 0 &&
             strcmp(q.params[1].text, "a%b") == 0 && strcmp(q.params[2].text, "c_d") == 0 &&
             q.params[3].owned && strcmp(q.params[3].text, "%50\\%\\_off\\\\%") == 0;
    check("tag values exact, search pattern LIKE-escaped", ok, q.n > 3 ? q.params[3].text : NULL);
    sq_free(&q);
}

/* Single-value tag drives the join in index order; a second tag name is an
 * EXISTS point lookup; hex values compare as blobs; kinds/since on the tag row. */
static void test_tag_join(void) {
    filter_t f; memset(&f, 0, sizeof(f));
    char *pe[] = {(char *) "p", H1};
    char *te[] = {(char *) "t", (char *) "nostr", (char *) "bitcoin"};
    tag_t tags[2] = { { te, 3, 3 }, { pe, 2, 2 } };
    int kinds[] = {1, 7};
    f.tags = tags; f.tags_count = 2; f.kinds = kinds; f.kinds_count = 2; f.since = 9;
    sq_query_t q = {0};
    ng_status_t st = sq_build(&q, &f, false, 50);
    const char *want = "SELECT " SQ_EVENT_COLUMNS " FROM tag t JOIN event e ON e.seq = t.ev "
                       "WHERE t.name = ? AND t.value = unhex(?) AND t.kind IN (?,?) AND t.created_at >= 9 "
                       "AND EXISTS (SELECT 1 FROM tag x WHERE x.name = ? AND x.value IN (?,?) "
                       "AND x.created_at = e.created_at AND x.ev = e.seq) "
                       "ORDER BY t.created_at DESC, e.id ASC LIMIT ?";
    check("tag join SQL", st == NG_OK && strcmp(q.sql, want) == 0, q.sql);
    check("tag join params", q.n == 8 && strcmp(q.params[0].text, "p") == 0 && q.params[1].text == H1 &&
          q.params[2].num == 1 && q.params[3].num == 7 && strcmp(q.params[4].text, "t") == 0, NULL);
    sq_free(&q);
    st = sq_build(&q, &f, true, 50);
    check("tag COUNT", st == NG_OK && strncmp(q.sql, "SELECT COUNT(*) FROM tag t JOIN", 31) == 0, q.sql);
    sq_free(&q);
    char *bad[] = {(char *) "title", (char *) "x"};
    tag_t badt = { bad, 2, 2 };
    memset(&f, 0, sizeof(f)); f.tags = &badt; f.tags_count = 1;
    st = sq_build(&q, &f, false, 50);
    check("multi-letter tag name -> NG_E_INVALID", st == NG_E_INVALID, NULL);
    sq_free(&q);
}

/* A long search string is never truncated (was a fixed 512-byte pattern). */
static void test_long_search_not_truncated(void) {
    filter_t f; memset(&f, 0, sizeof(f));
    char *s = (char *) malloc(5001);
    if (!s) { check("long search (alloc)", 0, NULL); return; }
    memset(s, 'q', 5000); s[5000] = '\0';
    f.search = s;
    sq_query_t q = {0};
    ng_status_t st = sq_build(&q, &f, false, 1);
    check("long search kept whole", st == NG_OK && q.n == 2 && strlen(q.params[0].text) == 5002, NULL);
    sq_free(&q);
    free(s);
}

/* Large but legal filters compile (the fixed 2 KiB / 256-param buffers
 * rejected e.g. 200 authors); past the policy caps building fails. */
static void test_caps(void) {
    static char *many[256];
    static int kinds[256];
    for (int i = 0; i < 256; i++) { many[i] = H1; kinds[i] = i; }
    filter_t f; memset(&f, 0, sizeof(f));
    f.ids = many; f.ids_count = 256; f.authors = many; f.authors_count = 256;
    f.kinds = kinds; f.kinds_count = 256;
    sq_query_t q = {0};
    ng_status_t st = sq_build(&q, &f, false, 500);
    check("256 ids + 256 authors + 256 kinds compile", st == NG_OK && q.n == 256 * 4 + 1, NULL);
    sq_free(&q);

    static char *vals[257];
    vals[0] = (char *) "p";
    for (int i = 1; i < 257; i++) vals[i] = H2;
    static tag_t tags[16];
    for (int t = 0; t < 16; t++) { tags[t].elements = vals; tags[t].count = 257; tags[t].capacity = 257; }
    memset(&f, 0, sizeof(f));
    f.tags = tags; f.tags_count = 16;                  /* 16 * 256 * 2 params > SQ_MAX_PARAMS */
    st = sq_build(&q, &f, false, 500);
    check("past SQ_MAX_PARAMS -> NG_E_TOOBIG", st == NG_E_TOOBIG && q.n <= SQ_MAX_PARAMS && q.len <= SQ_MAX_SQL, NULL);
    sq_free(&q);

    tag_t empty = { vals, 1, 1 };
    memset(&f, 0, sizeof(f));
    f.tags = &empty; f.tags_count = 1;
    st = sq_build(&q, &f, false, 500);
    check("tag name without values -> NG_E_INVALID", st == NG_E_INVALID, NULL);
    sq_free(&q);
}

int main(void) {
    test_simple_req();
    test_count_authors_ids();
    test_tags_and_search_escaped();
    test_tag_join();
    test_long_search_not_truncated();
    test_caps();
    return failures ? 1 : 0;
}
