#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json_util.h"

/* Regression: append_string() used to cap the ids/authors array at 32 slots
 * (capacity passed by value, never updated) while parse_string_array()
 * allowed 256 entries -> heap buffer overflow from a single REQ filter with
 * >= 33 ids. Run under a heap debugger/ASAN for full effect; the count and
 * content checks below catch the accounting part deterministically. */
static void test_filter_many_ids(void) {
    size_t n = 40;
    size_t cap = n * 70 + 32;
    char *buf = (char *) malloc(cap);
    if (!buf) { printf("FAIL: out of memory\n"); return; }
    size_t off = (size_t) snprintf(buf, cap, "{\"ids\":[");
    for (size_t i = 0; i < n; i++)
        off += (size_t) snprintf(buf + off, cap - off, "%s\"%016llx%016llx%016llx%016llx\"",
                                 i ? "," : "",
                                 (unsigned long long) (0x1111111111111111ull * (i + 1)),
                                 (unsigned long long) (0x2222222222222222ull * (i + 1)),
                                 (unsigned long long) (0x3333333333333333ull * (i + 1)),
                                 (unsigned long long) (0x4444444444444444ull * (i + 1)));
    snprintf(buf + off, cap - off, "]}");

    filter_t filter;
    bool ok = json_parse_filter(buf, &filter);
    if (!ok) {
        printf("FAIL: filter with 40 ids should parse\n");
    } else if (filter.ids_count != n) {
        printf("FAIL: ids_count=%zu expected %zu\n", filter.ids_count, n);
        filter_release(&filter);
    } else {
        int intact = 1;
        for (size_t i = 0; i < filter.ids_count && intact; i++) {
            char expected[65];
            snprintf(expected, sizeof(expected), "%016llx%016llx%016llx%016llx",
                     (unsigned long long) (0x1111111111111111ull * (i + 1)),
                     (unsigned long long) (0x2222222222222222ull * (i + 1)),
                     (unsigned long long) (0x3333333333333333ull * (i + 1)),
                     (unsigned long long) (0x4444444444444444ull * (i + 1)));
            if (strcmp(filter.ids[i], expected) != 0) intact = 0;
        }
        printf("%s: filter with 40 ids parses intact\n", intact ? "PASS" : "FAIL");
        filter_release(&filter);
    }
    free(buf);
}

/* Regression (was a stack smash with the fixed 64 KiB buffer): serializing
 * events with ~65.3 KB of tags must produce complete, NUL-terminated JSON
 * whose length matches the builder's position. The builder now grows. */
static void test_serialize_huge_tags_terminated(void) {
    event_t event;
    memset(&event, 0, sizeof(event));
    strcpy(event.id,     "0000000000000000000000000000000000000000000000000000000000000000");
    strcpy(event.pubkey, "1111111111111111111111111111111111111111111111111111111111111111");
    strcpy(event.sig,     "2222222222222222222222222222222222222222222222222222222222222222"
                          "2222222222222222222222222222222222222222222222222222222222222222");
    event.created_at = 1700000000;
    event.kind = 1;
    event.content = (char *) "hi";
    event.content_len = 2;

    int pass = 1;
    char *tags = (char *) malloc(65340 + 1);
    if (!tags) { printf("FAIL: out of memory\n"); return; }
    for (size_t tags_len = 65200; tags_len <= 65340 && pass; tags_len++) {
        size_t off = 0;
        tags[off++] = '[';
        int first = 1;
        while (off + 10 <= tags_len - 1) {
            if (!first) tags[off++] = ',';
            first = 0;
            memcpy(tags + off, "[\"t\",\"x\"]", 9);
            off += 9;
        }
        while (off < tags_len - 1) tags[off++] = ' ';
        tags[tags_len - 1] = ']';
        tags[tags_len] = '\0';
        event.tags_json = tags;
        event.tags_json_len = tags_len;

        json_builder_t b;
        json_builder_start(&b);
        json_builder_append_string(&b, "EVENT");
        json_builder_append_string(&b, "sub");
        json_serialize_event(&event, &b);
        const char *out = json_builder_finish(&b);
        size_t want = json_serialized_event_size(&event) + strlen("[\"EVENT\",\"sub\",]");
        if (!out || strlen(out) != json_builder_length(&b) || strlen(out) != want ||
            memcmp(out + strlen(out) - 2, "}]", 2) != 0) {
            printf("FAIL: incomplete serialization at tags_len=%zu\n", tags_len);
            pass = 0;
        }
        json_builder_free(&b);
    }
    free(tags);
    printf("%s: serialization of ~65 KB tags is complete and terminated\n",
           pass ? "PASS" : "FAIL");
}

/* Regression: validate_event_tags() and check_event()'s tag scanner
 * (parse_tags_json in crypto.c) must agree on the per-tag element cap;
 * events carrying oversized tags must be rejected at parse time. */
static void test_event_with_oversized_tag_rejected(void) {
    char *tags = (char *) malloc(65536);
    char *wire = (char *) malloc(65536 + 512);
    if (!tags || !wire) { printf("FAIL: out of memory\n"); free(tags); free(wire); return; }
    size_t off = (size_t) snprintf(tags, 65536, "[[");
    for (int i = 0; i < 300; i++)
        off += (size_t) snprintf(tags + off, 65536 - off, "%s\"x\"", i ? "," : "");
    off += (size_t) snprintf(tags + off, 65536 - off, "],"
            "[\"p\",\"%064d\"]]", 0);
    (void) off;

    snprintf(wire, 65536 + 512,
             "{\"id\":\"%064d\",\"pubkey\":\"%064d\",\"created_at\":1700000000,"
             "\"kind\":1,\"tags\":%s,\"content\":\"hi\",\"sig\":\"%0128d\"}",
             0, 1, tags, 0);

    event_t parsed;
    if (json_parse_event(wire, &parsed)) {
        printf("FAIL: event with a >%d-element tag must be rejected\n", MAX_TAG_ELEMENTS);
        event_release(&parsed);
    } else {
        printf("PASS: event with a >%d-element tag rejected at parse time\n",
               MAX_TAG_ELEMENTS);
    }
    free(tags);
    free(wire);
}

static void test_parse_string_array_hex64(void) {
    filter_t filter;
    if (json_parse_filter("{\"ids\": [\"short\"]}", &filter)) {
        printf("FAIL: short hex id must be rejected\n");
        filter_release(&filter);
        return;
    }
    printf("PASS: short hex id rejected\n");
}

static void test_filter_empty_is_match_all(void) {
    /* NIP-01: a filter object with no keys matches everything. It must parse
     * successfully and carry the default limit. */
    filter_t filter;
    if (!json_parse_filter("{}", &filter)) {
        printf("FAIL: empty filter should parse as match-all\n");
        return;
    }
    printf("%s: empty filter parses as match-all (limit=%d)\n",
           filter.limit == 500 ? "PASS" : "FAIL", filter.limit);
    filter_release(&filter);
}

static void test_builder_key_number_format(void) {
    json_builder_t builder;
    json_builder_start(&builder);
    json_builder_object_key_number(&builder, "count", 42);
    const char *result = json_builder_finish(&builder);
    printf("%s: builder key-number format\n",
           result && strstr(result, "\"count\":42") ? "PASS" : "FAIL");
    json_builder_free(&builder);
}

/* Invariant: json_serialized_event_size() must exactly predict the number
 * of bytes json_serialize_event() writes, so the publish-time rejection in
 * nip01 guarantees every stored event fits the fixed response buffer. */
static void test_serialized_size_matches(void) {
    const char *contents[] = {"plain", "with/slash", "quote\" and\\back",
                              "control\n\t\x01\x1f", "unicode: \xc3\xa9"};
    int pass = 1;
    for (size_t i = 0; i < sizeof(contents) / sizeof(contents[0]) && pass; i++) {
        event_t event;
        memset(&event, 0, sizeof(event));
        strcpy(event.id,     "0000000000000000000000000000000000000000000000000000000000000000");
        strcpy(event.pubkey, "1111111111111111111111111111111111111111111111111111111111111111");
        strcpy(event.sig,     "2222222222222222222222222222222222222222222222222222222222222222"
                              "2222222222222222222222222222222222222222222222222222222222222222");
        event.created_at = 1700000000;
        event.kind = 1;
        event.content = strdup(contents[i]);
        event.content_len = strlen(event.content);
        event.tags_json = strdup("[[\"t\",\"abc\"],\"x\"]");
        event.tags_json_len = strlen(event.tags_json);

        size_t predicted = json_serialized_event_size(&event);
        json_builder_t b;
        json_builder_start(&b);
        json_serialize_event(&event, &b);
        /* buffer = '[' + '{...}' + ']'  ->  object length = strlen - 2 */
        const char *r = json_builder_finish(&b);
        size_t actual = r ? strlen(r) - 2 : 0;
        if (predicted != actual) {
            printf("FAIL: content[%zu] predicted=%zu actual=%zu (%s)\n",
                   i, predicted, actual, contents[i]);
            pass = 0;
        }
        json_builder_free(&b);
        free(event.content);
        free(event.tags_json);
    }
    printf("%s: json_serialized_event_size matches serialization\n", pass ? "PASS" : "FAIL");
}

/* Regression: control bytes other than \b\f\n\r\t were written as a
 * truncated "\u00X" plus an embedded NUL (snprintf size 6 for a 6-char
 * escape), corrupting stored and broadcast JSON. */
static void test_builder_control_escape(void) {
    json_builder_t b;
    json_builder_start(&b);
    json_builder_append_string(&b, "a\x01\x1f\x7f\"\\z");
    const char *r = json_builder_finish(&b);
    int ok = r && strcmp(r, "[\"a\\u0001\\u001f\x7f\\\"\\\\z\"]") == 0 &&
             strlen(r) == json_builder_length(&b);
    printf("%s: builder escapes control bytes as \\u00XX (%s)\n", ok ? "PASS" : "FAIL", r ? r : "(null)");
    json_builder_free(&b);
}

/* Long keys are written in full (the fixed builder used to drop them). */
static void test_builder_long_key(void) {
    json_builder_t b;
    char key[300]; memset(key, 'k', sizeof(key) - 1); key[sizeof(key) - 1] = '\0';
    json_builder_start(&b);
    json_builder_start_object(&b);
    json_builder_object_key_number(&b, key, 1);
    json_builder_object_key_number(&b, "n", 2);
    json_builder_end_object(&b);
    const char *r = json_builder_finish(&b);
    int ok = r && strlen(r) == json_builder_length(&b) && strstr(r, "\"n\":2") != NULL &&
             strlen(r) == 1 + 1 + (1 + 299 + 1 + 1 + 1) + 1 + 5 + 1 + 1;
    printf("%s: long key written in full\n", ok ? "PASS" : "FAIL");
    json_builder_free(&b);
}

/* Past JSON_BUILDER_MAX the builder fails explicitly: NG_E_TOOBIG, sticky,
 * finish() returns NULL instead of truncated JSON. */
static void test_builder_overflow_is_error(void) {
    size_t chunk = 64 * 1024;
    char *s = (char *) malloc(chunk + 1);
    if (!s) { printf("FAIL: out of memory\n"); return; }
    memset(s, 'x', chunk); s[chunk] = '\0';
    json_builder_t b;
    json_builder_start(&b);
    int ok = 1;
    for (size_t total = 0; total < JSON_BUILDER_MAX - 2 * chunk; total += chunk + 3)
        json_builder_append_string(&b, s);
    ok &= json_builder_status(&b) == NG_OK;                /* still under the cap */
    for (int i = 0; i < 4; i++) json_builder_append_string(&b, s);
    ok &= json_builder_status(&b) == NG_E_TOOBIG;
    size_t pos = json_builder_length(&b);
    json_builder_append_string(&b, "y");                    /* sticky: no-op */
    ok &= json_builder_length(&b) == pos && json_builder_finish(&b) == NULL;
    json_builder_free(&b);
    json_builder_free(&b);                                  /* idempotent */
    free(s);
    printf("%s: builder overflow past JSON_BUILDER_MAX returns NG_E_TOOBIG / NULL\n", ok ? "PASS" : "FAIL");
}

/* Scratch builders: reset on every call, independent slots, reusable after
 * a failure, heap buffer kept between uses. */
static void test_builder_scratch_reuse(void) {
    int ok = 1;
    json_builder_t *a = json_builder_scratch(JSON_SCRATCH_BCAST);
    json_builder_t *q = json_builder_scratch(JSON_SCRATCH_QUERY);
    ok &= a != q;
    char big[2000]; memset(big, 'z', sizeof(big) - 1); big[sizeof(big) - 1] = '\0';
    json_builder_append_string(a, big);
    const char *r = json_builder_finish(a);
    ok &= r && strlen(r) == sizeof(big) - 1 + 4;
    json_builder_t *a2 = json_builder_scratch(JSON_SCRATCH_BCAST);
    ok &= a2 == a;
    json_builder_append_string(a2, "v");
    r = json_builder_finish(a2);
    ok &= r && strcmp(r, "[\"v\"]") == 0;
    json_builder_append_string(q, "q");
    r = json_builder_finish(q);
    ok &= r && strcmp(r, "[\"q\"]") == 0;
    printf("%s: scratch builders reset per use, slots independent\n", ok ? "PASS" : "FAIL");
}

int main(void) {
    printf("Running json_util security regression tests...\n");
    test_filter_many_ids();
    test_serialize_huge_tags_terminated();
    test_event_with_oversized_tag_rejected();
    test_serialized_size_matches();
    test_parse_string_array_hex64();
    test_filter_empty_is_match_all();
    test_builder_key_number_format();
    test_builder_control_escape();
    test_builder_long_key();
    test_builder_overflow_is_error();
    test_builder_scratch_reuse();
    printf("json_util security regression tests complete.\n");
    return 0;
}
