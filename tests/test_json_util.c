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

/* Regression: json_builder_object_key_string() used to pass a fixed 128-byte
 * budget to snprintf after checking only 4 bytes of headroom, writing past
 * json_builder_t.buffer[65535] (into the adjacent pos field / stack memory)
 * when serializing events with ~65.3 KB of tags. The fixed code bounds the
 * key write by the remaining capacity; this test asserts the builder never
 * reports a position outside the buffer and that the result stays NUL-
 * terminated. */
static void test_serialize_huge_tags_terminated(void) {
    event_t event;
    memset(&event, 0, sizeof(event));
    strcpy(event.id,     "0000000000000000000000000000000000000000000000000000000000000000");
    strcpy(event.pubkey, "1111111111111111111111111111111111111111111111111111111111111111");
    strcpy(event.sig,     "2222222222222222222222222222222222222222222222222222222222222222"
                          "2222222222222222222222222222222222222222222222222222222222222222");
    event.created_at = 1700000000;
    event.kind = 1;
    event.content = strdup("hi");
    event.content_len = 2;

    int pass = 1;
    for (size_t tags_len = 65200; tags_len <= 65340 && pass; tags_len++) {
        char *tags = (char *) malloc(tags_len + 1);
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

        json_builder_t *b = (json_builder_t *) malloc(sizeof(json_builder_t));
        memset(b, 0, sizeof(*b));
        json_builder_start(b);
        json_builder_append_string(b, "EVENT");
        json_builder_append_string(b, "sub");
        size_t pos_before = b->pos;
        json_serialize_event(&event, b);
        const char *out = json_builder_finish(b);

        if (b->pos < pos_before) {
            printf("FAIL: pos went backward at tags_len=%zu (OOB write)\n", tags_len);
            pass = 0;
        }
        if (b->pos >= sizeof(b->buffer)) {
            printf("FAIL: pos=%zu outside buffer at tags_len=%zu\n", b->pos, tags_len);
            pass = 0;
        }
        if (memchr(b->buffer, 0, sizeof(b->buffer)) == NULL) {
            printf("FAIL: unterminated builder at tags_len=%zu\n", tags_len);
            pass = 0;
        }
        if (strlen(out) != b->pos) {
            printf("FAIL: strlen(out)=%zu != pos=%zu at tags_len=%zu\n",
                   strlen(out), b->pos, tags_len);
            pass = 0;
        }
        free(b);
        free(tags);
    }
    printf("%s: serialization of ~65 KB tags stays bounded and terminated\n",
           pass ? "PASS" : "FAIL");
    free(event.content);
}

/* Regression: validate_event_tags() used to allow tags with unlimited
 * elements, while check_event()'s delegation scanner (parse_tags_json in
 * crypto.c) bails out past MAX_TAG_ELEMENTS elements -- silently skipping
 * delegation signature verification for such events. Both parsers must
 * agree; events carrying oversized tags must be rejected at parse time. */
static void test_event_with_oversized_tag_rejected(void) {
    char *tags = (char *) malloc(65536);
    size_t off = (size_t) snprintf(tags, 65536, "[[");
    for (int i = 0; i < 300; i++)
        off += (size_t) snprintf(tags + off, 65536 - off, "%s\"x\"", i ? "," : "");
    off += (size_t) snprintf(tags + off, 65536 - off, "],"
            "[\"delegation\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
            "\"kind=1\",\"%064d\"]]", 0);
    (void) off;

    char *wire = (char *) malloc(65536 + 512);
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
        json_builder_t *b = (json_builder_t *) malloc(sizeof(json_builder_t));
        json_builder_start(b);
        json_serialize_event(&event, b);
        /* buffer = '[' + '{...}' + ']'  ->  object length = strlen - 2 */
        size_t actual = strlen(json_builder_finish(b)) - 2;
        if (predicted != actual) {
            printf("FAIL: content[%zu] predicted=%zu actual=%zu (%s)\n",
                   i, predicted, actual, contents[i]);
            pass = 0;
        }
        free(b);
        free(event.content);
        free(event.tags_json);
    }
    printf("%s: json_serialized_event_size matches serialization\n", pass ? "PASS" : "FAIL");
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
    printf("json_util security regression tests complete.\n");
    return 0;
}
