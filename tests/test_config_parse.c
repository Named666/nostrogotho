/* Unit tests for the pure half of ng_config.c: line splitting, size parsing,
 * the key table and its ranges, and file loading with error positions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ng_config.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void test_parse_line(void) {
    char b[128], *k = NULL, *v = NULL;
    strcpy(b, "  key =  value  # c\n"); CHECK(ng_config_parse_line(b, &k, &v) == NG_OK && !strcmp(k, "key") && !strcmp(v, "value"));
    strcpy(b, "k=v"); CHECK(ng_config_parse_line(b, &k, &v) == NG_OK && !strcmp(k, "k") && !strcmp(v, "v"));
    strcpy(b, "k ="); CHECK(ng_config_parse_line(b, &k, &v) == NG_OK && !strcmp(v, ""));
    strcpy(b, "   # only a comment"); CHECK(ng_config_parse_line(b, &k, &v) == NG_E_AGAIN);
    strcpy(b, "\n"); CHECK(ng_config_parse_line(b, &k, &v) == NG_E_AGAIN);
    strcpy(b, "novalue\n"); CHECK(ng_config_parse_line(b, &k, &v) == NG_E_INVALID);
    strcpy(b, " = v"); CHECK(ng_config_parse_line(b, &k, &v) == NG_E_INVALID);
    strcpy(b, "a = b = c"); CHECK(ng_config_parse_line(b, &k, &v) == NG_OK && !strcmp(k, "a") && !strcmp(v, "b = c"));
}

static void test_parse_size(void) {
    size_t x = 7;
    CHECK(ng_parse_size("0", 0, 10, &x) && x == 0);
    CHECK(ng_parse_size("4K", 0, (size_t) -1, &x) && x == 4096);
    CHECK(ng_parse_size("4m", 0, (size_t) -1, &x) && x == ((size_t) 4 << 20));
    CHECK(ng_parse_size("1G", 0, (size_t) -1, &x) && x == ((size_t) 1 << 30));
    x = 7;
    CHECK(!ng_parse_size("", 0, 10, &x) && x == 7);
    CHECK(!ng_parse_size("-1", 0, 10, &x) && x == 7);
    CHECK(!ng_parse_size("11", 0, 10, &x) && x == 7);          /* above hi */
    CHECK(!ng_parse_size("1", 2, 10, &x) && x == 7);           /* below lo */
    CHECK(!ng_parse_size("1T", 0, (size_t) -1, &x));           /* unknown suffix */
    CHECK(!ng_parse_size("1KK", 0, (size_t) -1, &x));
    CHECK(!ng_parse_size("99999999999999999999", 0, (size_t) -1, &x));  /* strtoull overflow */
    CHECK(!ng_parse_size("17179869184G", 0, (size_t) -1, &x)); /* x*m would overflow */
    CHECK(!ng_parse_size(NULL, 0, 10, &x));
}

static void test_keys(void) {
    ng_config_t c, d;
    ng_config_defaults(&c);
    CHECK(c.db_sync == NG_DB_SYNC_FULL && c.conn_outbound_max == ((size_t) 4 << 20) &&
          c.total_outbound_max == ((size_t) 1 << 30) && c.worker_queue_max == ((size_t) 16 << 20) &&
          c.writer_queue_max == 65536 && c.conn_pending_max == 1024 && c.io_threads == 0 &&
          c.workers == 0 && c.listen_backlog == 0);
    CHECK(ng_config_set(&c, "db_sync", "normal") == NG_OK && c.db_sync == NG_DB_SYNC_NORMAL);
    CHECK(ng_config_set(&c, "db_sync", "full") == NG_OK && c.db_sync == NG_DB_SYNC_FULL);
    d = c; CHECK(ng_config_set(&c, "db_sync", "off") == NG_E_INVALID && !memcmp(&c, &d, sizeof c));
    CHECK(ng_config_set(&c, "io_threads", "8") == NG_OK && c.io_threads == 8);
    CHECK(ng_config_set(&c, "io_threads", "auto") == NG_OK && c.io_threads == 0);
    CHECK(ng_config_set(&c, "io_threads", "65") == NG_E_RANGE);
    CHECK(ng_config_set(&c, "io_threads", "0") == NG_E_RANGE);
    CHECK(ng_config_set(&c, "workers", "64") == NG_OK && c.workers == 64);
    CHECK(ng_config_set(&c, "listen_backlog", "auto") == NG_OK && c.listen_backlog == 0);
    CHECK(ng_config_set(&c, "listen_backlog", "8192") == NG_OK && c.listen_backlog == 8192);
    CHECK(ng_config_set(&c, "conn_outbound_max", "64K") == NG_OK && c.conn_outbound_max == 65536);
    CHECK(ng_config_set(&c, "conn_outbound_max", "63K") == NG_E_RANGE);
    CHECK(ng_config_set(&c, "total_outbound_max", "2G") == NG_OK && c.total_outbound_max == ((size_t) 2 << 30));
    CHECK(ng_config_set(&c, "worker_queue_max", "1M") == NG_OK && c.worker_queue_max == ((size_t) 1 << 20));
    CHECK(ng_config_set(&c, "writer_queue_max", "16777216") == NG_OK && c.writer_queue_max == 16777216);
    CHECK(ng_config_set(&c, "writer_queue_max", "16777217") == NG_E_RANGE);
    CHECK(ng_config_set(&c, "conn_pending_max", "1") == NG_OK && c.conn_pending_max == 1);
    CHECK(ng_config_set(&c, "no_such_key", "1") == NG_E_UNKNOWN);
}

static void test_load(void) {
    char path[] = "/tmp/ng_cfg_XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0);
    FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
    CHECK(f); if (!f) return;
    fputs("# comment\n\ndb_sync = normal\nworkers = 3 # trailing\nconn_pending_max = nope\nio_threads = 2\n", f);
    fclose(f);
    ng_config_t c; ng_config_error_t e;
    ng_config_defaults(&c);
    CHECK(ng_config_load(&c, path, true, &e) == NG_E_RANGE);
    CHECK(e.line == 5 && !strcmp(e.key, "conn_pending_max") && e.status == NG_E_RANGE);
    CHECK(c.db_sync == NG_DB_SYNC_NORMAL && c.workers == 3 && c.io_threads == 0);   /* stopped at line 5 */
    f = fopen(path, "w"); CHECK(f); if (!f) return;
    fputs("db_sync = normal\nio_threads=auto\n", f); fclose(f);
    ng_config_defaults(&c);
    CHECK(ng_config_load(&c, path, true, &e) == NG_OK && e.line == 0 && c.db_sync == NG_DB_SYNC_NORMAL);
    f = fopen(path, "w"); CHECK(f); if (!f) return;
    for (int i = 0; i < 600; i++) fputc('x', f);
    fputs("\n", f); fclose(f);
    CHECK(ng_config_load(&c, path, true, &e) == NG_E_INVALID && e.line == 1);   /* overlong line */
    remove(path);
    ng_config_defaults(&c);
    CHECK(ng_config_load(&c, path, false, &e) == NG_OK);       /* missing, optional */
    CHECK(ng_config_load(&c, path, true, &e) == NG_E_IO && e.line == 0);
}

static void test_limits_and_info(void) {
    ng_config_t c, d; ng_config_defaults(&c);
    CHECK(c.limits.max_event_tags == 5000 && c.limits.max_subscriptions == 100 && !strcmp(c.info.name, "nostrogotho"));
    CHECK(ng_config_set(&c, "max_event_size", "256K") == NG_OK && c.limits.max_event_size == 256 << 10);
    CHECK(ng_config_set(&c, "max_filters", "65") == NG_E_RANGE);
    CHECK(ng_config_set(&c, "max_event_tags", "0") == NG_E_RANGE);
    CHECK(ng_config_set(&c, "relay_name", "My relay") == NG_OK && !strcmp(c.info.name, "My relay"));
    char longv[300]; memset(longv, 'a', sizeof longv - 1); longv[sizeof longv - 1] = 0;
    d = c; CHECK(ng_config_set(&c, "relay_contact", longv) == NG_E_RANGE && !memcmp(&c, &d, sizeof c));
    CHECK(ng_config_set(&c, "relay_pubkey", "abc") == NG_E_INVALID);
    CHECK(ng_config_set(&c, "relay_pubkey", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ABCDEF") == NG_E_INVALID);
    CHECK(ng_config_set(&c, "relay_pubkey", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == NG_OK && c.info.pubkey[63] == 'f');
    CHECK(ng_config_set(&c, "relay_pubkey", "") == NG_OK && !c.info.pubkey[0]);
    CHECK(ng_config_set(&c, "created_at_upper_limit", "0") == NG_OK && c.info.created_at_upper_limit == 0);
    ng_limits_t l = c.limits; l.max_limit = 100; l.default_limit = 200;
    ng_limits_apply(&l); CHECK(ng_limits.default_limit == 100);    /* default never above max */
    ng_limits_defaults(&l); ng_limits_apply(&l);
}

int main(void) {
    test_parse_line();
    test_parse_size();
    test_keys();
    test_load();
    test_limits_and_info();
    if (fails) { fprintf(stderr, "%d failure(s)\n", fails); return 1; }
    printf("test_config_parse: all passed\n");
    return 0;
}
