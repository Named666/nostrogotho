/* ============================================================================
 * Fuzz tests for src/json_util.c: json_array_parse + json_parse_event
 * (+ json_parse_filter as a bonus target — same harness).
 *
 * NIPs: NIP-01 (REQ, EVENT, AUTH, COUNT message format), NIP-42 (AUTH), NIP-45 (COUNT)
 * Spec sections: NIP-01 § "Communication", NIP-42 § "Authentication Flow", NIP-45 § "COUNT"
 * PLAN.md sections: §1.5 (Protocol/Transport Boundary), §1.6 (Composable REQ filter -> SQL)
 *
 * Deterministic structured fuzzing: a fixed-seed xorshift64* PRNG mutates a
 * corpus of real protocol frames. No sanitizer is available in this
 * toolchain, so the harness leans on checkable invariants instead:
 *   - parse results stay within bounds (count <= max, enum range, lengths)
 *   - free functions survive every parse outcome
 *   - parsing is deterministic (same input twice => identical result)
 *   - Windows heap integrity is probed periodically via _heapchk()
 * Any violation prints the failing input (escaped) and exits nonzero.
 * Reproduce: build/test_json_fuzz(.exe) [iterations] [seed] [-v] [only-N]
 *   only-N reruns a single mutated case; a sixth argument reruns one
 *   baseline seed through all three targets (debug aid).
 *
 * Build (from repo root, mirroring nob flags):
 *   gcc -std=c99 -O1 -Ibuild -I. -Isrc ... -o build/test_json_fuzz(.exe)
 *   tests/test_json_fuzz.c src/json_util.c src/nostrogotho.c
 *   thirdparty/mongoose/mongoose.c -lws2_32
 * ============================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "json_util.h"

#ifdef _WIN32
#include <malloc.h>
#endif

static int g_fail = 0;
static unsigned long g_cases = 0;

/* --- Deterministic PRNG (xorshift64*) --- */
static uint64_t rng_state = 0x123456789abcdefULL;

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* SplitMix64: derives the per-case PRNG state, so case N is a pure
 * function of (master seed, N) and any failure reproduces via
 * `test_json_fuzz 1 <seed> -v <N>`. */
static uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

static size_t rng_range(size_t n) {
    return n == 0 ? 0 : (size_t)(rng_next() % (uint64_t)n);
}

/* --- Corpus: real protocol frames + pathological edges --- */
static const char *seeds[] = {
    "[\"REQ\",\"sub1\",{\"kinds\":[1]}]",
    "[\"REQ\",\"s\",{\"ids\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"],\"authors\":[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"],\"kinds\":[1,4],\"#p\":[\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"],\"since\":100,\"until\":200,\"limit\":10}]",
    "[\"EVENT\",{\"id\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"pubkey\":\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\",\"created_at\":1700000000,\"kind\":1,\"tags\":[[\"p\",\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"]],\"content\":\"hello\",\"sig\":\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}]",
    "[\"COUNT\",\"c1\",{\"kinds\":[1]}]",
    "[\"CLOSE\",\"sub1\"]",
    "[\"AUTH\",{\"id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"pubkey\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"created_at\":1700000000,\"kind\":22242,\"tags\":[[\"relay\",\"ws://x\"],[\"challenge\",\"abcd\"]],\"content\":\"\",\"sig\":\"33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333\"}]",
    "[\"EVENT\",{\"id\":\"short\",\"pubkey\":\"x\",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"y\"}]",
    "{}",
    "[]",
    "[[]]",
    "[[[[[[[[[[[]]]]]]]]]]",
    "[\"REQ\",\"s\",{}]",
    "{\"ids\":[]}",
    "[\"EVENT\",{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"pubkey\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"created_at\":1700000000,\"kind\":1,\"tags\":[[\"e\",\"a\",\"b\",\"c\",\"d\",\"e\",\"f\"]],\"content\":\"caf\\u00e9 \\ud83d\\ude00 \\/ \\b\\f\\n\\r\\t\\\"\\\\\",\"sig\":\"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222\"}]",
    "[\"REQ\",\"\\ud83d\\ude00\",{\"search\":\"\\b\\f\"}]",
    "[\"EVENT\",null]",
    "null",
    "123",
    "\"lone string\"",
    "[\"REQ\"]",
    "[\"REQ\",\"s\",\"not-an-object\"]",
    "[\"REQ\",\"s\",null,{\"kinds\":[1]}]",
    "[\"REQ\",\"s\",{\"kinds\":[-1,2147483647,2147483648,9999999999999999999]}]",
    "[\"REQ\",\"s\",{\"since\":-5,\"until\":0,\"limit\":-1}]",
    "[\"REQ\",\"s\",{\"limit\":999999999999}]",
    "[\"REQ\",\"s\",{\"#p\":[]}]",
    "[\"REQ\",\"s\",{\"#x\":[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]}]",
    "[\"REQ\",\"s\",{\"authors\":[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"]}]",
    "[\"REQ\",\"s\",{\"ids\":[\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"]}]",
    "[\"EVENT\",{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"pubkey\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"created_at\":1.5,\"kind\":1.0,\"tags\":{},\"content\":[],\"sig\":\"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222\"}]",
    "[\"AUTH\",\"challenge-string\"]",
    "[\"NOTICE\",\"hello\"]",
    "[\"OK\",\"id\",true,\"\"]",
    "[\"EOSE\",\"sub\"]",
    "[\"CLOSED\",\"sub\",\"auth-required: nope\"]",
    "{\"id\":\"x\"}",
    "[\"EVENT\",{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"pubkey\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"created_at\":9223372036854775807,\"kind\":-2147483648,\"tags\":[],\"content\":\"\",\"sig\":\"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222\"}]",
};

#define MAX_INPUT 2048

static const char alphabet[] =
    "[]{}}\",:. \t\n\r0123456789abcdefABCDEF\\uNULtnulltruefs-+#p intensive";

static void mutate(const char *seed, char *out, size_t outsz) {
    size_t seed_len = strlen(seed);
    size_t len = seed_len < outsz - 1 ? seed_len : outsz - 1;
    memcpy(out, seed, len);
    out[len] = '\0';
    /* 1-4 mutation ops per case. */
    size_t ops = 1 + rng_range(4);
    for (size_t o = 0; o < ops; o++) {
        switch (rng_range(6)) {
        case 0: { /* random byte poke from the alphabet */
            if (len == 0) break;
            out[rng_range(len)] = alphabet[rng_range(sizeof(alphabet) - 1)];
            break;
        }
        case 1: /* truncate (possibly to empty) */
            len = rng_range(len + 1);
            out[len] = '\0';
            break;
        case 2: { /* duplicate a random span */
            if (len == 0) break;
            size_t at = rng_range(len);
            size_t span = 1 + rng_range(len - at > 16 ? 16 : (len - at ? len - at : 1));
            if (len + span >= outsz) break;
            memmove(out + at + span, out + at, len - at + 1);
            memcpy(out + at, out + at + span, span);
            len += span;
            break;
        }
        case 3: { /* insert alphabet soup */
            size_t n = 1 + rng_range(12);
            size_t at = rng_range(len + 1);
            if (len + n >= outsz) break;
            memmove(out + at + n, out + at, len - at + 1);
            for (size_t i = 0; i < n; i++)
                out[at + i] = alphabet[rng_range(sizeof(alphabet) - 1)];
            len += n;
            break;
        }
        case 4: { /* splice in a chunk of another seed */
            const char *other = seeds[rng_range(sizeof(seeds) / sizeof(seeds[0]))];
            size_t olen = strlen(other);
            if (olen == 0 || len == 0) break;
            size_t oat = rng_range(olen);
            size_t span = 1 + rng_range(olen - oat > 24 ? 24 : (olen - oat ? olen - oat : 1));
            size_t at = rng_range(len + 1);
            if (len + span >= outsz) break;
            memmove(out + at + span, out + at, len - at + 1);
            memcpy(out + at, other + oat, span);
            len += span;
            break;
        }
        default: { /* NUL byte injection */
            if (len + 1 >= outsz) break;
            out[rng_range(len + 1)] = '\0';
            break;
        }
        }
    }
}

static void print_escaped(const char *s, size_t maxlen) {
    size_t n = 0;
    putchar('"');
    for (; *s && n < maxlen; s++, n++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c >= 32 && c < 127) {
            putchar(c);
        } else {
            printf("\\x%02x", c);
        }
    }
    if (*s) printf("...<%zu more>", strlen(s) - n);
    putchar('"');
}

#define FAIL(...)                                                             \
    do {                                                                      \
        printf("FAIL(case %lu): ", g_cases);                                  \
        printf(__VA_ARGS__);                                                  \
        printf("\n  input=");                                                 \
        print_escaped(input, 256);                                            \
        printf("\n");                                                         \
        g_fail++;                                                             \
        if (g_fail > 5) {                                                     \
            printf("too many failures, aborting\n");                          \
            exit(1);                                                          \
        }                                                                     \
    } while (0)

/* Invariant: string slots hold NULL or readable C strings. Other types
 * share the union storage (e.g. a bool leaves a nonzero pattern where the
 * pointer sits), so only STRING/ARRAY/OBJECT slots may be dereferenced --
 * mirroring json_array_free's own condition. */
static int values_sane(const json_value_t *values, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (values[i].type < JSON_TYPE_NULL || values[i].type > JSON_TYPE_OBJECT)
            return 0;
        if ((values[i].type == JSON_TYPE_STRING ||
             values[i].type == JSON_TYPE_ARRAY ||
             values[i].type == JSON_TYPE_OBJECT) &&
            values[i].value.string_val) {
            volatile size_t n = strlen(values[i].value.string_val);
            (void)n;
        }
    }
    return 1;
}

static void fuzz_array_parse(const char *input) {
    json_value_t a[128], b[128];
    size_t na, nb;
    g_cases++;

    na = json_array_parse(input, a, 128);
    if (na > 128) {
        FAIL("json_array_parse returned %zu > max 128", na);
        return;
    }
    if (!values_sane(a, na)) {
        FAIL("json_array_parse produced insane value slots");
        json_array_free(a, na);
        return;
    }
    /* Determinism: parse twice, compare counts + types + strings. */
    nb = json_array_parse(input, b, 128);
    if (nb != na) {
        FAIL("nondeterministic count %zu vs %zu", na, nb);
        json_array_free(a, na);
        json_array_free(b, nb);
        return;
    }
    for (size_t i = 0; i < na; i++) {
        if (a[i].type != b[i].type) {
            FAIL("nondeterministic type at slot %zu", i);
            break;
        }
        /* Compare payloads only for string-carrying types (other types
         * share the union storage; see values_sane). */
        if (a[i].type != JSON_TYPE_STRING && a[i].type != JSON_TYPE_ARRAY &&
            a[i].type != JSON_TYPE_OBJECT)
            continue;
        const char *sa = a[i].value.string_val;
        const char *sb = b[i].value.string_val;
        if ((sa == NULL) != (sb == NULL) || (sa && strcmp(sa, sb) != 0)) {
            FAIL("nondeterministic string at slot %zu", i);
            break;
        }
    }
    json_array_free(a, na);
    json_array_free(b, nb);
}

static int events_equal(const event_t *a, const event_t *b) {
    if (strcmp(a->id, b->id) != 0) return 0;
    if (strcmp(a->pubkey, b->pubkey) != 0) return 0;
    if (strcmp(a->sig, b->sig) != 0) return 0;
    if (a->created_at != b->created_at || a->kind != b->kind) return 0;
    if ((a->content == NULL) != (b->content == NULL)) return 0;
    if (a->content && strcmp(a->content, b->content) != 0) return 0;
    if ((a->tags_json == NULL) != (b->tags_json == NULL)) return 0;
    if (a->tags_json && strcmp(a->tags_json, b->tags_json) != 0) return 0;
    return 1;
}

static void fuzz_parse_event(const char *input) {
    event_t e1, e2;
    bool r1, r2;
    g_cases++;

    memset(&e1, 0, sizeof(e1));
    memset(&e2, 0, sizeof(e2));
    r1 = json_parse_event(input, &e1);
    r2 = json_parse_event(input, &e2);
    if (r1 != r2) {
        FAIL("nondeterministic verdict %d vs %d", (int)r1, (int)r2);
        if (r1) event_release(&e1);
        if (r2) event_release(&e2);
        return;
    }
    if (r1) {
        /* Field sanity: fixed buffers must be NUL-terminated in range. */
        if (strlen(e1.id) > MAX_ID_SIZE || strlen(e1.pubkey) > MAX_PUBKEY_SIZE ||
            strlen(e1.sig) > MAX_SIG_SIZE) {
            FAIL("event fixed field overruns its buffer");
        } else if (!events_equal(&e1, &e2)) {
            FAIL("nondeterministic event parse");
        }
        event_release(&e1);
        event_release(&e2);
    }
}

static void fuzz_parse_filter(const char *input) {
    filter_t f1, f2;
    bool r1, r2;
    g_cases++;

    memset(&f1, 0, sizeof(f1));
    memset(&f2, 0, sizeof(f2));
    r1 = json_parse_filter(input, &f1);
    r2 = json_parse_filter(input, &f2);
    if (r1 != r2) {
        FAIL("nondeterministic filter verdict %d vs %d", (int)r1, (int)r2);
        if (r1) filter_release(&f1);
        if (r2) filter_release(&f2);
        return;
    }
    if (r1) {
        if (f1.ids_count > 256 || f1.authors_count > 256 || f1.kinds_count > 256 ||
            f1.tags_count > 256) {
            FAIL("filter counts exceed documented caps");
        }
        filter_release(&f1);
        filter_release(&f2);
    }
}

int main(int argc, char **argv) {
    unsigned long iters = 200000;
    uint64_t seed = 0x123456789abcdefULL;
    char input[MAX_INPUT + 1];
    size_t nseeds = sizeof(seeds) / sizeof(seeds[0]);
    clock_t start = clock();
    int verbose = 0;
    long only = -1;

    if (argc > 1) iters = strtoul(argv[1], NULL, 10);
    if (argc > 2) seed = strtoull(argv[2], NULL, 0);
    if (argc > 3 && strcmp(argv[3], "-v") == 0) verbose = 1;
    if (argc > 4) only = strtol(argv[4], NULL, 10);
    if (argc > 5) {
        /* Debug mode: run one baseline seed (all three targets) and exit. */
        long b = strtol(argv[5], NULL, 10);
        if (b >= 0 && (size_t)b < nseeds) {
            fuzz_array_parse(seeds[b]);
            fuzz_parse_event(seeds[b]);
            fuzz_parse_filter(seeds[b]);
        }
        printf("baseline-seed %ld done, failures=%d\n", b, g_fail);
        return g_fail ? 1 : 0;
    }
    if (iters == 0) iters = 1;
    rng_state = seed ? seed : 1;

    /* Baseline: every seed must parse without tripping invariants. */
    for (size_t i = 0; i < nseeds; i++) {
        if (verbose) fprintf(stderr, "baseline %lu/%lu\n", (unsigned long)i,
                             (unsigned long)nseeds);
        fuzz_array_parse(seeds[i]);
        fuzz_parse_event(seeds[i]);
        fuzz_parse_filter(seeds[i]);
        if (g_fail) return 1;
    }

    for (unsigned long i = 0; i < iters && !g_fail; i++) {
        if (verbose && (i & 1023) == 0)
            fprintf(stderr, "iter %lu/%lu cases=%lu\n", i, iters, g_cases);
        /* Reseed per case: case i is reproducible in isolation. */
        rng_state = splitmix64(seed + i * 0x9E3779B97F4A7C15ULL);
        if (rng_state == 0) rng_state = 1;
        if (only >= 0 && (long)i != only) continue;
        mutate(seeds[rng_range(nseeds)], input, sizeof(input));
        switch (rng_range(3)) {
        case 0: fuzz_array_parse(input); break;
        case 1: fuzz_parse_event(input); break;
        default: fuzz_parse_filter(input); break;
        }
#ifdef _WIN32
        /* Periodic heap-integrity probe (no sanitizer in this toolchain). */
        if ((i & 4095) == 4095 && _heapchk() != _HEAPOK) {
            FAIL("Windows heap corruption detected");
            return 1;
        }
#endif
    }

    {
        double secs = (double)(clock() - start) / CLOCKS_PER_SEC;
        printf("fuzz: %lu cases (%.0f/sec), %d failures [seed=0x%llx]\n",
               g_cases, secs > 0 ? g_cases / secs : 0.0, g_fail,
               (unsigned long long)seed);
    }
    return g_fail ? 1 : 0;
}
