/* ng_alloc.h - overflow-checked size arithmetic and allocation.
 *
 * Every allocation whose size is computed from a count or from peer input
 * goes through these helpers: on overflow they fail exactly like an
 * out-of-memory malloc (return false / NULL, errno untouched) instead of
 * allocating a short buffer. Ownership: the returned memory belongs to the
 * caller and is released with free(). Thread-safe (no state).
 */
#ifndef NG_ALLOC_H_
#define NG_ALLOC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

/* *out = a + b / a * b; false (and *out untouched) on size_t overflow. */
static inline bool ng_size_add(size_t a, size_t b, size_t *out) {
    size_t r; if (__builtin_add_overflow(a, b, &r)) return false; *out = r; return true;
}
static inline bool ng_size_mul(size_t a, size_t b, size_t *out) {
    size_t r; if (__builtin_mul_overflow(a, b, &r)) return false; *out = r; return true;
}
/* *out = a + b + c. */
static inline bool ng_size_add3(size_t a, size_t b, size_t c, size_t *out) {
    size_t r; return ng_size_add(a, b, &r) && ng_size_add(r, c, out);
}
/* *out = head + n * elem (struct with a flexible array member). */
static inline bool ng_size_flex(size_t head, size_t n, size_t elem, size_t *out) {
    size_t r; return ng_size_mul(n, elem, &r) && ng_size_add(head, r, out);
}

/* malloc/realloc of n elements of size elem; NULL on overflow or OOM.
 * ng_realloc_array leaves p untouched (still owned by the caller) on failure. */
static inline void *ng_malloc_array(size_t n, size_t elem) {
    size_t s; return ng_size_mul(n, elem, &s) ? malloc(s ? s : 1) : NULL;
}
static inline void *ng_realloc_array(void *p, size_t n, size_t elem) {
    size_t s; return ng_size_mul(n, elem, &s) ? realloc(p, s ? s : 1) : NULL;
}
/* malloc(head + n * elem). */
static inline void *ng_malloc_flex(size_t head, size_t n, size_t elem) {
    size_t s; return ng_size_flex(head, n, elem, &s) ? malloc(s) : NULL;
}
/* malloc(a + b), e.g. a string of length a plus b terminator/extra bytes. */
static inline void *ng_malloc_add(size_t a, size_t b) {
    size_t s; return ng_size_add(a, b, &s) ? malloc(s) : NULL;
}

/* Capacity >= need reached by doubling cur (or min when cur is 0); when
 * doubling would overflow size_t it returns need itself. Callers must still
 * compute need with ng_size_add. For amortized buffer growth. */
static inline size_t ng_grow_cap(size_t cur, size_t need, size_t min) {
    size_t c = cur ? cur : min;
    if (!c) c = 1;
    while (c < need) { if (c > ((size_t) -1) / 2) return need; c *= 2; }
    return c;
}

#endif /* NG_ALLOC_H_ */
