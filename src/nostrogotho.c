#include "nostrogotho.h"
#include "platform/ng_alloc.h"
#include <string.h>
#include <stdio.h>

static void tag_release(tag_t *tag);

/* ============================================================================
 * Event Allocation and Deallocation
 * ============================================================================ */

/* event_alloc - Allocate a new zero-initialized event structure
 * 
 * Allocates and initializes a new event_t on the heap. All fields are
 * zero-initialized: fixed buffers are cleared, pointers are NULL, and
 * numeric fields are 0.
 * 
 * Returns: pointer to new event_t on success, NULL on malloc failure
 * 
 * Caller responsibility: Must call event_free() to release memory
 */
event_t *event_alloc(void) {
    event_t *ev = (event_t *)malloc(sizeof(event_t));
    if (!ev) return NULL;
    
    memset(ev, 0, sizeof(event_t));
    return ev;
}

/* event_release - Release an event's dynamically allocated fields
 * 
 * Frees the heap-allocated fields of an event_t (tags_json and content)
 * and nulls them out. Does NOT free the event_t struct itself, so it is
 * safe to call on stack-allocated events.
 * 
 * Args: ev - pointer to event (NULL-safe, does nothing if NULL)
 */
void event_release(event_t *ev) {
    if (!ev) return;
    
    if (ev->tags_json) {
        free(ev->tags_json);
        ev->tags_json = NULL;
    }
    if (ev->content) {
        free(ev->content);
        ev->content = NULL;
    }
}

/* event_free - Free an event and all its dynamically allocated memory
 * 
 * Safely releases an event_t structure and its contents:
 * - Frees tags_json if allocated
 * - Frees content if allocated
 * - Frees the event structure itself
 * 
 * Args: ev - pointer to event (NULL-safe, does nothing if NULL)
 * Note: Only use for heap-allocated events (from event_alloc()).
 *       For stack-allocated events, use event_release() instead.
 */
void event_free(event_t *ev) {
    if (!ev) return;
    
    event_release(ev);
    free(ev);
}

/* ============================================================================
 * Filter Allocation and Deallocation
 * ============================================================================ */

/* filter_alloc - Allocate a new zero-initialized filter structure
 * 
 * Creates a new filter_t on the heap with all fields initialized to zero:
 * pointer arrays are NULL, counts are 0, and limit defaults to 0.
 * 
 * Returns: pointer to new filter_t on success, NULL on malloc failure
 * 
 * Caller responsibility: Must call filter_free() to release memory
 */
filter_t *filter_alloc(void) {
    filter_t *f = (filter_t *)malloc(sizeof(filter_t));
    if (!f) return NULL;
    
    memset(f, 0, sizeof(filter_t));
    return f;
}

/* filter_release - Release a filter's dynamically allocated fields
 *
 * Frees ids/authors/kinds/tags/search and nulls them out. Does NOT free the
 * filter_t struct itself, so it is safe for stack-allocated filters.
 */
void filter_release(filter_t *f) {
    if (!f) return;

    if (f->ids) {
        for (size_t i = 0; i < f->ids_count; i++) {
            free(f->ids[i]);
        }
        free(f->ids);
        f->ids = NULL;
        f->ids_count = 0;
    }

    if (f->authors) {
        for (size_t i = 0; i < f->authors_count; i++) {
            free(f->authors[i]);
        }
        free(f->authors);
        f->authors = NULL;
        f->authors_count = 0;
    }

    if (f->kinds) {
        free(f->kinds);
        f->kinds = NULL;
        f->kinds_count = 0;
    }

    if (f->tags) {
        for (size_t i = 0; i < f->tags_count; i++) {
            tag_release(&f->tags[i]);
        }
        free(f->tags);
        f->tags = NULL;
        f->tags_count = 0;
    }

    if (f->search) {
        free(f->search);
        f->search = NULL;
    }
}

/* filter_free - Free a filter and all its dynamically allocated memory
 * 
 * Recursively frees all arrays and strings within a filter:
 * - Frees each id string, then ids array
 * - Frees each author string, then authors array
 * - Frees kinds array
 * - Frees each tag and tags array
 * - Frees search string
 * - Frees the filter structure itself
 * 
 * Args: f - pointer to filter (NULL-safe, does nothing if NULL)
 */
void filter_free(filter_t *f) {
    if (!f) return;

    filter_release(f);
    free(f);
}

/* ============================================================================
 * Tag Allocation and Deallocation
 * ============================================================================ */

/* tag_alloc - Allocate a tag structure with capacity for element_count elements
 * 
 * Creates a new tag_t with a pre-allocated elements array. The tag is
 * initialized with count=0 (no elements yet), but can hold up to
 * element_count string pointers.
 * 
 * Args: element_count - maximum number of elements this tag can hold
 * Returns: pointer to new tag_t on success, NULL on malloc failure
 * 
 * Caller responsibility: Must call tag_free() to release memory
 * 
 * Note: The caller should populate elements array and increment count as needed
 */
tag_t *tag_alloc(size_t element_count) {
    tag_t *tag = (tag_t *)malloc(sizeof(tag_t));
    if (!tag) return NULL;
    
    tag->elements = (char **) ng_malloc_array(element_count, sizeof(char *));
    if (!tag->elements) {
        free(tag);
        return NULL;
    }
    
    tag->count = 0;
    tag->capacity = element_count;
    memset(tag->elements, 0, element_count * sizeof(char *));
    return tag;
}

static void tag_release(tag_t *tag) {
    if (!tag) return;

    if (tag->elements) {
        for (size_t i = 0; i < tag->count; i++) {
            free(tag->elements[i]);
        }
        free(tag->elements);
    }
    tag->elements = NULL;
    tag->count = 0;
    tag->capacity = 0;
}

/* tag_free - Free a tag and all its element strings
 * 
 * Recursively releases a tag_t and all its contents:
 * - Frees each element string in the elements array
 * - Frees the elements array itself
 * - Frees the tag structure
 * 
 * Args: tag - pointer to tag (NULL-safe, does nothing if NULL)
 */
void tag_free(tag_t *tag) {
    if (!tag) return;
    tag_release(tag);
    free(tag);
}

/* ============================================================================
 * Tag Array Allocation and Deallocation
 * ============================================================================ */

/* tags_array_alloc - Allocate a tags array with capacity for tag_count tags
 * 
 * Creates a new tags_array_t with a pre-allocated tags array. The array is
 * initialized with count=0 (no tags yet), but can hold up to tag_count
 * tag_t structures.
 * 
 * Args: tag_count - maximum number of tags this array can hold
 * Returns: pointer to new tags_array_t on success, NULL on malloc failure
 * 
 * Caller responsibility: Must call tags_array_free() to release memory
 */
tags_array_t *tags_array_alloc(size_t tag_count) {
    tags_array_t *tags = (tags_array_t *)malloc(sizeof(tags_array_t));
    if (!tags) return NULL;
    
    tags->tags = (tag_t *) ng_malloc_array(tag_count, sizeof(tag_t));
    if (!tags->tags) {
        free(tags);
        return NULL;
    }
    
    tags->count = 0;
    memset(tags->tags, 0, tag_count * sizeof(tag_t));
    return tags;
}

/* tags_array_free - Free a tags array and all its contained tags
 * 
 * Recursively releases a tags_array_t and all its contents:
 * - Frees each tag_t in the tags array
 * - Frees the tags array itself
 * - Frees the tags_array_t structure
 * 
 * Args: tags - pointer to tags array (NULL-safe, does nothing if NULL)
 */
void tags_array_free(tags_array_t *tags) {
    if (!tags) return;
    
    if (tags->tags) {
        for (size_t i = 0; i < tags->count; i++) {
            tag_release(&tags->tags[i]);
        }
        free(tags->tags);
    }
    
    free(tags);
}

/* ============================================================================
 * String Utility Functions
 * ============================================================================ */

/* string_dup - Duplicate a null-terminated string
 * 
 * Creates a malloc'd copy of the input string. Useful for storing string
 * values that need separate ownership (e.g., in event IDs, pubkeys).
 * 
 * Args: str - null-terminated string to duplicate (NULL-safe)
 * Returns: malloc'd copy on success, NULL if str is NULL or malloc fails
 * 
 * Caller responsibility: Must call string_free() to release the copy
 */
char *string_dup(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str);
    char *dup = (char *) ng_malloc_add(len, 1);
    if (!dup) return NULL;
    
    strcpy(dup, str);
    return dup;
}

/* string_free - Free a duplicated string
 * 
 * Safely releases memory allocated by string_dup().
 * 
 * Args: str - pointer to malloc'd string (NULL-safe, does nothing if NULL)
 */
void string_free(char *str) {
    free(str);
}


/* ============================================================================
 * NIP-50 search terms (see nostrogotho.h)
 * ============================================================================ */

bool ng_search_kind(int kind) {
    switch (kind) {
    case 4: case 13: case 1059: case 1060: case 21059: case 22242: case 24133: return false;
    default: return true;
    }
}

static bool term_byte(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80;
}

static bool space_byte(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

/* A whitespace-delimited word "key:value" with a letters/digits/_/- key
 * and a non-empty value: a NIP-50 extension. */
static bool extension_word(const char *w, size_t n) {
    size_t i = 0;
    while (i < n && (term_byte((unsigned char) w[i]) || w[i] == '_' || w[i] == '-')) i++;
    return i > 0 && i + 1 < n && w[i] == ':';
}

/* Call fn(term, len, arg) for each term of search; stops early when fn
 * returns false. Returns false iff fn did. */
static bool each_term(const char *search, bool (*fn)(const char *, size_t, void *), void *arg) {
    const char *p = search ? search : "";
    while (*p) {
        while (*p && space_byte((unsigned char) *p)) p++;
        const char *w = p;
        while (*p && !space_byte((unsigned char) *p)) p++;
        size_t n = (size_t) (p - w);
        if (n == 0 || extension_word(w, n)) continue;
        for (size_t i = 0; i < n;) {
            while (i < n && !term_byte((unsigned char) w[i])) i++;
            size_t s = i;
            while (i < n && term_byte((unsigned char) w[i])) i++;
            if (i > s && !fn(w + s, i - s, arg)) return false;
        }
    }
    return true;
}

static bool stop_at_first(const char *t, size_t n, void *arg) { (void) t; (void) n; *(bool *) arg = true; return false; }

bool ng_search_has_terms(const char *search) {
    bool any = false;
    each_term(search, stop_at_first, &any);
    return any;
}

typedef struct { char *buf; size_t len, cap; bool oom; } fts_out_t;

static bool fts_append(const char *t, size_t n, void *arg) {
    fts_out_t *o = (fts_out_t *) arg;
    size_t need;   /* separator + quotes + term (no '"' inside: not a term byte) + NUL */
    if (!ng_size_add3(o->len, n, 4, &need)) { o->oom = true; return false; }
    if (need > o->cap) {
        size_t cap = o->cap ? o->cap : 64;
        while (cap < need) { if (!ng_size_mul(cap, 2, &cap)) { o->oom = true; return false; } }
        char *b = (char *) realloc(o->buf, cap);
        if (!b) { o->oom = true; return false; }
        o->buf = b; o->cap = cap;
    }
    if (o->len) o->buf[o->len++] = ' ';
    o->buf[o->len++] = '"';
    memcpy(o->buf + o->len, t, n); o->len += n;
    o->buf[o->len++] = '"';
    o->buf[o->len] = '\0';
    return true;
}

char *ng_search_fts_query(const char *search) {
    fts_out_t o = { NULL, 0, 0, false };
    each_term(search, fts_append, &o);
    if (o.oom || o.len == 0) { free(o.buf); return NULL; }
    return o.buf;
}

typedef struct { const char *content; size_t len; } live_t;

static unsigned char fold(unsigned char c) { return (c >= 'A' && c <= 'Z') ? (unsigned char) (c + 32) : c; }

/* term occurs in content as a whole term (bounded by non-term bytes). */
static bool live_term(const char *t, size_t n, void *arg) {
    const live_t *l = (const live_t *) arg;
    const unsigned char *c = (const unsigned char *) l->content;
    for (size_t i = 0; i < l->len;) {
        while (i < l->len && !term_byte(c[i])) i++;
        size_t s = i;
        while (i < l->len && term_byte(c[i])) i++;
        if (i - s != n) continue;
        size_t k = 0;
        while (k < n && fold(c[s + k]) == fold((unsigned char) t[k])) k++;
        if (k == n) return true;
    }
    return false;
}

bool ng_search_match(const char *search, int kind, const char *content, size_t content_len) {
    if (!ng_search_has_terms(search)) return true;
    if (!ng_search_kind(kind)) return false;
    live_t l = { content ? content : "", content ? content_len : 0 };
    return each_term(search, live_term, &l);
}
