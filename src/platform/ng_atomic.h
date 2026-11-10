/* ng_atomic.h - atomics for the C99 + GCC/Clang __atomic contract.
 *
 * Replaces <stdatomic.h> (C11). Each atomic type is a one-member struct so a
 * plain read or write of the value does not compile: every access goes
 * through these macros and names its memory order. The generated code is
 * identical to <stdatomic.h> (both lower to the same __atomic builtins).
 *
 *   ng_atomic_load(p)                 seq_cst load of *p
 *   ng_atomic_load_explicit(p, mo)    load with order mo (NG_MO_*)
 *   ng_atomic_store[_explicit](p, v[, mo])
 *   ng_atomic_fetch_add/sub[_explicit](p, v[, mo])   returns the old value
 *   ng_atomic_exchange(p, v)          seq_cst, returns the old value
 *   ng_atomic_cas_weak_explicit(p, &expected, v, mo_ok, mo_fail)
 *   ng_atomic_init(p, v)              plain store; only before the object
 *                                     is visible to another thread
 * p is a pointer to one of the ng_atomic_* types below.
 */
#ifndef NG_ATOMIC_H_
#define NG_ATOMIC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NG_MO_RELAXED __ATOMIC_RELAXED
#define NG_MO_ACQUIRE __ATOMIC_ACQUIRE
#define NG_MO_RELEASE __ATOMIC_RELEASE
#define NG_MO_ACQ_REL __ATOMIC_ACQ_REL
#define NG_MO_SEQ_CST __ATOMIC_SEQ_CST

typedef struct { int v; } ng_atomic_int;
typedef struct { unsigned v; } ng_atomic_uint;
typedef struct { bool v; } ng_atomic_bool;
typedef struct { size_t v; } ng_atomic_size;
typedef struct { long long v; } ng_atomic_llong;
typedef struct { unsigned long long v; } ng_atomic_ullong;

#define ng_atomic_init(p, x)                   ((void) ((p)->v = (x)))
#define ng_atomic_load_explicit(p, mo)         __atomic_load_n(&(p)->v, mo)
#define ng_atomic_load(p)                      ng_atomic_load_explicit(p, NG_MO_SEQ_CST)
#define ng_atomic_store_explicit(p, x, mo)     __atomic_store_n(&(p)->v, (x), mo)
#define ng_atomic_store(p, x)                  ng_atomic_store_explicit(p, x, NG_MO_SEQ_CST)
#define ng_atomic_fetch_add_explicit(p, x, mo) __atomic_fetch_add(&(p)->v, (x), mo)
#define ng_atomic_fetch_add(p, x)              ng_atomic_fetch_add_explicit(p, x, NG_MO_SEQ_CST)
#define ng_atomic_fetch_sub_explicit(p, x, mo) __atomic_fetch_sub(&(p)->v, (x), mo)
#define ng_atomic_fetch_sub(p, x)              ng_atomic_fetch_sub_explicit(p, x, NG_MO_SEQ_CST)
#define ng_atomic_exchange(p, x)               __atomic_exchange_n(&(p)->v, (x), NG_MO_SEQ_CST)
/* Weak CAS: if *p == *expected store x and return true, else load *p into
 * *expected and return false (may fail spuriously: call in a loop). */
#define ng_atomic_cas_weak_explicit(p, expected, x, mo_ok, mo_fail) \
    __atomic_compare_exchange_n(&(p)->v, (expected), (x), true, mo_ok, mo_fail)

#endif /* NG_ATOMIC_H_ */
