/* ng_platform.h - the compiler/platform contract in one place (see PLATFORM.md).
 *
 * Contract: ISO C99 (built as gnu99) + POSIX.1-2008 threads/sockets + the
 * GCC/Clang extensions named below. Every extension our code relies on is
 * spelled through a macro or inline function from this header (or
 * ng_atomic.h / ng_alloc.h), so a port to another compiler only touches
 * src/platform/. Nothing here allocates or has state.
 */
#ifndef NG_PLATFORM_H_
#define NG_PLATFORM_H_

#include <stdint.h>

#if !defined(__GNUC__) && !defined(__clang__)
#error "nostrogotho requires GCC or Clang (see PLATFORM.md)"
#endif

/* Thread-local storage (GNU __thread; C11 _Thread_local is not in C99). */
#define NG_THREAD_LOCAL __thread

/* Object alignment, e.g. to keep a hot atomic on its own cache line. */
#define NG_ALIGNED(n) __attribute__((aligned(n)))
#define NG_CACHELINE 64

/* Branch hints for the few measured hot paths. */
#define NG_LIKELY(x)   __builtin_expect(!!(x), 1)
#define NG_UNLIKELY(x) __builtin_expect(!!(x), 0)

#define NG_UNUSED __attribute__((unused))

/* Compile-time assertion (C99: negative array size on failure). */
#define NG_STATIC_ASSERT(cond, tag) typedef char ng_static_assert_##tag[(cond) ? 1 : -1] NG_UNUSED

/* Index of the lowest set bit of a nonzero 64-bit mask. */
static inline int ng_ctz64(uint64_t m) { return __builtin_ctzll(m); }

#endif /* NG_PLATFORM_H_ */
