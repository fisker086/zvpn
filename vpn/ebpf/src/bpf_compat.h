/* BPF compatibility header - defines stubs for kernel-internal functions/macros
 * that are not available in BPF context but are referenced by kernel headers
 */

#ifndef __BPF_COMPAT_H__
#define __BPF_COMPAT_H__

/* Prevent kernel internals from being included */
#ifndef __BPF__
#define __BPF__
#endif

/* Define GCC attributes early - must be defined before any headers use them */
/* For BPF, we define these as empty since they're optimization hints and BPF has different constraints */
/* Undefine first to ensure clean definition */
#ifdef __attribute_const__
#undef __attribute_const__
#endif
#define __attribute_const__

#ifdef __attribute_pure__
#undef __attribute_pure__
#endif
#define __attribute_pure__

#ifdef __attribute_always_inline__
#undef __attribute_always_inline__
#endif
#define __attribute_always_inline__ __attribute__((__always_inline__))

/* Define missing types that kernel headers expect */
/* Include stdbool.h equivalent definitions */
#ifndef __cplusplus
#ifndef __bool_true_false_are_defined
#define __bool_true_false_are_defined 1
#ifndef bool
#define bool _Bool
#endif
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#endif
#endif

/* Define size_t if not already defined */
#ifndef _SIZE_T
#define _SIZE_T
#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
#ifndef size_t
typedef unsigned long size_t;
#endif
#endif
#endif

/* Prevent problematic kernel header includes by defining include guards early */
#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H
#endif

#ifndef __LINUX_KASAN_CHECKS_H
#define __LINUX_KASAN_CHECKS_H
/* Stub out KASAN checks - use bool to match kernel headers */
static inline bool __kasan_check_read(const volatile void *p, unsigned int size) { return true; }
static inline bool __kasan_check_write(const volatile void *p, unsigned int size) { return true; }
static inline bool kasan_check_read(const volatile void *p, unsigned int size) { return true; }
static inline bool kasan_check_write(const volatile void *p, unsigned int size) { return true; }
#endif

#ifndef __LINUX_KCSAN_CHECKS_H
#define __LINUX_KCSAN_CHECKS_H
/* Stub out KCSAN checks */
static inline void __kcsan_check_access(const volatile void *ptr, size_t size, int type) {}
static inline void kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type, ...) {}
static inline void kcsan_check_access(const volatile void *ptr, size_t size, int type) {}
#endif

/* Stub definitions for kernel-internal functions/macros */
#ifndef unlikely
#define unlikely(x) (x)
#endif

#ifndef likely
#define likely(x) (x)
#endif

#ifndef barrier
#define barrier() ((void)0)
#endif

/* Stub for fls/fls64 - return 0 to avoid errors */
#ifndef fls
#define fls(x) (0)
#endif

#ifndef fls64
#define fls64(x) (0)
#endif

/* Stub for hweight32/hweight64 - return 0 to avoid errors */
#ifndef hweight32
#define hweight32(x) (0)
#endif

#ifndef hweight64
#define hweight64(x) (0)
#endif

/* Stub for bit operations - simplified for BPF */
#ifndef __set_bit
#define __set_bit(nr, addr) ((void)0)
#endif

#ifndef __clear_bit
#define __clear_bit(nr, addr) ((void)0)
#endif

#ifndef set_bit
#define set_bit(nr, addr) ((void)0)
#endif

#ifndef clear_bit
#define clear_bit(nr, addr) ((void)0)
#endif

/* Stub for compiler attributes that aren't available in BPF */
/* These are used as type qualifiers in kernel headers (e.g., "static __no_sanitize_or_inline") */
#ifndef __no_sanitize_or_inline
#define __no_sanitize_or_inline inline
#endif

#ifndef __no_kasan_or_inline
#define __no_kasan_or_inline inline
#endif

#endif /* __BPF_COMPAT_H__ */

