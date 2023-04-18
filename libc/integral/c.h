#ifndef PLEDGE_LIBC_INTEGRAL_C_H_
#define PLEDGE_LIBC_INTEGRAL_C_H_

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef __STRICT_ANSI__
#define pureconst __attribute__((__const__))
#else
#define pureconst
#endif

#if !defined(__STRICT_ANSI__) &&     \
    (__has_attribute(__nonnull__) || \
     (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 403)
#define paramsnonnull(opt_1idxs) __attribute__((__nonnull__ opt_1idxs))
#else
#define paramsnonnull(opt_1idxs)
#endif

#define libcesque dontthrow nocallback

#if defined(__cplusplus) && !defined(__STRICT_ANSI__) && \
    (__has_attribute(dontthrow) ||                       \
     (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 303)
#define dontthrow __attribute__((__nothrow__))
#elif defined(_MSC_VER)
#define dontthrow __declspec(nothrow)
#else
#define dontthrow
#endif

#if !defined(__STRICT_ANSI__) &&  \
    (__has_attribute(__leaf__) || \
     (!defined(__llvm__) &&       \
      (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 406))
#define nocallback __attribute__((__leaf__))
#else
#define nocallback
#endif

#if !defined(__STRICT_ANSI__) && \
    (__has_attribute(__sentinel__) || __GNUC__ + 0 >= 4)
#define nullterminated(x) __attribute__((__sentinel__ x))
#else
#define nullterminated(x)
#endif

#if !defined(__STRICT_ANSI__) &&    \
    (__has_attribute(__malloc__) || \
     (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 409)
#define returnspointerwithnoaliases __attribute__((__malloc__))
#elif defined(_MSC_VER)
#define returnspointerwithnoaliases __declspec(allocator)
#else
#define returnspointerwithnoaliases
#endif

#if !defined(__STRICT_ANSI__) &&                           \
    ((__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 304 || \
     __has_attribute(__warn_unused_result__))
#define dontdiscard __attribute__((__warn_unused_result__))
#else
#define dontdiscard
#endif

#if !defined(__STRICT_ANSI__) &&             \
    (__has_attribute(__returns_nonnull__) || \
     (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 409)
#define returnsnonnull __attribute__((__returns_nonnull__))
#else
#define returnsnonnull
#endif

#if !defined(__STRICT_ANSI__) &&        \
    (__has_attribute(__alloc_size__) || \
     (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 409)
#define attributeallocsize(x) __attribute__((__alloc_size__ x))
#else
#define attributeallocsize(x)
#endif

#ifdef __cplusplus
#define forceinline inline
#else
#if !defined(__STRICT_ANSI__) && \
    (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 302
#if (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 403 || \
    !defined(__cplusplus) ||                              \
    (defined(__clang__) &&                                \
     (defined(__GNUC_STDC_INLINE__) || defined(__GNUC_GNU_INLINE__)))
#if defined(__GNUC_STDC_INLINE__) || defined(__cplusplus)
#define forceinline                                                 \
  static __inline __attribute__((__always_inline__, __gnu_inline__, \
                                 __no_instrument_function__, __unused__))
#else
#define forceinline                                 \
  static __inline __attribute__((__always_inline__, \
                                 __no_instrument_function__, __unused__))
#endif /* __GNUC_STDC_INLINE__ */
#endif /* GCC >= 4.3 */
#elif defined(_MSC_VER)
#define forceinline __forceinline
#else
#define forceinline static inline
#endif /* !ANSI && GCC >= 3.2 */
#endif /* __cplusplus */

#define strlenesque libcesque nosideeffect paramsnonnull()

#if !defined(__STRICT_ANSI__) &&  \
    (__has_attribute(__pure__) || \
     (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 296)
#define nosideeffect __attribute__((__pure__))
#else
#define nosideeffect
#endif

#if __cplusplus + 0 >= 201103L
#define autotype(x) auto
#elif ((__has_builtin(auto_type) || defined(__llvm__) ||       \
        (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 409) && \
       !defined(__chibicc__))
#define autotype(x) __auto_type
#else
#define autotype(x) typeof(x)
#endif

#define privileged

#ifndef __STRICT_ANSI__
#define thatispacked __attribute__((__packed__))
#else
#define thatispacked
#endif

#define notpossible abort()

#if !defined(__STRICT_ANSI__) &&      \
    (__has_attribute(__noreturn__) || \
     (__GNUC__ + 0) * 100 + (__GNUC_MINOR__ + 0) >= 208)
#define wontreturn __attribute__((__noreturn__))
#else
#define wontreturn
#endif

#endif
