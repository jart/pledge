#ifndef PLEDGE_LIBC_INTRIN_LIKELY_H_
#define PLEDGE_LIBC_INTRIN_LIKELY_H_

#ifndef __STRICT_ANSI__
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x)
#define UNLIKELY(x)
#endif

#endif
