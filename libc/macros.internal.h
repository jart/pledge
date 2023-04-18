#ifndef PLEDGE_LIBC_MACROS_INTERNAL_H_
#define PLEDGE_LIBC_MACROS_INTERNAL_H_

#define ROUNDUP(X, K) (((X) + (K)-1) & -(K))
#define ARRAYLEN(A) \
  ((sizeof(A) / sizeof(*(A))) / ((unsigned)!(sizeof(A) % sizeof(*(A)))))

#endif
