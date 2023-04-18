#ifndef PLEDGE_LIBC_X_X_H_
#define PLEDGE_LIBC_X_X_H_

#include "libc/integral/c.h"

void xdie(void) wontreturn;
void *xmalloc(size_t) attributeallocsize((1))
    returnspointerwithnoaliases dontthrow nocallback dontdiscard returnsnonnull;
void *xrealloc(void *, size_t)
    attributeallocsize((2)) dontthrow nocallback dontdiscard;
char *xstrdup(const char *) paramsnonnull()
    returnspointerwithnoaliases dontthrow nocallback dontdiscard returnsnonnull;
char *xstrcat(const char *, ...) paramsnonnull((1)) nullterminated()
    returnspointerwithnoaliases dontthrow nocallback dontdiscard returnsnonnull;
#define xstrcat(...) (xstrcat)(__VA_ARGS__, 0)
char *xjoinpaths(const char *, const char *) paramsnonnull()
    returnspointerwithnoaliases dontthrow nocallback dontdiscard returnsnonnull;

#endif
