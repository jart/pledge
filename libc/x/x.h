#ifndef PLEDGE_LIBC_X_X_H_
#define PLEDGE_LIBC_X_X_H_

#include "libc/integral/c.h"

_Noreturn void xdie(void);
void *xmalloc(size_t);
void *xrealloc(void *, size_t);
char *xstrdup(const char *);
char *xstrcat(const char *, ...);
#define xstrcat(...) (xstrcat)(__VA_ARGS__, NULL)
char *xjoinpaths(const char *, const char *);

#endif
