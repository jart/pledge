#ifndef PLEDGE_LIBC_STR_PATH_H_
#define PLEDGE_LIBC_STR_PATH_H_

#include "libc/integral/c.h"
#include <stdbool.h>

#define _kPathAbs  1
#define _kPathDev  2
#define _kPathRoot 4
#define _kPathDos  8
#define _kPathWin  16
#define _kPathNt   32

int classifypath(const char *) libcesque nosideeffect;
bool isabspath(const char *) libcesque strlenesque;
char *joinpaths(char *, size_t, const char *, const char *);

#endif
