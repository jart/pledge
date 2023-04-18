#ifndef PLEDGE_LIBC_RUNTIME_RUNTIME_H_
#define PLEDGE_LIBC_RUNTIME_RUNTIME_H_

#include <stdbool.h>
#include "libc/integral/c.h"

unsigned getcpucount(void) pureconst;
bool _IsDynamicExecutable(const char *);

#endif
