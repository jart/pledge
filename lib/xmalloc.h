#ifndef PLEDGE_LIB_XMALLOC_H_
#define PLEDGE_LIB_XMALLOC_H_

#include "integral.h"
#include <stddef.h>

void *xmalloc(size_t) attributeallocsize((1))
    returnspointerwithnoaliases dontthrow nocallback dontdiscard returnsnonnull;

#endif
