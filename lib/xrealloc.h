#ifndef PLEDGE_LIB_XREALLOC_H_
#define PLEDGE_LIB_XREALLOC_H_

#include "integral.h"
#include <stddef.h>

void *xrealloc(void *, size_t)
    attributeallocsize((2)) dontthrow nocallback dontdiscard;

#endif
