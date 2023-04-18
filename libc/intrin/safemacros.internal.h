#ifndef PLEDGE_LIBC_INTRIN_SAFEMACROS_INTERNAL_H_
#define PLEDGE_LIBC_INTRIN_SAFEMACROS_INTERNAL_H_

#include "libc/integral/c.h"

#define max(x, y)              \
  ({                           \
    autotype(x) MaxX = (x);    \
    autotype(y) MaxY = (y);    \
    MaxX > MaxY ? MaxX : MaxY; \
  })

#endif
