#ifndef PLEDGE_LIB_MAX_H_
#define PLEDGE_LIB_MAX_H_

#include "integral.h"

#define max(x, y)              \
  ({                           \
    autotype(x) MaxX = (x);    \
    autotype(y) MaxY = (y);    \
    MaxX > MaxY ? MaxX : MaxY; \
  })

#endif
