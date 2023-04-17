#ifndef PLEDGE_LIB_CHECKLARGESTACKALLOCATION_H_
#define PLEDGE_LIB_CHECKLARGESTACKALLOCATION_H_

#include "integral.h"
#include <sys/types.h>

forceinline void CheckLargeStackAllocation(void *p, ssize_t n) {
  for (; n > 0; n -= 4096) {
    ((char *)p)[n - 1] = 0;
  }
}

#endif
