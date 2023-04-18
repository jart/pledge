#ifndef PLEDGE_LIBC_RUNTIME_STACK_H_
#define PLEDGE_LIBC_RUNTIME_STACK_H_

#include "libc/integral/c.h"
#include <sys/types.h>

forceinline void CheckLargeStackAllocation(void *p, ssize_t n) {
  for (; n > 0; n -= 4096) {
    ((char *)p)[n - 1] = 0;
  }
}

#endif
