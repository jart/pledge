#ifndef PLEDGE_LIBC_CALLS_PLEDGE_INTERNAL_H_
#define PLEDGE_LIBC_CALLS_PLEDGE_INTERNAL_H_

#include "libc/calls/pledge.h"
#include "libc/intrin/promises.internal.h"
#include <stdint.h>
#include <stddef.h>

struct Pledges {
  const char *name;
  const uint16_t *syscalls;
  const size_t len;
};

extern const struct Pledges kPledge[PROMISE_LEN_];

int sys_pledge_linux(unsigned long, int);
int ParsePromises(const char *, unsigned long *);

#endif
