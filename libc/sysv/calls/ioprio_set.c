#include "libc/calls/calls.h"

#include <sys/syscall.h>
#include <unistd.h>

int ioprio_set(int which, int who, int ioprio) {
  return syscall(__NR_ioprio_set, which, who, ioprio);
}
