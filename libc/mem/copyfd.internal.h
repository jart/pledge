#ifndef PLEDGE_LIBC_MEM_COPYFD_INTERNAL_H_
#define PLEDGE_LIBC_MEM_COPYFD_INTERNAL_H_

#include <sys/types.h>
#include <stddef.h>

ssize_t copyfd(int, int, size_t);

#endif
