#ifndef PLEDGE_LIB_COPYFD_H_
#define PLEDGE_LIB_COPYFD_H_

#include <sys/types.h>
#include <stddef.h>

ssize_t copyfd(int, int, size_t);

#endif
