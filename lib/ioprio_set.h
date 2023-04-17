#ifndef PLEDGE_LIB_IOPRIO_SET_H_
#define PLEDGE_LIB_IOPRIO_SET_H_

#include <linux/ioprio.h>

int ioprio_set(int, int, int);

#endif
