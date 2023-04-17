#ifndef PLEDGE_LIB_LANDLOCK_RESTRICT_SELF_H_
#define PLEDGE_LIB_LANDLOCK_RESTRICT_SELF_H_

#include <stdint.h>

int landlock_restrict_self(int, uint32_t);

#endif
