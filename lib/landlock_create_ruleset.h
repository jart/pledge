#ifndef PLEDGE_LIB_LANDLOCK_CREATE_RULESET_H_
#define PLEDGE_LIB_LANDLOCK_CREATE_RULESET_H_

#include <linux/landlock.h>
#include <stdint.h>
#include <stddef.h>

int landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t,
                            uint32_t);

#endif
