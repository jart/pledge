#ifndef PLEDGE_LIB_LANDLOCK_ADD_RULE_H_
#define PLEDGE_LIB_LANDLOCK_ADD_RULE_H_

#include <linux/landlock.h>
#include <stdint.h>

int landlock_add_rule(int, enum landlock_rule_type, const void *, uint32_t);

#endif
