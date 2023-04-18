#ifndef PLEDGE_LIBC_CALLS_LANDLOCK_H_
#define PLEDGE_LIBC_CALLS_LANDLOCK_H_

#include <linux/landlock.h>
#include <stdint.h>
#include <stddef.h>

int landlock_restrict_self(int, uint32_t);
int landlock_add_rule(int, enum landlock_rule_type, const void *, uint32_t);
int landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t,
                            uint32_t);

#endif
