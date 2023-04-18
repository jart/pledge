#ifndef PLEDGE_LIBC_CALLS_LANDLOCK_H_
#define PLEDGE_LIBC_CALLS_LANDLOCK_H_

#include <linux/landlock.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Allow renaming or linking file to a different directory.
 *
 * @see https://lore.kernel.org/r/20220329125117.1393824-8-mic@digikod.net
 * @see https://docs.kernel.org/userspace-api/landlock.html
 * @note ABI 2+
 */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER 0x2000ul
#endif

/**
 * Control file truncation.
 *
 * @see https://lore.kernel.org/all/20221018182216.301684-1-gnoack3000@gmail.com/
 * @see https://docs.kernel.org/userspace-api/landlock.html
 * @note ABI 3+
 */
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE 0x4000ul
#endif

int landlock_restrict_self(int, uint32_t);
int landlock_add_rule(int, enum landlock_rule_type, const void *, uint32_t);
int landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t,
                            uint32_t);

#endif
