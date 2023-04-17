#ifndef PLEDGE_LIB_PLEDGE_H_
#define PLEDGE_LIB_PLEDGE_H_

#include <stdint.h>
#include <stddef.h>

#define PROMISE_STDIO     0
#define PROMISE_RPATH     1
#define PROMISE_WPATH     2
#define PROMISE_CPATH     3
#define PROMISE_DPATH     4
#define PROMISE_FLOCK     5
#define PROMISE_FATTR     6
#define PROMISE_INET      7
#define PROMISE_UNIX      8
#define PROMISE_DNS       9
#define PROMISE_TTY       10
#define PROMISE_RECVFD    11
#define PROMISE_PROC      12
#define PROMISE_EXEC      13
#define PROMISE_ID        14
#define PROMISE_UNVEIL    15
#define PROMISE_SENDFD    16
#define PROMISE_SETTIME   17
#define PROMISE_PROT_EXEC 18
#define PROMISE_VMINFO    19
#define PROMISE_TMPPATH   20
#define PROMISE_CHOWN     21
#define PROMISE_LEN_      22

int ParsePromises(const char *, unsigned long *);

#define PLEDGE_PENALTY_KILL_THREAD  0x0000
#define PLEDGE_PENALTY_KILL_PROCESS 0x0001
#define PLEDGE_PENALTY_RETURN_EPERM 0x0002
#define PLEDGE_PENALTY_MASK         0x000f
#define PLEDGE_STDERR_LOGGING       0x0010

extern int __pledge_mode;

/*
extern unsigned long __promises;
extern unsigned long __execpromises;
*/

int pledge(const char *, const char *);
int sys_pledge_linux(unsigned long, int);

struct Pledges {
  const char *name;
  const uint16_t *syscalls;
  const size_t len;
};

extern const struct Pledges kPledge[PROMISE_LEN_];

#endif
