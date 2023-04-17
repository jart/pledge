# pledge for linux

OpenBSD is an operating system that's famous for its focus on security.
Unfortunately, OpenBSD leader Theo states that there are only 7000 users
of OpenBSD. So it's a very small but elite group, that wields a
disproportionate influence; since we hear all the time about the awesome
security features these guys get to use, even though we usually can't
use them ourselves, *until now*.

Pledge was like the forbidden fruit we'd all covet when the boss says we
must use things like Linux. Why does it matter? It's because pledge()
actually makes security comprehensible. Linux has never really had a
security layer that mere mortals can understand. For example, let's say
you want to do something on Linux like control whether or not some
program you downloaded from the web is allowed to have telemetry. You'd
need to write stuff like this:

```c
static const struct sock_filter kFilter[] = {
    /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 14 - 1),
    /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
    /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 4 - 3, 0),
    /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 10, 0, 13 - 4),
    /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
    /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~0x80800),
    /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 8 - 7, 0),
    /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 13 - 8),
    /* L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
    /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 12 - 10, 0),
    /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 12 - 11, 0),
    /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 13 - 11),
    /*L12*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /*L13*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
    /*L14*/ /* next filter */
};
```

Oh my gosh. It's like we traded one form of security privilege for
another. OpenBSD limits security to a small pond, but makes it easy.
Linux is a big tent, but makes it impossibly hard. SECCOMP BPF might as
well be the Traditional Chinese of programming languages, since only a
small number of people who've devoted the oodles of time it takes to
understand code like what you see above have actually been able to
benefit from it. But if you've got OpenBSD privilege, then doing the
same thing becomes easy:

```c
pledge("stdio rpath", 0);
```

That's really all OpenBSD users have to do to prevent things like leaks
of confidential information. So how do we get it that simple on Linux?
The answer is to find someone with enough free time to figure out how to
use SECCOMP BPF to implement pledge. The latest volunteers are us, so
look upon our code ye mighty and despair.
