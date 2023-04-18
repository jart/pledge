/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "libc/calls/pledge.internal.h"
#include "libc/intrin/likely.h"
#include "libc/intrin/promises.internal.h"
#include "libc/macros.internal.h"
#include "libc/runtime/runtime.h"
#include "libc/runtime/stack.h"

/**
 * @fileoverview OpenBSD pledge() Polyfill Payload for GNU/Systemd
 *
 * This file contains only the minimum amount of Linux-specific code
 * that's necessary to get a pledge() policy installed. This file is
 * designed to not use static or tls memory or libc depnedencies, so
 * it can be transplanted into codebases and injected into programs.
 */

#define Eperm       EPERM
#define Sigabrt     SIGABRT
#define Einval      EINVAL
#define Sigsys      SIGSYS
#define Enosys      ENOSYS
#define Sig_Setmask SIG_SETMASK
#define Sa_Siginfo  SA_SIGINFO
#define Sa_Restorer SA_RESTORER
#define Sa_Restart  SA_RESTART

#define SPECIAL   0xf000
#define SELF      0x8000
#define ADDRLESS  0x2000
#define INET      0x2000
#define LOCK      0x4000
#define NOEXEC    0x8000
#define EXEC      0x4000
#define READONLY  0x8000
#define WRITEONLY 0x4000
#define CREATONLY 0x2000
#define STDIO     0x8000
#define THREAD    0x8000
#define TTY       0x8000
#define UNIX      0x4000
#define NOBITS    0x8000
#define RESTRICT  0x1000

#define PLEDGE(pledge) pledge, ARRAYLEN(pledge)
#define OFF(f)         offsetof(struct seccomp_data, f)
#define _bsrl(x)       (__builtin_clzll(x) ^ 63)

#ifdef __x86_64__
#define MCONTEXT_SYSCALL_RESULT_REGISTER gregs[REG_RAX]
#define MCONTEXT_INSTRUCTION_POINTER     gregs[REG_RIP]
#elif defined(__aarch64__)
#define MCONTEXT_SYSCALL_RESULT_REGISTER regs[0]
#define MCONTEXT_INSTRUCTION_POINTER     pc
#else
#error "unsupported architecture"
#endif

struct Filter {
  size_t n;
  struct sock_filter p[700];
};

static const struct thatispacked SyscallName {
  uint16_t n;
  const char *const s;
} kSyscallName[] = {
    {__NR_exit, "exit"},              //
    {__NR_exit_group, "exit_group"},  //
    {__NR_read, "read"},              //
    {__NR_write, "write"},            //
#ifdef __NR_open
    {__NR_open, "open"},  //
#endif
    {__NR_close, "close"},  //
#ifdef __NR_stat
    {__NR_stat, "stat"},  //
#endif
    {__NR_fstat, "fstat"},  //
#ifdef __NR_lstat
    {__NR_lstat, "lstat"},  //
#endif
#ifdef __NR_poll
    {__NR_poll, "poll"},  //
#endif
    {__NR_ppoll, "ppoll"},                 //
    {__NR_brk, "brk"},                     //
    {__NR_rt_sigreturn, "sigreturn"},      //
    {__NR_lseek, "lseek"},                 //
    {__NR_mmap, "mmap"},                   //
    {__NR_msync, "msync"},                 //
    {__NR_mprotect, "mprotect"},           //
    {__NR_munmap, "munmap"},               //
    {__NR_rt_sigaction, "sigaction"},      //
    {__NR_rt_sigprocmask, "sigprocmask"},  //
    {__NR_ioctl, "ioctl"},                 //
    {__NR_pread64, "pread"},               //
    {__NR_pwrite64, "pwrite"},             //
    {__NR_readv, "readv"},                 //
    {__NR_writev, "writev"},               //
#ifdef __NR_access
    {__NR_access, "access"},  //
#endif
#ifdef __NR_pipe
    {__NR_pipe, "pipe"},  //
#endif
#ifdef __NR_select
    {__NR_select, "select"},  //
#endif
    {__NR_pselect6, "pselect6"},        //
    {__NR_sched_yield, "sched_yield"},  //
    {__NR_mremap, "mremap"},            //
    {__NR_mincore, "mincore"},          //
    {__NR_madvise, "madvise"},          //
    {__NR_shmget, "shmget"},            //
    {__NR_shmat, "shmat"},              //
    {__NR_shmctl, "shmctl"},            //
    {__NR_dup, "dup"},                  //
#ifdef __NR_dup2
    {__NR_dup2, "dup2"},  //
#endif
#ifdef __NR_pause
    {__NR_pause, "pause"},  //
#endif
    {__NR_nanosleep, "nanosleep"},  //
    {__NR_getitimer, "getitimer"},  //
    {__NR_setitimer, "setitimer"},  //
#ifdef __NR_alarm
    {__NR_alarm, "alarm"},  //
#endif
    {__NR_getpid, "getpid"},            //
    {__NR_sendfile, "sendfile"},        //
    {__NR_socket, "socket"},            //
    {__NR_connect, "connect"},          //
    {__NR_accept, "accept"},            //
    {__NR_sendto, "sendto"},            //
    {__NR_recvfrom, "recvfrom"},        //
    {__NR_sendmsg, "sendmsg"},          //
    {__NR_recvmsg, "recvmsg"},          //
    {__NR_shutdown, "shutdown"},        //
    {__NR_bind, "bind"},                //
    {__NR_listen, "listen"},            //
    {__NR_getsockname, "getsockname"},  //
    {__NR_getpeername, "getpeername"},  //
    {__NR_socketpair, "socketpair"},    //
    {__NR_setsockopt, "setsockopt"},    //
    {__NR_getsockopt, "getsockopt"},    //
#ifdef __NR_fork
    {__NR_fork, "fork"},  //
#endif
#ifdef __NR_vfork
    {__NR_vfork, "vfork"},  //
#endif
    {__NR_execve, "execve"},                    //
    {__NR_wait4, "wait4"},                      //
    {__NR_kill, "kill"},                        //
    {__NR_clone, "clone"},                      //
    {__NR_tkill, "tkill"},                      //
    {__NR_futex, "futex"},                      //
    {__NR_set_robust_list, "set_robust_list"},  //
    {__NR_get_robust_list, "get_robust_list"},  //
    {__NR_uname, "uname"},                      //
    {__NR_semget, "semget"},                    //
    {__NR_semop, "semop"},                      //
    {__NR_semctl, "semctl"},                    //
    {__NR_shmdt, "shmdt"},                      //
    {__NR_msgget, "msgget"},                    //
    {__NR_msgsnd, "msgsnd"},                    //
    {__NR_msgrcv, "msgrcv"},                    //
    {__NR_msgctl, "msgctl"},                    //
    {__NR_fcntl, "fcntl"},                      //
    {__NR_flock, "flock"},                      //
    {__NR_fsync, "fsync"},                      //
    {__NR_fdatasync, "fdatasync"},              //
    {__NR_truncate, "truncate"},                //
    {__NR_ftruncate, "ftruncate"},              //
    {__NR_getcwd, "getcwd"},                    //
    {__NR_chdir, "chdir"},                      //
    {__NR_fchdir, "fchdir"},                    //
#ifdef __NR_rename
    {__NR_rename, "rename"},  //
#endif
#ifdef __NR_mkdir
    {__NR_mkdir, "mkdir"},  //
#endif
#ifdef __NR_rmdir
    {__NR_rmdir, "rmdir"},  //
#endif
#ifdef __NR_creat
    {__NR_creat, "creat"},  //
#endif
#ifdef __NR_link
    {__NR_link, "link"},  //
#endif
#ifdef __NR_unlink
    {__NR_unlink, "unlink"},  //
#endif
#ifdef __NR_symlink
    {__NR_symlink, "symlink"},  //
#endif
#ifdef __NR_readlink
    {__NR_readlink, "readlink"},  //
#endif
#ifdef __NR_chmod
    {__NR_chmod, "chmod"},  //
#endif
    {__NR_fchmod, "fchmod"},  //
#ifdef __NR_chown
    {__NR_chown, "chown"},  //
#endif
    {__NR_fchown, "fchown"},  //
#ifdef __NR_lchown
    {__NR_lchown, "lchown"},  //
#endif
    {__NR_umask, "umask"},                //
    {__NR_gettimeofday, "gettimeofday"},  //
    {__NR_getrlimit, "getrlimit"},        //
    {__NR_getrusage, "getrusage"},        //
    {__NR_sysinfo, "sysinfo"},            //
    {__NR_times, "times"},                //
    {__NR_ptrace, "ptrace"},              //
    {__NR_syslog, "syslog"},              //
    {__NR_getuid, "getuid"},              //
    {__NR_getgid, "getgid"},              //
    {__NR_getppid, "getppid"},            //
#ifdef __NR_getpgrp
    {__NR_getpgrp, "getpgrp"},  //
#endif
    {__NR_setsid, "setsid"},             //
    {__NR_getsid, "getsid"},             //
    {__NR_getpgid, "getpgid"},           //
    {__NR_setpgid, "setpgid"},           //
    {__NR_geteuid, "geteuid"},           //
    {__NR_getegid, "getegid"},           //
    {__NR_getgroups, "getgroups"},       //
    {__NR_setgroups, "setgroups"},       //
    {__NR_setreuid, "setreuid"},         //
    {__NR_setregid, "setregid"},         //
    {__NR_setuid, "setuid"},             //
    {__NR_setgid, "setgid"},             //
    {__NR_setresuid, "setresuid"},       //
    {__NR_setresgid, "setresgid"},       //
    {__NR_getresuid, "getresuid"},       //
    {__NR_getresgid, "getresgid"},       //
    {__NR_rt_sigpending, "sigpending"},  //
    {__NR_rt_sigsuspend, "sigsuspend"},  //
    {__NR_sigaltstack, "sigaltstack"},   //
#ifdef __NR_mknod
    {__NR_mknod, "mknod"},  //
#endif
    {__NR_mknodat, "mknodat"},                  //
    {__NR_statfs, "statfs"},                    //
    {__NR_fstatfs, "fstatfs"},                  //
    {__NR_getpriority, "getpriority"},          //
    {__NR_setpriority, "setpriority"},          //
    {__NR_mlock, "mlock"},                      //
    {__NR_munlock, "munlock"},                  //
    {__NR_mlockall, "mlockall"},                //
    {__NR_munlockall, "munlockall"},            //
    {__NR_setrlimit, "setrlimit"},              //
    {__NR_chroot, "chroot"},                    //
    {__NR_sync, "sync"},                        //
    {__NR_acct, "acct"},                        //
    {__NR_settimeofday, "settimeofday"},        //
    {__NR_mount, "mount"},                      //
    {__NR_reboot, "reboot"},                    //
    {__NR_quotactl, "quotactl"},                //
    {__NR_setfsuid, "setfsuid"},                //
    {__NR_setfsgid, "setfsgid"},                //
    {__NR_capget, "capget"},                    //
    {__NR_capset, "capset"},                    //
    {__NR_rt_sigtimedwait, "sigtimedwait"},     //
    {__NR_rt_sigqueueinfo, "rt_sigqueueinfo"},  //
    {__NR_personality, "personality"},          //
#ifdef __NR_ustat
    {__NR_ustat, "ustat"},  //
#endif
#ifdef __NR_sysfs
    {__NR_sysfs, "sysfs"},  //
#endif
    {__NR_sched_setparam, "sched_setparam"},                  //
    {__NR_sched_getparam, "sched_getparam"},                  //
    {__NR_sched_setscheduler, "sched_setscheduler"},          //
    {__NR_sched_getscheduler, "sched_getscheduler"},          //
    {__NR_sched_get_priority_max, "sched_get_priority_max"},  //
    {__NR_sched_get_priority_min, "sched_get_priority_min"},  //
    {__NR_sched_rr_get_interval, "sched_rr_get_interval"},    //
    {__NR_vhangup, "vhangup"},                                //
#ifdef __NR_modify_ldt
    {__NR_modify_ldt, "modify_ldt"},  //
#endif
    {__NR_pivot_root, "pivot_root"},  //
#ifdef __NR__sysctl
    {__NR__sysctl, "_sysctl"},  //
#endif
    {__NR_prctl, "prctl"},  //
#ifdef __NR_arch_prctl
    {__NR_arch_prctl, "arch_prctl"},  //
#endif
    {__NR_adjtimex, "adjtimex"},            //
    {__NR_umount2, "umount2"},              //
    {__NR_swapon, "swapon"},                //
    {__NR_swapoff, "swapoff"},              //
    {__NR_sethostname, "sethostname"},      //
    {__NR_setdomainname, "setdomainname"},  //
#ifdef __NR_iopl
    {__NR_iopl, "iopl"},  //
#endif
#ifdef __NR_ioperm
    {__NR_ioperm, "ioperm"},  //
#endif
    {__NR_init_module, "init_module"},              //
    {__NR_delete_module, "delete_module"},          //
    {__NR_gettid, "gettid"},                        //
    {__NR_readahead, "readahead"},                  //
    {__NR_setxattr, "setxattr"},                    //
    {__NR_fsetxattr, "fsetxattr"},                  //
    {__NR_getxattr, "getxattr"},                    //
    {__NR_fgetxattr, "fgetxattr"},                  //
    {__NR_listxattr, "listxattr"},                  //
    {__NR_flistxattr, "flistxattr"},                //
    {__NR_removexattr, "removexattr"},              //
    {__NR_fremovexattr, "fremovexattr"},            //
    {__NR_lsetxattr, "lsetxattr"},                  //
    {__NR_lgetxattr, "lgetxattr"},                  //
    {__NR_llistxattr, "llistxattr"},                //
    {__NR_lremovexattr, "lremovexattr"},            //
    {__NR_sched_setaffinity, "sched_setaffinity"},  //
    {__NR_sched_getaffinity, "sched_getaffinity"},  //
    {__NR_io_setup, "io_setup"},                    //
    {__NR_io_destroy, "io_destroy"},                //
    {__NR_io_getevents, "io_getevents"},            //
    {__NR_io_submit, "io_submit"},                  //
    {__NR_io_cancel, "io_cancel"},                  //
    {__NR_lookup_dcookie, "lookup_dcookie"},        //
#ifdef __NR_epoll_create
    {__NR_epoll_create, "epoll_create"},  //
#endif
#ifdef __NR_epoll_wait
    {__NR_epoll_wait, "epoll_wait"},  //
#endif
    {__NR_epoll_ctl, "epoll_ctl"},  //
#ifdef __NR_getdents
    {__NR_getdents, "getdents"},  //
#endif
    {__NR_getdents64, "getdents64"},              //
    {__NR_set_tid_address, "set_tid_address"},    //
    {__NR_restart_syscall, "restart_syscall"},    //
    {__NR_semtimedop, "semtimedop"},              //
    {__NR_fadvise64, "fadvise"},                  //
    {__NR_timer_create, "timer_create"},          //
    {__NR_timer_settime, "timer_settime"},        //
    {__NR_timer_gettime, "timer_gettime"},        //
    {__NR_timer_getoverrun, "timer_getoverrun"},  //
    {__NR_timer_delete, "timer_delete"},          //
    {__NR_clock_settime, "clock_settime"},        //
    {__NR_clock_gettime, "clock_gettime"},        //
    {__NR_clock_getres, "clock_getres"},          //
    {__NR_clock_nanosleep, "clock_nanosleep"},    //
    {__NR_tgkill, "tgkill"},                      //
    {__NR_mbind, "mbind"},                        //
    {__NR_set_mempolicy, "set_mempolicy"},        //
    {__NR_get_mempolicy, "get_mempolicy"},        //
    {__NR_mq_open, "mq_open"},                    //
    {__NR_mq_unlink, "mq_unlink"},                //
    {__NR_mq_timedsend, "mq_timedsend"},          //
    {__NR_mq_timedreceive, "mq_timedreceive"},    //
    {__NR_mq_notify, "mq_notify"},                //
    {__NR_mq_getsetattr, "mq_getsetattr"},        //
    {__NR_kexec_load, "kexec_load"},              //
    {__NR_waitid, "waitid"},                      //
    {__NR_add_key, "add_key"},                    //
    {__NR_request_key, "request_key"},            //
    {__NR_keyctl, "keyctl"},                      //
    {__NR_ioprio_set, "ioprio_set"},              //
    {__NR_ioprio_get, "ioprio_get"},              //
#ifdef __NR_inotify_init
    {__NR_inotify_init, "inotify_init"},  //
#endif
    {__NR_inotify_add_watch, "inotify_add_watch"},  //
    {__NR_inotify_rm_watch, "inotify_rm_watch"},    //
    {__NR_openat, "openat"},                        //
    {__NR_mkdirat, "mkdirat"},                      //
    {__NR_fchownat, "fchownat"},                    //
#ifdef __NR_utime
    {__NR_utime, "utime"},  //
#endif
#ifdef __NR_utimes
    {__NR_utimes, "utimes"},  //
#endif
#ifdef __NR_futimesat
    {__NR_futimesat, "futimesat"},  //
#endif
    {__NR_newfstatat, "fstatat"},                   //
    {__NR_unlinkat, "unlinkat"},                    //
    {__NR_renameat, "renameat"},                    //
    {__NR_linkat, "linkat"},                        //
    {__NR_symlinkat, "symlinkat"},                  //
    {__NR_readlinkat, "readlinkat"},                //
    {__NR_fchmodat, "fchmodat"},                    //
    {__NR_faccessat, "faccessat"},                  //
    {__NR_unshare, "unshare"},                      //
    {__NR_splice, "splice"},                        //
    {__NR_tee, "tee"},                              //
    {__NR_sync_file_range, "sync_file_range"},      //
    {__NR_vmsplice, "vmsplice"},                    //
    {__NR_migrate_pages, "migrate_pages"},          //
    {__NR_move_pages, "move_pages"},                //
    {__NR_preadv, "preadv"},                        //
    {__NR_pwritev, "pwritev"},                      //
    {__NR_utimensat, "utimensat"},                  //
    {__NR_fallocate, "fallocate"},                  //
    {__NR_accept4, "accept4"},                      //
    {__NR_dup3, "dup3"},                            //
    {__NR_pipe2, "pipe2"},                          //
    {__NR_epoll_pwait, "epoll_pwait"},              //
    {__NR_epoll_create1, "epoll_create1"},          //
    {__NR_perf_event_open, "perf_event_open"},      //
    {__NR_inotify_init1, "inotify_init1"},          //
    {__NR_rt_tgsigqueueinfo, "rt_tgsigqueueinfo"},  //
#ifdef __NR_signalfd
    {__NR_signalfd, "signalfd"},  //
#endif
    {__NR_signalfd4, "signalfd4"},  //
#ifdef __NR_eventfd
    {__NR_eventfd, "eventfd"},  //
#endif
    {__NR_eventfd2, "eventfd2"},                    //
    {__NR_timerfd_create, "timerfd_create"},        //
    {__NR_timerfd_settime, "timerfd_settime"},      //
    {__NR_timerfd_gettime, "timerfd_gettime"},      //
    {__NR_recvmmsg, "recvmmsg"},                    //
    {__NR_fanotify_init, "fanotify_init"},          //
    {__NR_fanotify_mark, "fanotify_mark"},          //
    {__NR_prlimit64, "prlimit"},                    //
    {__NR_name_to_handle_at, "name_to_handle_at"},  //
    {__NR_open_by_handle_at, "open_by_handle_at"},  //
    {__NR_clock_adjtime, "clock_adjtime"},          //
    {__NR_syncfs, "syncfs"},                        //
    {__NR_sendmmsg, "sendmmsg"},                    //
    {__NR_setns, "setns"},                          //
    {__NR_getcpu, "getcpu"},                        //
    {__NR_process_vm_readv, "process_vm_readv"},    //
    {__NR_process_vm_writev, "process_vm_writev"},  //
    {__NR_kcmp, "kcmp"},                            //
    {__NR_finit_module, "finit_module"},            //
    {__NR_sched_setattr, "sched_setattr"},          //
    {__NR_sched_getattr, "sched_getattr"},          //
    {__NR_renameat2, "renameat2"},                  //
    {__NR_seccomp, "seccomp"},                      //
    {__NR_getrandom, "getrandom"},                  //
    {__NR_memfd_create, "memfd_create"},            //
    {__NR_kexec_file_load, "kexec_file_load"},      //
    {__NR_bpf, "bpf"},                              //
    {__NR_execveat, "execveat"},                    //
    {__NR_userfaultfd, "userfaultfd"},              //
    {__NR_membarrier, "membarrier"},                //
    {__NR_mlock2, "mlock2"},                        //
    {__NR_copy_file_range, "copy_file_range"},      //
    {__NR_preadv2, "preadv2"},                      //
    {__NR_pwritev2, "pwritev2"},                    //
    {__NR_pkey_mprotect, "pkey_mprotect"},          //
    {__NR_pkey_alloc, "pkey_alloc"},                //
    {__NR_pkey_free, "pkey_free"},                  //
    {__NR_statx, "statx"},                          //
    {__NR_io_pgetevents, "io_pgetevents"},          //
    {__NR_rseq, "rseq"},                            //
    {__NR_pidfd_send_signal, "pidfd_send_signal"},  //
    {__NR_io_uring_setup, "io_uring_setup"},        //
    {__NR_io_uring_enter, "io_uring_enter"},        //
    {__NR_io_uring_register, "io_uring_register"},  //
    {__NR_open_tree, "open_tree"},                  //
    {__NR_move_mount, "move_mount"},                //
    {__NR_fsopen, "fsopen"},                        //
    {__NR_fsconfig, "fsconfig"},                    //
    {__NR_fsmount, "fsmount"},                      //
    {__NR_fspick, "fspick"},                        //
    {__NR_pidfd_open, "pidfd_open"},                //
    {__NR_clone3, "clone3"},                        //
    {__NR_close_range, "close_range"},              //
    {__NR_openat2, "openat2"},                      //
    {__NR_pidfd_getfd, "pidfd_getfd"},              //
    {__NR_faccessat2, "faccessat2"},                //
    {__NR_process_madvise, "process_madvise"},      //
    {__NR_epoll_pwait2, "epoll_pwait2"},            //
    {__NR_mount_setattr, "mount_setattr"},          //
#ifdef __NR_quotactl_fd
    {__NR_quotactl_fd, "quotactl_fd"},  //
#endif
    {__NR_landlock_create_ruleset, "landlock_create_ruleset"},  //
    {__NR_landlock_add_rule, "landlock_add_rule"},              //
    {__NR_landlock_restrict_self, "landlock_restrict_self"},    //
#ifdef __NR_memfd_secret
    {__NR_memfd_secret, "memfd_secret"},  //
#endif
#ifdef __NR_process_mrelease
    {__NR_process_mrelease, "process_mrelease"},  //
#endif
#ifdef __NR_futex_waitv
    {__NR_futex_waitv, "futex_waitv"},  //
#endif
#ifdef __NR_set_mempolicy_home_node
    {__NR_set_mempolicy_home_node, "set_mempolicy_home_node"},  //
#endif
};

static const uint16_t kPledgeDefault[] = {
    __NR_exit,  // thread return / exit()
};

// stdio contains all the benign system calls. openbsd makes the
// assumption that preexisting file descriptors are trustworthy. we
// implement checking for these as a simple linear scan rather than
// binary search, since there doesn't appear to be any measurable
// difference in the latency of sched_yield() if it's at the start of
// the bpf script or the end.
static const uint16_t kPledgeStdio[] = {
    __NR_rt_sigreturn,       //
    __NR_restart_syscall,    //
    __NR_exit_group,         //
    __NR_sched_yield,        //
    __NR_sched_getaffinity,  //
    __NR_clock_getres,       //
    __NR_clock_gettime,      //
    __NR_clock_nanosleep,    //
    __NR_close_range,        //
    __NR_close,              //
    __NR_write,              //
    __NR_writev,             //
    __NR_pwrite64,           //
    __NR_pwritev,            //
    __NR_pwritev2,           //
    __NR_read,               //
    __NR_readv,              //
    __NR_pread64,            //
    __NR_preadv,             //
    __NR_preadv2,            //
    __NR_dup,                //
#ifdef __NR_dup2
    __NR_dup2,  //
#endif
    __NR_dup3,           //
    __NR_fchdir,         //
    __NR_fcntl | STDIO,  //
    __NR_fstat,          //
    __NR_fsync,          //
    __NR_sysinfo,        //
    __NR_fdatasync,      //
    __NR_ftruncate,      //
    __NR_getrandom,      //
    __NR_getgroups,      //
    __NR_getpgid,        //
#ifdef __NR_getpgrp
    __NR_getpgrp,  //
#endif
    __NR_getpid,             //
    __NR_gettid,             //
    __NR_getuid,             //
    __NR_getgid,             //
    __NR_getsid,             //
    __NR_getppid,            //
    __NR_geteuid,            //
    __NR_getegid,            //
    __NR_getrlimit,          //
    __NR_getresgid,          //
    __NR_getresuid,          //
    __NR_getitimer,          //
    __NR_setitimer,          //
    __NR_timerfd_create,     //
    __NR_timerfd_settime,    //
    __NR_timerfd_gettime,    //
    __NR_copy_file_range,    //
    __NR_gettimeofday,       //
    __NR_sendfile,           //
    __NR_vmsplice,           //
    __NR_splice,             //
    __NR_lseek,              //
    __NR_tee,                //
    __NR_brk,                //
    __NR_msync,              //
    __NR_mmap | NOEXEC,      //
    __NR_mremap,             //
    __NR_munmap,             //
    __NR_mincore,            //
    __NR_madvise,            //
    __NR_fadvise64,          //
    __NR_mprotect | NOEXEC,  //
#ifdef __NR_arch_prctl
    __NR_arch_prctl,  //
#endif
    __NR_migrate_pages,    //
    __NR_sync_file_range,  //
    __NR_set_tid_address,  //
    __NR_membarrier,       //
    __NR_nanosleep,        //
#ifdef __NR_pipe
    __NR_pipe,  //
#endif
    __NR_pipe2,  //
#ifdef __NR_poll
    __NR_poll,  //
#endif
    __NR_ppoll,  //
#ifdef __NR_select
    __NR_select,  //
#endif
    __NR_pselect6,  //
#ifdef __NR_epoll_create
    __NR_epoll_create,  //
#endif
    __NR_epoll_create1,  //
    __NR_epoll_ctl,      //
#ifdef __NR_epoll_wait
    __NR_epoll_wait,  //
#endif
    __NR_epoll_pwait,        //
    __NR_epoll_pwait2,       //
    __NR_recvfrom,           //
    __NR_sendto | ADDRLESS,  //
    __NR_ioctl | RESTRICT,   //
#ifdef __NR_alarm
    __NR_alarm,  //
#endif
#ifdef __NR_pause
    __NR_pause,  //
#endif
    __NR_shutdown,  //
#ifdef __NR_eventfd
    __NR_eventfd,  //
#endif
    __NR_eventfd2,  //
#ifdef __NR_signalfd
    __NR_signalfd,  //
#endif
    __NR_signalfd4,          //
    __NR_rt_sigaction,       //
    __NR_sigaltstack,        //
    __NR_rt_sigprocmask,     //
    __NR_rt_sigsuspend,      //
    __NR_rt_sigpending,      //
    __NR_kill | SELF,        //
    __NR_tkill,              //
    __NR_tgkill | SELF,      //
    __NR_socketpair,         //
    __NR_getrusage,          //
    __NR_times,              //
    __NR_umask,              //
    __NR_wait4,              //
    __NR_uname,              //
    __NR_prctl | STDIO,      //
    __NR_clone | THREAD,     //
    __NR_futex,              //
    __NR_set_robust_list,    //
    __NR_get_robust_list,    //
    __NR_prlimit64 | STDIO,  //
    __NR_sched_getaffinity,  //
    __NR_sched_setaffinity,  //
    __NR_rt_sigtimedwait,    //
};

static const uint16_t kPledgeFlock[] = {
    __NR_flock,         //
    __NR_fcntl | LOCK,  //
};

static const uint16_t kPledgeRpath[] = {
    __NR_chdir,   //
    __NR_getcwd,  //
#ifdef __NR_open
    __NR_open | READONLY,  //
#endif
    __NR_openat | READONLY,  //
#ifdef __NR_stat
    __NR_stat,  //
#endif
#ifdef __NR_lstat
    __NR_lstat,  //
#endif
    __NR_fstat,       //
    __NR_newfstatat,  //
#ifdef __NR_access
    __NR_access,  //
#endif
    __NR_faccessat,   //
    __NR_faccessat2,  //
#ifdef __NR_readlink
    __NR_readlink,  //
#endif
    __NR_readlinkat,  //
    __NR_statfs,      //
    __NR_fstatfs,     //
#ifdef __NR_getdents
    __NR_getdents,  //
#endif
    __NR_getdents64,  //
};

static const uint16_t kPledgeWpath[] = {
    __NR_getcwd,  //
#ifdef __NR_open
    __NR_open | WRITEONLY,  //
#endif
    __NR_openat | WRITEONLY,  //
#ifdef __NR_stat
    __NR_stat,  //
#endif
    __NR_fstat,  //
#ifdef __NR_lstat
    __NR_lstat,  //
#endif
    __NR_newfstatat,  //
#ifdef __NR_access
    __NR_access,  //
#endif
    __NR_truncate,    //
    __NR_faccessat,   //
    __NR_faccessat2,  //
    __NR_readlinkat,  //
#ifdef __NR_chmod
    __NR_chmod | NOBITS,  //
#endif
    __NR_fchmod | NOBITS,    //
    __NR_fchmodat | NOBITS,  //
};

static const uint16_t kPledgeCpath[] = {
#ifdef __NR_open
    __NR_open | CREATONLY,  //
#endif
    __NR_openat | CREATONLY,  //
#ifdef __NR_creat
    __NR_creat | RESTRICT,  //
#endif
#ifdef __NR_rename
    __NR_rename,  //
#endif
    __NR_renameat,   //
    __NR_renameat2,  //
#ifdef __NR_link
    __NR_link,  //
#endif
    __NR_linkat,  //
#ifdef __NR_symlink
    __NR_symlink,  //
#endif
    __NR_symlinkat,  //
#ifdef __NR_rmdir
    __NR_rmdir,  //
#endif
#ifdef __NR_unlink
    __NR_unlink,  //
#endif
    __NR_unlinkat,  //
#ifdef __NR_mkdir
    __NR_mkdir,  //
#endif
    __NR_mkdirat,  //
};

static const uint16_t kPledgeDpath[] = {
#ifdef __NR_mknod
    __NR_mknod,  //
#endif
    __NR_mknodat,  //
};

static const uint16_t kPledgeFattr[] = {
#ifdef __NR_chmod
    __NR_chmod | NOBITS,  //
#endif
    __NR_fchmod | NOBITS,    //
    __NR_fchmodat | NOBITS,  //
#ifdef __NR_utime
    __NR_utime,  //
#endif
#ifdef __NR_utimes
    __NR_utimes,  //
#endif
#ifdef __NR_futimesat
    __NR_futimesat,  //
#endif
    __NR_utimensat,  //
};

static const uint16_t kPledgeInet[] = {
    __NR_socket | INET,          //
    __NR_listen,                 //
    __NR_bind,                   //
    __NR_sendto,                 //
    __NR_connect,                //
    __NR_accept,                 //
    __NR_accept4,                //
    __NR_ioctl | INET,           //
    __NR_getsockopt | RESTRICT,  //
    __NR_setsockopt | RESTRICT,  //
    __NR_getpeername,            //
    __NR_getsockname,            //
};

static const uint16_t kPledgeUnix[] = {
    __NR_socket | UNIX,          //
    __NR_listen,                 //
    __NR_bind,                   //
    __NR_connect,                //
    __NR_sendto,                 //
    __NR_accept,                 //
    __NR_accept4,                //
    __NR_getsockopt | RESTRICT,  //
    __NR_setsockopt | RESTRICT,  //
    __NR_getpeername,            //
    __NR_getsockname,            //
};

static const uint16_t kPledgeDns[] = {
    __NR_socket | INET,          //
    __NR_bind,                   //
    __NR_sendto,                 //
    __NR_connect,                //
    __NR_recvfrom,               //
    __NR_setsockopt | RESTRICT,  //
    __NR_newfstatat,             //
    __NR_openat | READONLY,      //
    __NR_read,                   //
    __NR_close,                  //
};

static const uint16_t kPledgeTty[] = {
    __NR_ioctl | TTY,  //
};

static const uint16_t kPledgeRecvfd[] = {
    __NR_recvmsg,   //
    __NR_recvmmsg,  //
};

static const uint16_t kPledgeSendfd[] = {
    __NR_sendmsg,   //
    __NR_sendmmsg,  //
};

static const uint16_t kPledgeProc[] = {
#ifdef __NR_fork
    __NR_fork,  //
#endif
#ifdef __NR_vfork
    __NR_vfork,  //
#endif
    __NR_clone | RESTRICT,        //
    __NR_kill,                    //
    __NR_tgkill,                  //
    __NR_setsid,                  //
    __NR_setpgid,                 //
    __NR_prlimit64,               //
    __NR_setrlimit,               //
    __NR_getpriority,             //
    __NR_setpriority,             //
    __NR_ioprio_get,              //
    __NR_ioprio_set,              //
    __NR_sched_getscheduler,      //
    __NR_sched_setscheduler,      //
    __NR_sched_get_priority_min,  //
    __NR_sched_get_priority_max,  //
    __NR_sched_getparam,          //
    __NR_sched_setparam,          //
};

static const uint16_t kPledgeId[] = {
    __NR_setuid,       //
    __NR_setreuid,     //
    __NR_setresuid,    //
    __NR_setgid,       //
    __NR_setregid,     //
    __NR_setresgid,    //
    __NR_setgroups,    //
    __NR_prlimit64,    //
    __NR_setrlimit,    //
    __NR_getpriority,  //
    __NR_setpriority,  //
    __NR_setfsuid,     //
    __NR_setfsgid,     //
};

static const uint16_t kPledgeChown[] = {
#ifdef __NR_chown
    __NR_chown,  //
#endif
    __NR_fchown,  //
#ifdef __NR_lchown
    __NR_lchown,  //
#endif
    __NR_fchownat,  //
};

static const uint16_t kPledgeSettime[] = {
    __NR_settimeofday,   //
    __NR_clock_adjtime,  //
};

static const uint16_t kPledgeProtExec[] = {
    __NR_mmap | EXEC,  //
    __NR_mprotect,     //
};

static const uint16_t kPledgeExec[] = {
    __NR_execve,    //
    __NR_execveat,  //
};

static const uint16_t kPledgeUnveil[] = {
    __NR_landlock_create_ruleset,  //
    __NR_landlock_add_rule,        //
    __NR_landlock_restrict_self,   //
};

// placeholder group
//
// pledge.com checks this to do auto-unveiling
static const uint16_t kPledgeVminfo[] = {
    __NR_sched_yield,  //
};

// placeholder group
//
// pledge.com uses this to auto-unveil /tmp and $TMPPATH with rwc
// permissions. pledge() alone (without unveil() too) offers very
// little security here. consider using them together.
static const uint16_t kPledgeTmppath[] = {
#ifdef __NR_lstat
    __NR_lstat,  //
#endif
#ifdef __NR_unlink
    __NR_unlink,  //
#endif
    __NR_unlinkat,  //
};

const struct Pledges kPledge[PROMISE_LEN_] = {
    [PROMISE_STDIO] = {"stdio", PLEDGE(kPledgeStdio)},             //
    [PROMISE_RPATH] = {"rpath", PLEDGE(kPledgeRpath)},             //
    [PROMISE_WPATH] = {"wpath", PLEDGE(kPledgeWpath)},             //
    [PROMISE_CPATH] = {"cpath", PLEDGE(kPledgeCpath)},             //
    [PROMISE_DPATH] = {"dpath", PLEDGE(kPledgeDpath)},             //
    [PROMISE_FLOCK] = {"flock", PLEDGE(kPledgeFlock)},             //
    [PROMISE_FATTR] = {"fattr", PLEDGE(kPledgeFattr)},             //
    [PROMISE_INET] = {"inet", PLEDGE(kPledgeInet)},                //
    [PROMISE_UNIX] = {"unix", PLEDGE(kPledgeUnix)},                //
    [PROMISE_DNS] = {"dns", PLEDGE(kPledgeDns)},                   //
    [PROMISE_TTY] = {"tty", PLEDGE(kPledgeTty)},                   //
    [PROMISE_RECVFD] = {"recvfd", PLEDGE(kPledgeRecvfd)},          //
    [PROMISE_SENDFD] = {"sendfd", PLEDGE(kPledgeSendfd)},          //
    [PROMISE_PROC] = {"proc", PLEDGE(kPledgeProc)},                //
    [PROMISE_EXEC] = {"exec", PLEDGE(kPledgeExec)},                //
    [PROMISE_ID] = {"id", PLEDGE(kPledgeId)},                      //
    [PROMISE_UNVEIL] = {"unveil", PLEDGE(kPledgeUnveil)},          //
    [PROMISE_SETTIME] = {"settime", PLEDGE(kPledgeSettime)},       //
    [PROMISE_PROT_EXEC] = {"prot_exec", PLEDGE(kPledgeProtExec)},  //
    [PROMISE_VMINFO] = {"vminfo", PLEDGE(kPledgeVminfo)},          //
    [PROMISE_TMPPATH] = {"tmppath", PLEDGE(kPledgeTmppath)},       //
    [PROMISE_CHOWN] = {"chown", PLEDGE(kPledgeChown)},             //
};

static const struct sock_filter kPledgeStart[] = {
#if 0
    // make sure this isn't an i386 binary or something
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
    // each filter assumes ordinal is already loaded into accumulator
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
// forbid some system calls with ENOSYS (rather than EPERM)
#ifdef __NR_memfd_secret
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, __NR_memfd_secret, 5, 0),
#endif
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rseq, 4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_memfd_create, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_statx, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (Enosys & SECCOMP_RET_DATA)),
};

static const struct sock_filter kFilterIgnoreExitGroup[] = {
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (Eperm & SECCOMP_RET_DATA)),
};

static privileged unsigned long StrLen(const char *s) {
  unsigned long n = 0;
  while (*s++) ++n;
  return n;
}

static privileged void *MemCpy(void *d, const void *s, unsigned long n) {
  unsigned long i = 0;
  for (; i < n; ++i) ((char *)d)[i] = ((char *)s)[i];
  return (char *)d + n;
}

static privileged char *FixCpy(char p[17], uint64_t x, int k) {
  while (k > 0) *p++ = "0123456789abcdef"[(x >> (k -= 4)) & 15];
  *p = '\0';
  return p;
}

static privileged char *HexCpy(char p[17], uint64_t x) {
  return FixCpy(p, x, ROUNDUP(x ? _bsrl(x) + 1 : 1, 4));
}

static privileged void Log(const char *s, ...) {
  int ax;
  va_list va;
  va_start(va, s);
  do ax = write(2, s, strlen(s));
  while ((s = va_arg(va, const char *)));
  va_end(va);
}

static privileged int Prctl(int op, long a, void *b, long c, long d) {
  return syscall(__NR_prctl, op, a, b, c, d);
}

static privileged void KillThisProcess(void) {
  abort();
}

static privileged void KillThisThread(void) {
  int ax;
  sigset_t full, empty;
  sigfillset(&full);
  sigemptyset(&empty);
  sigaction(Sigabrt, &(struct sigaction){0}, 0);
  sigprocmask(Sig_Setmask, &full, 0);
  ax = syscall(__NR_tkill, syscall(__NR_gettid), SIGABRT);
  sigprocmask(Sig_Setmask, &empty, 0);
  syscall(__NR_exit, 128 + SIGABRT);
  abort();
}

static privileged const char *GetSyscallName(uint16_t n) {
  int i;
  for (i = 0; i < ARRAYLEN(kSyscallName); ++i) {
    if (kSyscallName[i].n == n) {
      return kSyscallName[i].s;
    }
  }
  return "unknown";
}

static privileged int HasSyscall(const struct Pledges *p, uint16_t n) {
  int i;
  for (i = 0; i < p->len; ++i) {
    if (p->syscalls[i] == n) {
      return 1;
    }
    if ((p->syscalls[i] & 0xfff) == n) {
      return 2;
    }
  }
  return 0;
}

static privileged void OnSigSys(int sig, siginfo_t *si, void *vctx) {
  bool found;
  char ord[17], ip[17];
  int i, ok, mode = si->si_errno;
  ucontext_t *ctx = vctx;
  ctx->uc_mcontext.MCONTEXT_SYSCALL_RESULT_REGISTER = -Eperm;
  FixCpy(ord, si->si_syscall, 12);
  HexCpy(ip, ctx->uc_mcontext.MCONTEXT_INSTRUCTION_POINTER);
  for (found = i = 0; i < ARRAYLEN(kPledge); ++i) {
    if (HasSyscall(kPledge + i, si->si_syscall)) {
      Log("error: pledge ", kPledge[i].name, " for ",
          GetSyscallName(si->si_syscall), " (ord=0x", ord, " ip=0x", ip, ")\n",
          0);
      found = true;
    }
  }
  if (!found) {
    Log("error: bad syscall (", GetSyscallName(si->si_syscall), " ord=0x", ord,
        " ip=0x", ip, ")\n", 0);
  }
  switch (mode & PLEDGE_PENALTY_MASK) {
    case PLEDGE_PENALTY_KILL_PROCESS:
      KillThisProcess();
      // fallthrough
    case PLEDGE_PENALTY_KILL_THREAD:
      KillThisThread();
      notpossible;
    default:
      break;
  }
}

static privileged void MonitorSigSys(void) {
  int ax;
  struct sigaction sa = {
      .sa_sigaction = OnSigSys,
      .sa_flags = Sa_Siginfo | Sa_Restart,
  };
  // we block changing sigsys once pledge is installed
  // so we aren't terribly concerned if this will fail
  if (sigaction(Sigsys, &sa, 0) == -1) {
    notpossible;
  }
}

static privileged void AppendFilter(struct Filter *f,
                                    const struct sock_filter *p, size_t n) {
  if (UNLIKELY(f->n + n > ARRAYLEN(f->p))) notpossible;
  MemCpy(f->p + f->n, p, n * sizeof(*f->p));
  f->n += n;
}

// The first argument of kill() must be
//
//   - getpid()
//
static privileged void AllowKillSelf(struct Filter *f) {
  struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, getpid(), 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The first argument of tgkill() must be
//
//   - getpid()
//
static privileged void AllowTgkillSelf(struct Filter *f) {
  struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, getpid(), 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The following system calls are allowed:
//
//   - write(2) to allow logging
//   - kill(getpid(), SIGABRT) to abort process
//   - tkill(gettid(), SIGABRT) to abort thread
//   - sigaction(SIGABRT) to force default signal handler
//   - sigreturn() to return from signal handler
//   - sigprocmask() to force signal delivery
//
static privileged void AllowMonitor(struct Filter *f) {
  struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 6),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, getpid(), 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, Sigabrt, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_tkill, 0, 6),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, gettid(), 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, Sigabrt, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 4),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, Sigabrt, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  AppendFilter(f, PLEDGE(fragment));
}

#if 0
// SYSCALL is only allowed in the .privileged section
// We assume program image is loaded in 32-bit spaces
static privileged void AppendOriginVerification(struct Filter *f) {
  long x = (long)__privileged_start;
  long y = (long)__privileged_end;
  struct sock_filter fragment[] = {
      /*L0*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(instruction_pointer) + 4),
      /*L1*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5 - 2),
      /*L2*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(instruction_pointer)),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, x, 0, 5 - 4),
      /*L4*/ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, y, 0, 6 - 5),
      /*L5*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
      /*L6*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L7*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

#define AppendOriginVerification(f)

// The first argument of sys_clone_linux() must NOT have:
//
//   - CLONE_NEWNS    (0x00020000)
//   - CLONE_PTRACE   (0x00002000)
//   - CLONE_UNTRACED (0x00800000)
//
static privileged void AllowCloneRestrict(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x00822000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The first argument of sys_clone_linux() must have:
//
//   - CLONE_VM       (0x00000100)
//   - CLONE_FS       (0x00000200)
//   - CLONE_FILES    (0x00000400)
//   - CLONE_THREAD   (0x00010000)
//   - CLONE_SIGHAND  (0x00000800)
//
// The first argument of sys_clone_linux() must NOT have:
//
//   - CLONE_NEWNS    (0x00020000)
//   - CLONE_PTRACE   (0x00002000)
//   - CLONE_UNTRACED (0x00800000)
//
static privileged void AllowCloneThread(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x00010f00),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x00010f00, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x00822000),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of ioctl() must be one of:
//
//   - FIONREAD (0x541b)
//   - FIONBIO  (0x5421)
//   - FIOCLEX  (0x5451)
//   - FIONCLEX (0x5450)
//
static privileged void AllowIoctlStdio(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 7),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x541b, 3, 0),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5421, 2, 0),
      /*L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5451, 1, 0),
      /*L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5450, 0, 1),
      /*L6*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L8*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of ioctl() must be one of:
//
//   - SIOCATMARK (0x8905)
//
static privileged void AllowIoctlInet(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 4),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x8905, 0, 1),
      /*L6*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L8*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of ioctl() must be one of:
//
//   - TCGETS     (0x5401)
//   - TCSETS     (0x5402)
//   - TCSETSW    (0x5403)
//   - TCSETSF    (0x5404)
//   - TIOCGWINSZ (0x5413)
//   - TIOCSPGRP  (0x5410)
//   - TIOCGPGRP  (0x540f)
//   - TIOCSWINSZ (0x5414)
//   - TCFLSH     (0x540b)
//   - TCXONC     (0x540a)
//   - TCSBRK     (0x5409)
//   - TIOCSBRK   (0x5427)
//
static privileged void AllowIoctlTty(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 15),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5401, 11, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5402, 10, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5403, 9, 0),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5404, 8, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5413, 7, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5410, 6, 0),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x540f, 5, 0),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5414, 4, 0),
      /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x540b, 3, 0),
      /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x540a, 2, 0),
      /*L12*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5409, 1, 0),
      /*L13*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5427, 0, 1),
      /*L14*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L15*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L16*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The level argument of setsockopt() must be one of:
//
//   - SOL_IP     (0)
//   - SOL_SOCKET (1)
//   - SOL_TCP    (6)
//   - SOL_IPV6   (41)
//
// The optname argument of setsockopt() must be one of:
//
//   - TCP_NODELAY          (0x01)
//   - TCP_CORK             (0x03)
//   - TCP_KEEPIDLE         (0x04)
//   - TCP_KEEPINTVL        (0x05)
//   - SO_TYPE              (0x03)
//   - SO_ERROR             (0x04)
//   - SO_DONTROUTE         (0x05)
//   - SO_BROADCAST         (0x06)
//   - SO_REUSEPORT         (0x0f)
//   - SO_REUSEADDR         (0x02)
//   - SO_KEEPALIVE         (0x09)
//   - SO_RCVTIMEO          (0x14)
//   - SO_SNDTIMEO          (0x15)
//   - IP_RECVTTL           (0x0c)
//   - IP_RECVERR           (0x0b)
//   - TCP_FASTOPEN         (0x17)
//   - TCP_FASTOPEN_CONNECT (0x1e)
//   - IPV6_V6ONLY          (0x1a)
//   - TCP_QUICKACK         (0x0c)
//
static privileged void AllowSetsockoptRestrict(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setsockopt, 0, 25),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 41, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 19),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0c, 16, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x1a, 15, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x06, 14, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0f, 13, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x03, 12, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0c, 11, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x13, 10, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 9, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x09, 8, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x14, 7, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 6, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0b, 5, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x04, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x05, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x17, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x1e, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x15, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The level argument of getsockopt() must be one of:
//
//   - SOL_SOCKET (1)
//   - SOL_TCP    (6)
//
// The optname argument of getsockopt() must be one of:
//
//   - SO_TYPE      (0x03)
//   - SO_ERROR     (0x04)
//   - SO_REUSEPORT (0x0f)
//   - SO_REUSEADDR (0x02)
//   - SO_KEEPALIVE (0x09)
//   - SO_RCVTIMEO  (0x14)
//   - SO_SNDTIMEO  (0x15)
//
static privileged void AllowGetsockoptRestrict(struct Filter *f) {
  static const int nr = __NR_getsockopt;
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 13),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 9),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x03, 6, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x04, 5, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0f, 4, 0),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 3, 0),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x09, 2, 0),
      /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x14, 1, 0),
      /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x15, 0, 1),
      /*L12*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L13*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L14*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The flags parameter of mmap() must not have:
//
//   - MAP_LOCKED   (0x02000)
//   - MAP_NONBLOCK (0x10000)
//   - MAP_HUGETLB  (0x40000)
//
static privileged void AllowMmapExec(struct Filter *f) {
  // long y = (long)__privileged_end;
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[3])),  // flags
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x52000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 5 - 4),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The prot parameter of mmap() may only have:
//
//   - PROT_NONE  (0)
//   - PROT_READ  (1)
//   - PROT_WRITE (2)
//
// The flags parameter must not have:
//
//   - MAP_LOCKED   (0x02000)
//   - MAP_POPULATE (0x08000)
//   - MAP_NONBLOCK (0x10000)
//   - MAP_HUGETLB  (0x40000)
//
static privileged void AllowMmapNoexec(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),  // prot
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~(PROT_READ | PROT_WRITE)),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[3])),  // flags
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x5a000),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The prot parameter of mprotect() may only have:
//
//   - PROT_NONE  (0)
//   - PROT_READ  (1)
//   - PROT_WRITE (2)
//
static privileged void AllowMprotectNoexec(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),  // prot
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~(PROT_READ | PROT_WRITE)),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_open
// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_RDONLY
//
// The flags parameter of open() must not have:
//
//   - O_CREAT     (000000100)
//   - O_TRUNC     (000001000)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenReadonly(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020001100),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_RDONLY
//
// The flags parameter of open() must not have:
//
//   - O_CREAT     (000000100)
//   - O_TRUNC     (000001000)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenatReadonly(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 9 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDONLY, 0, 8 - 4),
      /*L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020001100),
      /*L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L7*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L9*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_open
// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_WRONLY
//   - (flags & O_ACCMODE) == O_RDWR
//
// The open() flags parameter must not contain
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenWriteonly(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 10 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_WRONLY, 1, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDWR, 0, 9 - 5),
      /* L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L6*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020000100),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /* L8*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /* L9*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L10*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The open() system call is permitted only when
//
//   - (flags & O_ACCMODE) == O_WRONLY
//   - (flags & O_ACCMODE) == O_RDWR
//
// The openat() flags parameter must not contain
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
static privileged void AllowOpenatWriteonly(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 10 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, O_ACCMODE),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_WRONLY, 1, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_RDWR, 0, 9 - 5),
      /* L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L6*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020000100),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /* L8*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /* L9*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L10*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_open
// If the flags parameter of open() has one of:
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
// Then the mode parameter must not have:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowOpenCreatonly(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 12 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 000000100),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 000000100, 7 - 4, 0),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020200000),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 020200000, 0, 10 - 7),
      /* L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L8*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L10*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L11*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L12*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// If the flags parameter of openat() has one of:
//
//   - O_CREAT     (000000100)
//   - __O_TMPFILE (020000000)
//
// Then the mode parameter must not have:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowOpenatCreatonly(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 12 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 000000100),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 000000100, 7 - 4, 0),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 020200000),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 020200000, 0, 10 - 7),
      /* L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[3])),
      /* L8*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L10*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L11*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L12*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_creat
// Then the mode parameter must not have:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowCreatRestrict(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_creat, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The second argument of fcntl() must be one of:
//
//   - F_DUPFD (0)
//   - F_DUPFD_CLOEXEC (1030)
//   - F_GETFD (1)
//   - F_SETFD (2)
//   - F_GETFL (3)
//   - F_SETFL (4)
//
static privileged void AllowFcntlStdio(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1030, 4 - 3, 0),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 5, 5 - 4, 0),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The second argument of fcntl() must be one of:
//
//   - F_GETLK (0x05)
//   - F_SETLK (0x06)
//   - F_SETLKW (0x07)
//   - F_OFD_GETLK (0x24)
//   - F_OFD_SETLK (0x25)
//   - F_OFD_SETLKW (0x26)
//
static privileged void AllowFcntlLock(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 9),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x05, 5, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x06, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x07, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x24, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x25, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x26, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The addr parameter of sendto() must be
//
//   - NULL
//
static privileged void AllowSendtoAddrless(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendto, 0, 7 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[4]) + 0),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6 - 3),
      /*L3*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[4]) + 4),
      /*L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6 - 5),
      /*L5*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L6*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L7*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The family parameter of socket() must be one of:
//
//   - AF_INET  (0x02)
//   - AF_INET6 (0x0a)
//
// The type parameter of socket() will ignore:
//
//   - SOCK_CLOEXEC  (0x80000)
//   - SOCK_NONBLOCK (0x00800)
//
// The type parameter of socket() must be one of:
//
//   - SOCK_STREAM (0x01)
//   - SOCK_DGRAM  (0x02)
//
// The protocol parameter of socket() must be one of:
//
//   - 0
//   - IPPROTO_ICMP (0x01)
//   - IPPROTO_TCP  (0x06)
//   - IPPROTO_UDP  (0x11)
//
static privileged void AllowSocketInet(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 15 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 1, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0a, 0, 14 - 4),
      /* L4*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~0x80800),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 1, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 0, 14 - 8),
      /* L8*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L9*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x00, 3, 0),
      /*L10*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x01, 2, 0),
      /*L11*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x06, 1, 0),
      /*L12*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 0, 1),
      /*L13*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L14*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L15*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The family parameter of socket() must be one of:
//
//   - AF_UNIX (1)
//   - AF_LOCAL (1)
//
// The type parameter of socket() will ignore:
//
//   - SOCK_CLOEXEC  (0x80000)
//   - SOCK_NONBLOCK (0x00800)
//
// The type parameter of socket() must be one of:
//
//   - SOCK_STREAM (1)
//   - SOCK_DGRAM  (2)
//
// The protocol parameter of socket() must be one of:
//
//   - 0
//
static privileged void AllowSocketUnix(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 11 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 10 - 3),
      /* L3*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /* L5*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~0x80800),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 1, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, 10 - 7),
      /* L7*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /* L9*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L10*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L11*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The first parameter of prctl() can be any of
//
//   - PR_SET_NAME         (15)
//   - PR_GET_NAME         (16)
//   - PR_GET_SECCOMP      (21)
//   - PR_SET_SECCOMP      (22)
//   - PR_SET_NO_NEW_PRIVS (38)
//   - PR_CAPBSET_READ     (23)
//   - PR_CAPBSET_DROP     (24)
//
static privileged void AllowPrctlStdio(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /* L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 11 - 1),
      /* L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[0])),
      /* L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 15, 6, 0),
      /* L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 16, 5, 0),
      /* L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 21, 4, 0),
      /* L5*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 3, 0),
      /* L6*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 23, 2, 0),
      /* L7*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 24, 1, 0),
      /* L8*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 38, 0, 1),
      /* L9*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L10*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L11*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

#ifdef __NR_chmod
// The mode parameter of chmod() can't have the following:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowChmodNobits(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chmod, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}
#endif

// The mode parameter of fchmod() can't have the following:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowFchmodNobits(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchmod, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[1])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The mode parameter of fchmodat() can't have the following:
//
//   - S_ISVTX (01000 sticky)
//   - S_ISGID (02000 setgid)
//   - S_ISUID (04000 setuid)
//
static privileged void AllowFchmodatNobits(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchmodat, 0, 6 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L2*/ BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 07000),
      /*L3*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L4*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L5*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L6*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

// The new_limit parameter of prlimit() must be
//
//   - NULL (0)
//
static privileged void AllowPrlimitStdio(struct Filter *f) {
  static const struct sock_filter fragment[] = {
      /*L0*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prlimit64, 0, 7 - 1),
      /*L1*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2])),
      /*L2*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 6 - 3),
      /*L3*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(args[2]) + 4),
      /*L4*/ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
      /*L5*/ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      /*L6*/ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF(nr)),
      /*L7*/ /* next filter */
  };
  AppendFilter(f, PLEDGE(fragment));
}

static privileged int CountUnspecial(const uint16_t *p, size_t len) {
  int i, count;
  for (count = i = 0; i < len; ++i) {
    if (!(p[i] & SPECIAL)) {
      ++count;
    }
  }
  return count;
}

static privileged void AppendPledge(struct Filter *f,   //
                                    const uint16_t *p,  //
                                    size_t len) {       //
  int i, j, count;

  // handle ordinals which allow syscalls regardless of args
  // we put in extra effort here to reduce num of bpf instrs
  if ((count = CountUnspecial(p, len))) {
    if (count < 256) {
      for (j = i = 0; i < len; ++i) {
        if (p[i] & SPECIAL) continue;
        // jump to ALLOW rule below if accumulator equals ordinal
        struct sock_filter fragment[] = {
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,  // instruction
                     p[i],                       // operand
                     count - j - 1,              // jump if true displacement
                     j == count - 1),            // jump if false displacement
        };
        AppendFilter(f, PLEDGE(fragment));
        ++j;
      }
      struct sock_filter fragment[] = {
          BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      };
      AppendFilter(f, PLEDGE(fragment));
    } else {
      notpossible;
    }
  }

  // handle "special" ordinals which use hand-crafted bpf
  for (i = 0; i < len; ++i) {
    if (!(p[i] & SPECIAL)) continue;
    switch (p[i]) {
      case __NR_mmap | EXEC:
        AllowMmapExec(f);
        break;
      case __NR_mmap | NOEXEC:
        AllowMmapNoexec(f);
        break;
      case __NR_mprotect | NOEXEC:
        AllowMprotectNoexec(f);
        break;
#ifdef __NR_chmod
      case __NR_chmod | NOBITS:
        AllowChmodNobits(f);
        break;
#endif
      case __NR_fchmod | NOBITS:
        AllowFchmodNobits(f);
        break;
      case __NR_fchmodat | NOBITS:
        AllowFchmodatNobits(f);
        break;
      case __NR_prctl | STDIO:
        AllowPrctlStdio(f);
        break;
#ifdef __NR_open
      case __NR_open | CREATONLY:
        AllowOpenCreatonly(f);
        break;
#endif
      case __NR_openat | CREATONLY:
        AllowOpenatCreatonly(f);
        break;
#ifdef __NR_open
      case __NR_open | READONLY:
        AllowOpenReadonly(f);
        break;
#endif
      case __NR_openat | READONLY:
        AllowOpenatReadonly(f);
        break;
#ifdef __NR_open
      case __NR_open | WRITEONLY:
        AllowOpenWriteonly(f);
        break;
#endif
      case __NR_openat | WRITEONLY:
        AllowOpenatWriteonly(f);
        break;
      case __NR_setsockopt | RESTRICT:
        AllowSetsockoptRestrict(f);
        break;
      case __NR_getsockopt | RESTRICT:
        AllowGetsockoptRestrict(f);
        break;
#ifdef __NR_creat
      case __NR_creat | RESTRICT:
        AllowCreatRestrict(f);
        break;
#endif
      case __NR_fcntl | STDIO:
        AllowFcntlStdio(f);
        break;
      case __NR_fcntl | LOCK:
        AllowFcntlLock(f);
        break;
      case __NR_ioctl | RESTRICT:
        AllowIoctlStdio(f);
        break;
      case __NR_ioctl | TTY:
        AllowIoctlTty(f);
        break;
      case __NR_ioctl | INET:
        AllowIoctlInet(f);
        break;
      case __NR_socket | INET:
        AllowSocketInet(f);
        break;
      case __NR_socket | UNIX:
        AllowSocketUnix(f);
        break;
      case __NR_sendto | ADDRLESS:
        AllowSendtoAddrless(f);
        break;
      case __NR_clone | RESTRICT:
        AllowCloneRestrict(f);
        break;
      case __NR_clone | THREAD:
        AllowCloneThread(f);
        break;
      case __NR_prlimit64 | STDIO:
        AllowPrlimitStdio(f);
        break;
      case __NR_kill | SELF:
        AllowKillSelf(f);
        break;
      case __NR_tgkill | SELF:
        AllowTgkillSelf(f);
        break;
      default:
        notpossible;
    }
  }
}

/**
 * Installs SECCOMP BPF filter on Linux thread.
 *
 * @param ipromises is inverted integer bitmask of pledge() promises
 * @return 0 on success, or negative error number on error
 * @asyncsignalsafe
 * @threadsafe
 * @vforksafe
 */
privileged int sys_pledge_linux(unsigned long ipromises, int mode) {
  struct Filter f;
  int i, e, rc = -1;
  struct sock_filter sf[1] = {BPF_STMT(BPF_RET | BPF_K, 0)};
  CheckLargeStackAllocation(&f, sizeof(f));
  f.n = 0;

  // set up the seccomp filter
  AppendFilter(&f, PLEDGE(kPledgeStart));
  if (ipromises == -1) {
    // if we're pledging empty string, then avoid triggering a sigsys
    // when _Exit() gets called since we need to fallback to _Exit1()
    AppendFilter(&f, PLEDGE(kFilterIgnoreExitGroup));
  }
  AppendPledge(&f, PLEDGE(kPledgeDefault));
  for (i = 0; i < ARRAYLEN(kPledge); ++i) {
    if (~ipromises & (1ul << i)) {
      if (kPledge[i].len) {
        AppendPledge(&f, kPledge[i].syscalls, kPledge[i].len);
      } else {
        notpossible;
      }
    }
  }

  // now determine what we'll do on sandbox violations
  if (mode & PLEDGE_STDERR_LOGGING) {
    // trapping mode
    //
    // if we haven't pledged exec, then we can monitor SIGSYS
    // and print a helpful error message when things do break
    // to avoid tls / static memory, we embed mode within bpf
    MonitorSigSys();
    AllowMonitor(&f);
    sf[0].k = SECCOMP_RET_TRAP | (mode & SECCOMP_RET_DATA);
    AppendFilter(&f, PLEDGE(sf));
  } else {
    // non-trapping mode
    //
    // our sigsys error message handler can't be inherited across
    // execve() boundaries so if you've pledged exec then that'll
    // likely cause a SIGSYS in your child after the exec happens
    switch (mode & PLEDGE_PENALTY_MASK) {
      case PLEDGE_PENALTY_KILL_THREAD:
        sf[0].k = SECCOMP_RET_KILL_THREAD;
        break;
      case PLEDGE_PENALTY_KILL_PROCESS:
        sf[0].k = SECCOMP_RET_KILL_PROCESS;
        break;
      case PLEDGE_PENALTY_RETURN_EPERM:
        sf[0].k = SECCOMP_RET_ERRNO | Eperm;
        break;
      default:
        return -Einval;
    }
    AppendFilter(&f, PLEDGE(sf));
  }

  // drop privileges
  //
  // PR_SET_SECCOMP (Linux 2.6.23+) will refuse to work if
  // PR_SET_NO_NEW_PRIVS (Linux 3.5+) wasn't called so we punt the error
  // detection to the seccomp system call below.
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  // register our seccomp filter with the kernel
  struct sock_fprog sandbox = {.len = f.n, .filter = f.p};
  rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sandbox, 0, 0);

  // the EINVAL error could mean a lot of things. it could mean the bpf
  // code is broken. it could also mean we're running on RHEL5 which
  // doesn't have SECCOMP support. since we don't consider lack of
  // system support for security to be an error, we distinguish these
  // two cases by running a simpler SECCOMP operation.
  if (rc < 0 && errno == EINVAL && prctl(PR_GET_SECCOMP, 0, 0, 0, 0) < 0 &&
      errno == EINVAL) {
    rc = 0;  // -Enosys
  }

  return rc;
}
