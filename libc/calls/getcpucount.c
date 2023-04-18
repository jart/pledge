/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2021 Justine Alexandra Roberts Tunney                              │
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
#include <sched.h>
#include "libc/calls/calls.h"
#include "libc/runtime/runtime.h"

static unsigned _getcpucount_linux(void) {
  cpu_set_t s = {0};
  if (sched_getaffinity(0, sizeof(s), &s) != -1) {
    return CPU_COUNT(&s);
  } else {
    return 0;
  }
}

static unsigned _getcpucount_impl(void) {
  return _getcpucount_linux();
}

static int g_cpucount;

// precompute because process affinity on linux may change later
__attribute__((__constructor__)) static void _getcpucount_init(void) {
  g_cpucount = _getcpucount_impl();
}

/**
 * Returns number of CPUs in system.
 *
 * This is the same as the standard interface:
 *
 *     sysconf(_SC_NPROCESSORS_ONLN);
 *
 * Except this function isn't a bloated diamond dependency.
 *
 * On Intel systems with HyperThreading this will return the number of
 * cores multiplied by two.
 *
 * @return cpu count or 0 if it couldn't be determined
 */
unsigned getcpucount(void) {
  return g_cpucount;
}
