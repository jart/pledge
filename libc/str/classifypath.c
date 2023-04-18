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
#include "libc/dce.h"
#include "libc/str/path.h"
#include "libc/str/str.h"

/**
 * Classifies file path name.
 *
 * For the purposes of this function, we always consider backslash
 * interchangeable with forward slash, even though the underlying
 * operating system might not. Therefore, for the sake of clarity,
 * remaining documentation will only use the forward slash.
 *
 * This function behaves the same on all platforms. For instance, this
 * function will categorize `C:/FOO.BAR` as a DOS path, even if you're
 * running on UNIX rather than DOS.
 *
 * If you wish to check if a pathname is absolute, in a manner that's
 * inclusive of DOS drive paths, DOS rooted paths, in addition to the
 * New Technology UNC paths, then you may do the following:
 *
 *     if (_classifypath(str) & _kPathAbs) { ... }
 *
 * To check if path is a relative path:
 *
 *     if (~_classifypath(str) & _kPathAbs) { ... }
 *
 * Please note the above check includes rooted paths such as `\foo`
 * which is considered absolute by MSDN and we consider it absolute
 * although, it's technically relative to the current drive letter.
 *
 * Please note that `/foo/bar` is an absolute path on Windows, even
 * though it's actually a rooted path that's considered relative to
 * current drive by WIN32.
 *
 * @return integer value that's one of following:
 *     - `0` if non-weird relative path e.g. `c`
 *     - `_kPathAbs` if absolute (or rooted dos) path e.g. `/⋯`
 *     - `_kPathDos` if `c:`, `d:foo` i.e. drive-relative path
 *     - `_kPathAbs|_kPathDos` if proper dos path e.g. `c:/foo`
 *     - `_kPathDos|_kPathDev` if dos device path e.g. `nul`, `conin$`
 *     - `_kPathAbs|_kPathWin` if `//c`, `//?c`, etc.
 *     - `_kPathAbs|_kPathWin|_kPathDev` if `//./⋯`, `//?/⋯`
 *     - `_kPathAbs|_kPathWin|_kPathDev|_kPathRoot` if `//.` or `//?`
 *     - `_kPathAbs|_kPathNt` e.g. `\??\\⋯` (undoc. strict backslash)
 * @see "The Definitive Guide on Win32 to NT Path Conversion", James
 *     Forshaw, Google Project Zero Blog, 2016-02-29
 * @see "Naming Files, Paths, and Namespaces", MSDN 01/04/2021
 */
int classifypath(const char *s) {
  if (s) {
    switch (s[0]) {
      case 0:  // ""
      default:
        return 0;
      case '\\':
      case '/':
        return _kPathAbs;
    }
  } else {
    return 0;
  }
}
