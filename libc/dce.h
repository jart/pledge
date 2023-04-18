#ifndef PLEDGE_LIBC_DCE_H_
#define PLEDGE_LIBC_DCE_H_

#ifndef __linux__
#error "This program is extremely likely to only work properly on Linux !"
#endif

#define IsLinux() 1
#define IsWindows() 0
#define IsOpenbsd() 0

#endif
