#ifndef PLEDGE_LIB_CLASSIFYPATH_H_
#define PLEDGE_LIB_CLASSIFYPATH_H_

#include "integral.h"

#define _kPathAbs  1
#define _kPathDev  2
#define _kPathRoot 4
#define _kPathDos  8
#define _kPathWin  16
#define _kPathNt   32

int classifypath(const char *) libcesque nosideeffect;

#endif
