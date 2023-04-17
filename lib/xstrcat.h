#ifndef PLEDGE_LIB_XSTRCAT_H_
#define PLEDGE_LIB_XSTRCAT_H_

#include "integral.h"

char *xstrcat(const char *, ...) paramsnonnull((1)) nullterminated()
    returnspointerwithnoaliases dontthrow nocallback dontdiscard returnsnonnull;
#define xstrcat(...) (xstrcat)(__VA_ARGS__, 0)

#endif
