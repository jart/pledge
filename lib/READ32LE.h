#ifndef PLEDGE_LIB_READ32LE_H_
#define PLEDGE_LIB_READ32LE_H_

#include <stdint.h>

#ifdef __STRICT_ANSI__
#define READ32LE(S)                                                    \
  ((uint32_t)(255 & (S)[3]) << 030 | (uint32_t)(255 & (S)[2]) << 020 | \
   (uint32_t)(255 & (S)[1]) << 010 | (uint32_t)(255 & (S)[0]) << 000)
#else /* gcc needs help knowing above are mov if s isn't a variable */
#define READ32LE(S)                                      \
  ({                                                     \
    const uint8_t *Ptr = (const uint8_t *)(S);           \
    ((uint32_t)Ptr[3] << 030 | (uint32_t)Ptr[2] << 020 | \
     (uint32_t)Ptr[1] << 010 | (uint32_t)Ptr[0] << 000); \
  })
#endif

#endif
