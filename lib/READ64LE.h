#ifndef PLEDGE_LIB_READ64LE_H_
#define PLEDGE_LIB_READ64LE_H_

#include <stdint.h>

#ifdef __STRICT_ANSI__
#define READ64LE(S)                                                    \
  ((uint64_t)(255 & (S)[7]) << 070 | (uint64_t)(255 & (S)[6]) << 060 | \
   (uint64_t)(255 & (S)[5]) << 050 | (uint64_t)(255 & (S)[4]) << 040 | \
   (uint64_t)(255 & (S)[3]) << 030 | (uint64_t)(255 & (S)[2]) << 020 | \
   (uint64_t)(255 & (S)[1]) << 010 | (uint64_t)(255 & (S)[0]) << 000)
#else /* gcc needs help knowing above are mov if s isn't a variable */
#define READ64LE(S)                                      \
  ({                                                     \
    const uint8_t *Ptr = (const uint8_t *)(S);           \
    ((uint64_t)Ptr[7] << 070 | (uint64_t)Ptr[6] << 060 | \
     (uint64_t)Ptr[5] << 050 | (uint64_t)Ptr[4] << 040 | \
     (uint64_t)Ptr[3] << 030 | (uint64_t)Ptr[2] << 020 | \
     (uint64_t)Ptr[1] << 010 | (uint64_t)Ptr[0] << 000); \
  })
#endif


#endif
