#ifndef PLEDGE_LIBC_CALLS_BLOCKCANCEL_INTERNAL_H_
#define PLEDGE_LIBC_CALLS_BLOCKCANCEL_INTERNAL_H_

#define ALLOW_CANCELLATIONS                   \
  pthread_allow_cancellations(_cancelState);  \
  }                                           \
  while (0)

void pthread_allow_cancellations(int);

#define BLOCK_CANCELLATIONS \
  do {                      \
    int _cancelState;       \
  _cancelState = pthread_block_cancellations()

int pthread_block_cancellations(void);

#endif
