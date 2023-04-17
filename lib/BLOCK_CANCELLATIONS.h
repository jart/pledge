#ifndef PLEDGE_LIB_BLOCK_CANCELLATIONS_H_
#define PLEDGE_LIB_BLOCK_CANCELLATIONS_H_

#define BLOCK_CANCELLATIONS \
  do {                      \
    int _cancelState;       \
  _cancelState = pthread_block_cancellations()

int pthread_block_cancellations(void);

#endif
