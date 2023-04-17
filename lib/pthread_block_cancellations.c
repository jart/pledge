#include "BLOCK_CANCELLATIONS.h"
#include <pthread.h>

int pthread_block_cancellations(void) {
  int oldstate;
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
  return oldstate;
}
