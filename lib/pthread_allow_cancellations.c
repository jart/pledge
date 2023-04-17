#include "ALLOW_CANCELLATIONS.h"
#include <pthread.h>

void pthread_allow_cancellations(int oldstate) {
  pthread_setcancelstate(oldstate, 0);
}
