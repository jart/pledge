#ifndef PLEDGE_LIB_ALLOW_CANCELLATIONS_H_
#define PLEDGE_LIB_ALLOW_CANCELLATIONS_H_

#define ALLOW_CANCELLATIONS                   \
  pthread_allow_cancellations(_cancelState);  \
  }                                           \
  while (0)

void pthread_allow_cancellations(int);

#endif
