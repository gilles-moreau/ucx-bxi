#ifndef UCP_SCHED_INL_
#define UCP_SCHED_INL_

#include "ucp_sched.h"

#define ucp_sched_task_complete(_task)                                         \
  {                                                                            \
    ucs_assert(!((_task)->flags & UCP_SCHED_TASK_COMPLETED));                  \
                                                                               \
    (_task)->flags |= UCP_SCHED_TASK_COMPLETED;                                \
  }

#endif
