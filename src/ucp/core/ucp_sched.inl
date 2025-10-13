#ifndef UCP_SCHED_INL_
#define UCP_SCHED_INL_

#include "ucp_request.h"
#include "ucp_sched.h"

#define ucp_sched_task_complete(_task)                                         \
  {                                                                            \
    ucs_assert(!((_task)->flags & UCP_SCHED_TASK_COMPLETED));                  \
                                                                               \
    (_task)->flags |= UCP_SCHED_TASK_COMPLETED;                                \
  }

static UCS_F_ALWAYS_INLINE int ucp_sched_task_is_offload(ucp_request_t *req)
{
  return (req->flags & UCP_REQUEST_FLAG_SCHEDULED) &&
         (req->task->flags & UCP_SCHED_TASK_OFFLOADED);
}

#endif
